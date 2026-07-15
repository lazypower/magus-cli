package applygraph

import (
	"errors"
	"strings"
	"testing"

	"github.com/lazypower/magus-cli/internal/diff"
	"github.com/lazypower/magus-cli/internal/graph"
	"github.com/lazypower/magus-cli/internal/ir"
)

// ---- construction helpers --------------------------------------------------

func fileAct(path string, a diff.Action) diff.ResourceAction {
	return diff.ResourceAction{Path: path, Kind: diff.KindFile, Action: a}
}
func dirAct(path string, a diff.Action) diff.ResourceAction {
	return diff.ResourceAction{Path: path, Kind: diff.KindDirectory, Action: a}
}
func unitAct(name string, a diff.Action) diff.ResourceAction {
	return diff.ResourceAction{Path: diff.UnitPath(name), Kind: diff.KindUnit, UnitName: name, Action: a}
}
func dropInAct(unitName, dropIn string, a diff.Action) diff.ResourceAction {
	return diff.ResourceAction{Path: diff.DropInPath(unitName, dropIn), Kind: diff.KindUnit, UnitName: unitName, Action: a}
}
func quadletAct(name string, a diff.Action) diff.ResourceAction {
	return diff.ResourceAction{Path: "/etc/containers/systemd/" + name, Kind: diff.KindQuadlet, UnitName: name, Action: a}
}

func hasEdge(g *graph.Graph, from, to string, kind graph.Kind) bool {
	for _, e := range g.Edges() {
		if e.From == from && e.To == to && e.Kind == kind {
			return true
		}
	}
	return false
}

func edgeReason(g *graph.Graph, from, to string) string {
	for _, e := range g.Edges() {
		if e.From == from && e.To == to {
			return e.Reason
		}
	}
	return ""
}

// ---- per-rule derivation tests ---------------------------------------------

func TestContainmentEdge(t *testing.T) {
	in := &ir.IR{
		Directories: []ir.Directory{{Path: "/etc/app", Mode: 0o755}},
		Files:       []ir.File{{Path: "/etc/app/config", Mode: 0o644}},
	}
	plan := &diff.Plan{Actions: []diff.ResourceAction{
		dirAct("/etc/app", diff.ActionCreate),
		fileAct("/etc/app/config", diff.ActionCreate),
	}}
	g := Derive(plan, in)

	if !hasEdge(g, "/etc/app", "/etc/app/config", graph.Require) {
		t.Errorf("missing containment edge /etc/app → /etc/app/config\nedges=%+v", g.Edges())
	}
	if r := edgeReason(g, "/etc/app", "/etc/app/config"); r != "directory containment" {
		t.Errorf("containment reason = %q", r)
	}
}

func TestContainmentLongestPrefixOnly(t *testing.T) {
	// Nested dirs: the file attaches to its IMMEDIATE declared parent, not every
	// ancestor — /a/b, not /a.
	in := &ir.IR{
		Directories: []ir.Directory{{Path: "/a"}, {Path: "/a/b"}},
		Files:       []ir.File{{Path: "/a/b/f"}},
	}
	plan := &diff.Plan{Actions: []diff.ResourceAction{
		dirAct("/a", diff.ActionCreate),
		dirAct("/a/b", diff.ActionCreate),
		fileAct("/a/b/f", diff.ActionCreate),
	}}
	g := Derive(plan, in)

	if !hasEdge(g, "/a/b", "/a/b/f", graph.Require) {
		t.Error("file should attach to its immediate parent /a/b")
	}
	if hasEdge(g, "/a", "/a/b/f", graph.Require) {
		t.Error("file should NOT edge from the grandparent /a")
	}
	// The chain /a → /a/b still exists.
	if !hasEdge(g, "/a", "/a/b", graph.Require) {
		t.Error("missing /a → /a/b chain edge")
	}
	// Sibling-prefix guard: /ab must not be treated as under /a.
	in2 := &ir.IR{Directories: []ir.Directory{{Path: "/a"}}, Files: []ir.File{{Path: "/ab"}}}
	plan2 := &diff.Plan{Actions: []diff.ResourceAction{dirAct("/a", diff.ActionCreate), fileAct("/ab", diff.ActionCreate)}}
	if hasEdge(Derive(plan2, in2), "/a", "/ab", graph.Require) {
		t.Error("/a must not be a path prefix of /ab")
	}
}

func TestDropInOrderEdge(t *testing.T) {
	enabled := true
	in := &ir.IR{Units: []ir.Unit{{
		Name:     "web.service",
		Enabled:  &enabled,
		Contents: "[Service]\nExecStart=/usr/bin/web\n",
		DropIns:  []ir.DropIn{{Name: "10-magus.conf", Contents: "[Service]\nEnvironment=X=1\n"}},
	}}}
	plan := &diff.Plan{Actions: []diff.ResourceAction{
		unitAct("web.service", diff.ActionCreate),
		dropInAct("web.service", "10-magus.conf", diff.ActionCreate),
	}}
	g := Derive(plan, in)

	body := diff.UnitPath("web.service")
	dp := diff.DropInPath("web.service", "10-magus.conf")
	if !hasEdge(g, body, dp, graph.Order) {
		t.Errorf("missing body→drop-in order edge\nedges=%+v", g.Edges())
	}
}

func TestDropInOnlyUnitNoOrderEdge(t *testing.T) {
	// A drop-in-only unit (no owned body) extends a system unit — no body node,
	// so no body→drop-in edge, but the drop-in still exists and reloads.
	in := &ir.IR{Units: []ir.Unit{{
		Name:    "sshd.service",
		DropIns: []ir.DropIn{{Name: "10-magus.conf", Contents: "[Service]\nEnvironment=X=1\n"}},
	}}}
	plan := &diff.Plan{Actions: []diff.ResourceAction{
		dropInAct("sshd.service", "10-magus.conf", diff.ActionCreate),
	}}
	g := Derive(plan, in)

	body := diff.UnitPath("sshd.service")
	if g.HasNode(body) {
		t.Error("no body node should exist for a drop-in-only unit")
	}
	dp := diff.DropInPath("sshd.service", "10-magus.conf")
	if !hasEdge(g, dp, reloadNode, graph.Require) {
		t.Error("drop-in write should still trigger daemon-reload")
	}
}

func TestReloadBarrierEdges(t *testing.T) {
	enabled := true
	in := &ir.IR{Units: []ir.Unit{{Name: "web.service", Enabled: &enabled, Contents: "[Service]\nExecStart=/x\n"}}}
	plan := &diff.Plan{Actions: []diff.ResourceAction{unitAct("web.service", diff.ActionCreate)}}
	g := Derive(plan, in)

	body := diff.UnitPath("web.service")
	if !hasEdge(g, body, reloadNode, graph.Require) {
		t.Error("unit write should edge into daemon-reload")
	}
	if !hasEdge(g, reloadNode, "web.service", graph.Require) {
		t.Error("daemon-reload should edge into the service reconcile")
	}
}

func TestAdoptAndSkipDoNotTriggerReload(t *testing.T) {
	in := &ir.IR{Units: []ir.Unit{{Name: "web.service", Contents: "[Service]\nExecStart=/x\n"}}}
	for _, act := range []diff.Action{diff.ActionAdopt, diff.ActionSkip} {
		plan := &diff.Plan{Actions: []diff.ResourceAction{unitAct("web.service", act)}}
		g := Derive(plan, in)
		if g.HasNode(reloadNode) {
			t.Errorf("action %q must not create a daemon-reload node (no bytes changed)", act)
		}
		// The service node still exists (phase 3 reconciles it) but with no
		// reload dependency.
		if !g.HasNode("web.service") {
			t.Errorf("action %q: service node should still exist", act)
		}
	}
}

func TestNoReloadNodeWithoutUnitMutation(t *testing.T) {
	in := &ir.IR{Files: []ir.File{{Path: "/etc/x"}}}
	plan := &diff.Plan{Actions: []diff.ResourceAction{fileAct("/etc/x", diff.ActionCreate)}}
	g := Derive(plan, in)
	if g.HasNode(reloadNode) {
		t.Error("a file-only plan must not create a daemon-reload node")
	}
}

func TestReferenceEdgeAndSoftEdge(t *testing.T) {
	in := &ir.IR{Quadlets: []ir.Quadlet{
		{Path: "/etc/containers/systemd/db.network", Name: "db.network", Contents: []byte("[Network]\n")},
		{Path: "/etc/containers/systemd/web.container", Name: "web.container",
			Contents: []byte("[Container]\nImage=web\nNetwork=db.network\nVolume=data.volume:/data\n")},
		{Path: "/etc/containers/systemd/data.volume", Name: "data.volume", Contents: []byte("[Volume]\n")},
	}}
	plan := &diff.Plan{Actions: []diff.ResourceAction{
		quadletAct("db.network", diff.ActionCreate),
		quadletAct("web.container", diff.ActionCreate),
		quadletAct("data.volume", diff.ActionCreate),
	}}
	g := Derive(plan, in)

	// db.network → db-network.service ; web.container → web.service ; etc.
	if !hasEdge(g, "db-network.service", "web.service", graph.Require) {
		t.Errorf("missing Network= reference edge db-network.service → web.service\nedges=%+v", g.Edges())
	}
	if !hasEdge(g, "data-volume.service", "web.service", graph.Require) {
		t.Error("missing Volume= reference edge data-volume.service → web.service")
	}
	if r := edgeReason(g, "db-network.service", "web.service"); r != "Network=/Volume= reference" {
		t.Errorf("reference reason = %q", r)
	}
}

func TestReferenceSoftEdgeUndeclared(t *testing.T) {
	// Network=host and an undeclared network name yield no edge.
	in := &ir.IR{Quadlets: []ir.Quadlet{
		{Path: "/etc/containers/systemd/web.container", Name: "web.container",
			Contents: []byte("[Container]\nNetwork=host\nNetwork=absent.network\n")},
	}}
	plan := &diff.Plan{Actions: []diff.ResourceAction{quadletAct("web.container", diff.ActionCreate)}}
	g := Derive(plan, in)
	for _, e := range g.Edges() {
		if e.Reason == "Network=/Volume= reference" {
			t.Errorf("unexpected reference edge to an undeclared quadlet: %+v", e)
		}
	}
}

func TestNotifyEdgeAndSoftEdge(t *testing.T) {
	in := &ir.IR{
		Files: []ir.File{{Path: "/etc/app.env"}},
		Units: []ir.Unit{{
			Name:     "web.service",
			Contents: "[Service]\nEnvironmentFile=/etc/app.env\nEnvironmentFile=-/etc/missing.env\nExecStart=/x\n",
		}},
	}
	plan := &diff.Plan{Actions: []diff.ResourceAction{
		fileAct("/etc/app.env", diff.ActionUpdate),
		unitAct("web.service", diff.ActionSkip), // body unchanged; only the env file moved
	}}
	g := Derive(plan, in)

	if !hasEdge(g, "/etc/app.env", "web.service", graph.Notify) {
		t.Errorf("missing EnvironmentFile= notify edge\nedges=%+v", g.Edges())
	}
	if r := edgeReason(g, "/etc/app.env", "web.service"); r != "EnvironmentFile= reference" {
		t.Errorf("notify reason = %q", r)
	}
	// Soft edge: the undeclared /etc/missing.env gets no edge.
	if hasEdge(g, "/etc/missing.env", "web.service", graph.Notify) {
		t.Error("notify edge created for an undeclared env file")
	}
}

func TestNotifyFromQuadletAndDropIn(t *testing.T) {
	in := &ir.IR{
		Files: []ir.File{{Path: "/etc/q.env"}, {Path: "/etc/d.env"}},
		Units: []ir.Unit{{
			Name:     "web.service",
			Contents: "[Service]\nExecStart=/x\n",
			DropIns:  []ir.DropIn{{Name: "10-magus.conf", Contents: "[Service]\nEnvironmentFile=/etc/d.env\n"}},
		}},
		Quadlets: []ir.Quadlet{{
			Path: "/etc/containers/systemd/app.container", Name: "app.container",
			Contents: []byte("[Container]\nEnvironmentFile=/etc/q.env\n"),
		}},
	}
	plan := &diff.Plan{Actions: []diff.ResourceAction{
		fileAct("/etc/q.env", diff.ActionCreate),
		fileAct("/etc/d.env", diff.ActionCreate),
		unitAct("web.service", diff.ActionCreate),
		dropInAct("web.service", "10-magus.conf", diff.ActionCreate),
		quadletAct("app.container", diff.ActionCreate),
	}}
	g := Derive(plan, in)

	if !hasEdge(g, "/etc/q.env", "app.service", graph.Notify) {
		t.Error("quadlet EnvironmentFile= should notify its generated service")
	}
	if !hasEdge(g, "/etc/d.env", "web.service", graph.Notify) {
		t.Error("drop-in EnvironmentFile= should notify the unit's service")
	}
}

func TestReversedDeleteEdge(t *testing.T) {
	// A unit removed from the IR: body + drop-in are swept as deletes. On delete
	// the drop-in is removed before the body (reverse of create order).
	in := &ir.IR{} // nothing declared — old.service is gone
	body := diff.UnitPath("old.service")
	dp := diff.DropInPath("old.service", "10-magus.conf")
	plan := &diff.Plan{Actions: []diff.ResourceAction{
		{Path: body, Kind: diff.KindUnit, UnitName: "old.service", Action: diff.ActionDelete},
		{Path: dp, Kind: diff.KindUnit, UnitName: "old.service", Action: diff.ActionDelete},
	}}
	g := Derive(plan, in)

	if !hasEdge(g, dp, body, graph.Order) {
		t.Errorf("missing reversed delete edge drop-in → body\nedges=%+v", g.Edges())
	}
	if hasEdge(g, body, dp, graph.Order) {
		t.Error("create-order body→drop-in edge must NOT exist for deletes")
	}
}

func TestReversedDeleteDropInOnly(t *testing.T) {
	// A swept drop-in whose body isn't owned (magus never wrote the base unit):
	// no body node, so no reversed edge — and no panic.
	in := &ir.IR{}
	dp := diff.DropInPath("sshd.service", "10-magus.conf")
	plan := &diff.Plan{Actions: []diff.ResourceAction{
		{Path: dp, Kind: diff.KindUnit, UnitName: "sshd.service", Action: diff.ActionDelete},
	}}
	g := Derive(plan, in)
	for _, e := range g.Edges() {
		if e.Reason == "drop-in removed before unit body" {
			t.Errorf("no reversed edge expected without an owned body: %+v", e)
		}
	}
}

// ---- phase equivalence -----------------------------------------------------

// TestPhaseEquivalence proves the graph's topological order is a faithful
// interleaving of today's phases (1a deletes → 1b writes → 2 reload → 3 service
// ops). It asserts the HARD invariants — the orderings whose violation changes
// observable behavior — over a representative mixed plan.
func TestPhaseEquivalence(t *testing.T) {
	enabled := true
	in := &ir.IR{
		Directories: []ir.Directory{{Path: "/etc/app"}},
		Files:       []ir.File{{Path: "/etc/app/app.env"}},
		Units: []ir.Unit{{
			Name:     "web.service",
			Enabled:  &enabled,
			Contents: "[Service]\nEnvironmentFile=/etc/app/app.env\nExecStart=/x\n",
			DropIns:  []ir.DropIn{{Name: "10-magus.conf", Contents: "[Service]\nEnvironment=Y=1\n"}},
		}},
		Quadlets: []ir.Quadlet{
			{Path: "/etc/containers/systemd/db.network", Name: "db.network", Contents: []byte("[Network]\n")},
			{Path: "/etc/containers/systemd/app.container", Name: "app.container",
				Contents: []byte("[Container]\nImage=app\nNetwork=db.network\n")},
		},
	}
	plan := &diff.Plan{Actions: []diff.ResourceAction{
		dirAct("/etc/app", diff.ActionCreate),
		fileAct("/etc/app/app.env", diff.ActionCreate),
		unitAct("web.service", diff.ActionCreate),
		dropInAct("web.service", "10-magus.conf", diff.ActionCreate),
		quadletAct("db.network", diff.ActionCreate),
		quadletAct("app.container", diff.ActionCreate),
	}}

	g := Derive(plan, in)
	order, err := g.TopoSort()
	if err != nil {
		t.Fatalf("representative plan produced a cycle: %v", err)
	}
	pos := map[string]int{}
	for i, n := range order {
		pos[n] = i
	}

	must := func(a, b, why string) {
		t.Helper()
		if pos[a] >= pos[b] {
			t.Errorf("%s: %q (%d) should precede %q (%d)\norder=%v", why, a, pos[a], b, pos[b], order)
		}
	}

	// Directory before the file it contains.
	must("/etc/app", "/etc/app/app.env", "containment")
	// Unit body before its drop-in.
	must(diff.UnitPath("web.service"), diff.DropInPath("web.service", "10-magus.conf"), "body→drop-in")
	// Every unit/quadlet write before the single daemon-reload...
	for _, w := range []string{
		diff.UnitPath("web.service"),
		diff.DropInPath("web.service", "10-magus.conf"),
		"/etc/containers/systemd/db.network",
		"/etc/containers/systemd/app.container",
	} {
		must(w, reloadNode, "write→reload")
	}
	// ...and daemon-reload before every service reconcile.
	for _, s := range []string{"web.service", "db-network.service", "app.service"} {
		must(reloadNode, s, "reload→service")
	}
	// Network reference: the network service precedes the container service.
	must("db-network.service", "app.service", "Network= reference")
}

// TestDeriveSoundAcyclic asserts the core soundness property: the derivation
// never produces a cycle from well-formed IR — its rules are hierarchical
// (containment is length-ordered; notify/reference flow file→service and
// provider→consumer). A wrong edge here is a wrong write order on a
// root-privileged tool, so an accidental cycle would be a real defect.
func TestDeriveSoundAcyclic(t *testing.T) {
	enabled := true
	in := &ir.IR{
		Directories: []ir.Directory{{Path: "/etc/app"}, {Path: "/etc/app/sub"}},
		Files:       []ir.File{{Path: "/etc/app/a.env"}, {Path: "/etc/app/sub/b.env"}},
		Units: []ir.Unit{
			{Name: "one.service", Enabled: &enabled, Contents: "[Service]\nEnvironmentFile=/etc/app/a.env\nExecStart=/1\n",
				DropIns: []ir.DropIn{{Name: "10-magus.conf", Contents: "[Service]\nEnvironmentFile=/etc/app/sub/b.env\n"}}},
			{Name: "two.service", Contents: "[Service]\nExecStart=/2\n"},
		},
		Quadlets: []ir.Quadlet{
			{Path: "/etc/containers/systemd/net.network", Name: "net.network", Contents: []byte("[Network]\n")},
			{Path: "/etc/containers/systemd/vol.volume", Name: "vol.volume", Contents: []byte("[Volume]\n")},
			{Path: "/etc/containers/systemd/c.container", Name: "c.container",
				Contents: []byte("[Container]\nNetwork=net.network\nVolume=vol.volume:/v\nEnvironmentFile=/etc/app/a.env\n")},
		},
	}
	plan := &diff.Plan{Actions: []diff.ResourceAction{
		dirAct("/etc/app", diff.ActionCreate),
		dirAct("/etc/app/sub", diff.ActionCreate),
		fileAct("/etc/app/a.env", diff.ActionCreate),
		fileAct("/etc/app/sub/b.env", diff.ActionCreate),
		unitAct("one.service", diff.ActionCreate),
		dropInAct("one.service", "10-magus.conf", diff.ActionCreate),
		unitAct("two.service", diff.ActionUpdate),
		quadletAct("net.network", diff.ActionCreate),
		quadletAct("vol.volume", diff.ActionCreate),
		quadletAct("c.container", diff.ActionCreate),
	}}

	if _, err := Derive(plan, in).TopoSort(); err != nil {
		t.Fatalf("derivation is not acyclic: %v", err)
	}
}

// TestCycleProvenanceRenders exercises the diagnostic path end-to-end. Because
// Derive is acyclic-by-construction (TestDeriveSoundAcyclic), a cycle can only
// arise from a hand-crafted graph — this builds one using the derivation's own
// provenance vocabulary and asserts TopoSort reports it with each edge's reason,
// matching ADR-0002's cycle-rendering contract.
func TestCycleProvenanceRenders(t *testing.T) {
	g := graph.New()
	g.AddEdge("/etc/magus.d/a.env", "ollama.service", graph.Notify, "EnvironmentFile= reference")
	g.AddEdge("ollama.service", "/etc/magus.d/a.env", graph.Require, "directory containment")

	_, err := g.TopoSort()
	var ce *graph.CycleError
	if !errors.As(err, &ce) {
		t.Fatalf("expected a cycle error, got %v", err)
	}
	msg := err.Error()
	for _, want := range []string{
		"/etc/magus.d/a.env → ollama.service  (EnvironmentFile= reference)",
		"ollama.service → /etc/magus.d/a.env  (directory containment)",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("cycle render missing %q:\n%s", want, msg)
		}
	}
}

// TestEmptyPlan yields an empty, valid graph.
func TestEmptyPlan(t *testing.T) {
	g := Derive(&diff.Plan{}, &ir.IR{})
	if len(g.Nodes()) != 0 {
		t.Errorf("empty plan should yield an empty graph, got nodes %v", g.Nodes())
	}
	if order, err := g.TopoSort(); err != nil || len(order) != 0 {
		t.Errorf("empty graph toposort: order=%v err=%v", order, err)
	}
}
