// Package applygraph derives the apply-ordering graph from a diff plan.
//
// Apply's fixed phase pipeline — service-aware deletes → writes → one
// daemon-reload → service reconcile — is a hardcoded topological order over an
// implicit dependency graph. This package makes that graph explicit: it reads a
// plan (and the IR, for the declared contents the plan only hashes) and emits an
// internal/graph.Graph whose stable topological order is a faithful interleaving
// of today's phases, plus the change-propagation edges the phases can't express
// (an EnvironmentFile= change restarting its consumer).
//
// It derives edges only from structural references already present in the IR,
// under Puppet's soft-edge rule: an edge exists only when both endpoints are
// declared/owned. See docs/adr-0002-apply-graph.md for the autorequire table.
//
// This is the derivation half (plan → graph); nothing here mutates a host.
// internal/apply consumes the derived graph and walks it in topological order in
// place of the old phase loops (B3), reading the typed edges for the require
// (fail-closed) cascade and the notify (EnvironmentFile= restart) propagation.
package applygraph

import (
	"path/filepath"
	"strings"

	"github.com/lazypower/magus-cli/internal/diff"
	"github.com/lazypower/magus-cli/internal/graph"
	"github.com/lazypower/magus-cli/internal/ir"
)

// ReloadNode is the synthetic barrier node standing for the single
// `systemctl daemon-reload`. Every unit/quadlet content mutation edges into it;
// it edges into every service reconcile — preserving the spec's "reload exactly
// once, after all unit/quadlet writes, before service ops" invariant as explicit
// structure. It exists only when at least one unit/quadlet mutation is planned.
// Exported so the apply executor (B3) can recognize the barrier node during its
// graph walk.
const ReloadNode = "daemon-reload"

// Derive builds the apply-ordering graph for plan. in supplies the declared
// contents (EnvironmentFile=/Network=/Volume= directives) the plan rows don't
// carry. The returned graph is never nil; an empty plan yields an empty graph.
//
// Node identities:
//   - resources: their on-disk path (files, dirs, unit bodies, drop-ins, quadlets);
//   - services:  the systemd service name magus reconciles (a unit's own name, or
//     a quadlet's generated .service) — one per IR unit and per IR quadlet;
//   - the daemon-reload barrier (when any unit/quadlet mutation is planned).
func Derive(plan *diff.Plan, in *ir.IR) *graph.Graph {
	b := &builder{
		g:              graph.New(),
		declaredFiles:  map[string]bool{},
		declaredQuads:  map[string]bool{},
		userQuadPaths:  map[string]bool{},
		unitService:    map[string]string{},
		quadletService: map[string]string{},
	}
	b.indexIR(in)
	b.addNodes(plan, in)
	b.containmentEdges(plan)
	b.dropInOrderEdges(in)
	b.reloadEdges()
	b.referenceEdges(in)
	b.notifyEdges(in)
	b.reversedDeleteEdges(plan)
	return b.g
}

type builder struct {
	g *graph.Graph

	declaredFiles map[string]bool // ir.File paths — targets of EnvironmentFile= edges
	declaredQuads map[string]bool // ir.Quadlet names — targets of Network=/Volume= edges
	userQuadPaths map[string]bool // user-scope quadlet source paths — excluded from the system reload

	unitService    map[string]string // unit name    -> service node id
	quadletService map[string]string // quadlet name -> service node id

	dirs           []string // declared directory paths (for containment prefixing)
	reloadTriggers []string // resource paths whose mutation forces daemon-reload
	serviceNodes   []string // every service node, for the reload→service fan-out
	hasReload      bool
}

func (b *builder) indexIR(in *ir.IR) {
	for _, f := range in.Files {
		b.declaredFiles[f.Path] = true
	}
	for _, q := range in.Quadlets {
		b.declaredQuads[q.Name] = true
		if q.Scope == ir.ScopeUser {
			b.userQuadPaths[q.Path] = true
		}
	}
}

// addNodes registers every resource-action node, the service node for each IR
// unit/quadlet, and the daemon-reload barrier when a unit/quadlet mutation is
// planned. Service nodes are created for every IR unit/quadlet (not only those
// with pending work) so phase-3's "reconcile all declared units" is reproduced
// and notify edges always have a landing node.
func (b *builder) addNodes(plan *diff.Plan, in *ir.IR) {
	for _, a := range plan.Actions {
		b.g.AddNode(a.Path)
		if a.Kind == diff.KindDirectory {
			b.dirs = append(b.dirs, a.Path)
		}
		// A user-scope quadlet source write reloads the *user* generator (handled
		// out of this graph, in the user-workload reconciler), never the system
		// one — so it must not drag in the system daemon-reload barrier.
		if triggersReload(a) && !b.userQuadPaths[a.Path] {
			b.reloadTriggers = append(b.reloadTriggers, a.Path)
		}
	}

	b.hasReload = len(b.reloadTriggers) > 0
	if b.hasReload {
		b.g.AddNode(ReloadNode)
	}

	for _, u := range in.Units {
		sid := u.Name
		b.g.AddNode(sid)
		b.unitService[u.Name] = sid
		b.serviceNodes = append(b.serviceNodes, sid)
	}
	for _, q := range in.Quadlets {
		if q.Scope == ir.ScopeUser {
			continue // user-scope services are reconciled through the user manager, not this graph
		}
		svc, err := diff.QuadletGeneratedService(q.Name)
		if err != nil {
			continue // unsupported quadlet type — no generated service to reconcile
		}
		b.g.AddNode(svc)
		b.quadletService[q.Name] = svc
		b.serviceNodes = append(b.serviceNodes, svc)
	}
}

// containmentEdges: a declared directory must settle its mode/ownership before
// anything it contains lands (require). Each resource takes an edge from its
// longest declared directory prefix — the immediate declared parent — so a
// nested tree chains parent→child rather than every ancestor→descendant.
func (b *builder) containmentEdges(plan *diff.Plan) {
	for _, a := range plan.Actions {
		parent := longestDirPrefix(a.Path, b.dirs)
		if parent != "" && parent != a.Path {
			b.g.AddEdge(parent, a.Path, graph.Require, "directory containment")
		}
	}
}

// dropInOrderEdges: a unit body is written before its drop-ins (order) — the
// base unit exists before an extension refines it. Only fires when magus owns
// the body (a drop-in-only unit extends a system unit magus doesn't write).
func (b *builder) dropInOrderEdges(in *ir.IR) {
	for _, u := range in.Units {
		body := diff.UnitPath(u.Name)
		if !b.g.HasNode(body) {
			continue
		}
		for _, di := range u.DropIns {
			dp := diff.DropInPath(u.Name, di.Name)
			if b.g.HasNode(dp) {
				b.g.AddEdge(body, dp, graph.Order, "unit body precedes drop-in")
			}
		}
	}
}

// reloadEdges wire the daemon-reload barrier: every unit/quadlet mutation →
// reload (require), then reload → every service reconcile (require). This is the
// spec's phase-2 boundary made explicit — one reload, after all writes, before
// any service op.
func (b *builder) reloadEdges() {
	if !b.hasReload {
		return
	}
	for _, p := range b.reloadTriggers {
		b.g.AddEdge(p, ReloadNode, graph.Require, "unit/quadlet write needs daemon-reload")
	}
	for _, s := range b.serviceNodes {
		b.g.AddEdge(ReloadNode, s, graph.Require, "daemon-reload precedes service reconcile")
	}
}

// referenceEdges: a .container that names a declared .network/.volume must start
// after that network/volume's service (require). Soft-edge: the reference is
// honored only when the named quadlet is itself declared.
func (b *builder) referenceEdges(in *ir.IR) {
	for _, q := range in.Quadlets {
		if filepath.Ext(q.Name) != ".container" {
			continue
		}
		containerSvc, ok := b.quadletService[q.Name]
		if !ok {
			continue
		}
		for _, ref := range quadletRefs(q.Contents) {
			if !b.declaredQuads[ref] {
				continue // soft edge: only when the referenced quadlet is declared
			}
			if refSvc, ok := b.quadletService[ref]; ok {
				b.g.AddEdge(refSvc, containerSvc, graph.Require, "Network=/Volume= reference")
			}
		}
	}
}

// notifyEdges: a managed file consumed via EnvironmentFile= by a unit/quadlet
// notifies that service (notify) — if the file changed, the consumer refreshes.
// This is the change-propagation the phase pipeline can't express and the gap
// B3's walk closes. Soft-edge: only when the referenced path is a declared file.
func (b *builder) notifyEdges(in *ir.IR) {
	for _, u := range in.Units {
		sid := b.unitService[u.Name]
		b.notifyFrom(u.Contents, sid)
		for _, di := range u.DropIns {
			b.notifyFrom(di.Contents, sid)
		}
	}
	for _, q := range in.Quadlets {
		if sid, ok := b.quadletService[q.Name]; ok {
			b.notifyFrom(string(q.Contents), sid)
		}
	}
}

func (b *builder) notifyFrom(contents, service string) {
	if service == "" {
		return
	}
	for _, ef := range envFiles(contents) {
		if b.declaredFiles[ef] {
			b.g.AddEdge(ef, service, graph.Notify, "EnvironmentFile= reference")
		}
	}
}

// reversedDeleteEdges: deletes walk the reverse of create order. On create a
// unit body precedes its drop-ins; on delete the drop-ins are removed before the
// body (order, reversed). Grouped by unit from the sweep's delete rows.
//
// Cross-quadlet reference delete ordering (stop a container before the network
// it used) is deliberately NOT derived here: the deleted quadlet's source is
// gone from the IR, so its Network=/Volume= references are unrecoverable from the
// plan. Each quadlet delete already stops its own generated service before
// unlinking (apply's per-node teardown), so the single-resource case is covered;
// the multi-resource case is a documented deferral (ADR-0002's "small honest
// subset").
func (b *builder) reversedDeleteEdges(plan *diff.Plan) {
	// Group unit-kind delete rows by unit name.
	type unitDeletes struct {
		body    string
		dropins []string
	}
	byUnit := map[string]*unitDeletes{}
	for _, a := range plan.Actions {
		if a.Action != diff.ActionDelete || a.Kind != diff.KindUnit || a.UnitName == "" {
			continue
		}
		ud := byUnit[a.UnitName]
		if ud == nil {
			ud = &unitDeletes{}
			byUnit[a.UnitName] = ud
		}
		if a.Path == diff.UnitPath(a.UnitName) {
			ud.body = a.Path
		} else {
			ud.dropins = append(ud.dropins, a.Path)
		}
	}
	for _, ud := range byUnit {
		if ud.body == "" {
			continue
		}
		for _, dp := range ud.dropins {
			b.g.AddEdge(dp, ud.body, graph.Order, "drop-in removed before unit body")
		}
	}
}

// --- pure helpers ----------------------------------------------------------

// triggersReload reports whether a resource action forces a daemon-reload: a
// content mutation (create/update/delete) of a unit body, drop-in, or quadlet.
// Adopts and skips do not — the file's bytes did not change.
func triggersReload(a diff.ResourceAction) bool {
	if a.Kind != diff.KindUnit && a.Kind != diff.KindQuadlet {
		return false
	}
	switch a.Action {
	case diff.ActionCreate, diff.ActionUpdate, diff.ActionDelete:
		return true
	default:
		return false
	}
}

// longestDirPrefix returns the longest directory in dirs that is a strict path
// ancestor of p (a real path-segment prefix, so /etc/ab is not a prefix of
// /etc/abc). Returns "" when none applies.
func longestDirPrefix(p string, dirs []string) string {
	best := ""
	for _, d := range dirs {
		if d == p {
			continue
		}
		if isPathPrefix(d, p) && len(d) > len(best) {
			best = d
		}
	}
	return best
}

// isPathPrefix reports whether dir is a path-segment ancestor of p.
func isPathPrefix(dir, p string) bool {
	dir = strings.TrimSuffix(dir, "/")
	return strings.HasPrefix(p, dir+"/")
}

// quadletRefs extracts the quadlet names a .container references via Network= and
// Volume=. Network=name → name; Volume=name:/path:opts → name (the source before
// the first colon). Values that aren't declared quadlet names (Network=host, a
// bind-mount path) simply won't match under the soft-edge rule.
func quadletRefs(contents []byte) []string {
	var out []string
	for _, v := range diff.UnitValues(string(contents), "Network") {
		out = append(out, v)
	}
	for _, v := range diff.UnitValues(string(contents), "Volume") {
		out = append(out, strings.SplitN(v, ":", 2)[0])
	}
	return out
}

// envFiles extracts the EnvironmentFile= paths from a unit/quadlet body,
// stripping systemd's optional-file "-" prefix.
func envFiles(contents string) []string {
	var out []string
	for _, v := range diff.UnitValues(contents, "EnvironmentFile") {
		out = append(out, strings.TrimPrefix(v, "-"))
	}
	return out
}
