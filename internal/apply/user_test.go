package apply

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/lazypower/magus-cli/internal/diff"
	"github.com/lazypower/magus-cli/internal/ir"
	"github.com/lazypower/magus-cli/internal/systemd"
)

func uintp(i int) *int { return &i }

// argusIR declares the argus principal plus a user-scoped network + container.
func argusIR() *ir.IR {
	return &ir.IR{
		Users: []ir.User{{Name: "argus", UID: uintp(1000)}},
		Quadlets: []ir.Quadlet{
			{Name: "argusd.container", Path: "/var/home/argus/.config/containers/systemd/argusd.container", Scope: ir.ScopeUser, Owner: "argus"},
			{Name: "argus-egress.network", Path: "/var/home/argus/.config/containers/systemd/argus-egress.network", Scope: ir.ScopeUser, Owner: "argus"},
		},
	}
}

// allChanged marks every user quadlet source as written this apply (first apply).
func allChanged(in *ir.IR) map[string]bool {
	m := map[string]bool{}
	for _, q := range in.Quadlets {
		m[q.Path] = true
	}
	return m
}

func TestReconcileUserWorkloadsActivatesInOrder(t *testing.T) {
	in := argusIR()
	fu := systemd.NewFakeUser()
	var gotName string
	var gotUID int
	factory := func(name string, uid int) systemd.UserManager {
		gotName, gotUID = name, uid
		return fu
	}

	outs := ReconcileUserWorkloads(UserWorkloads{IR: in, Changed: allChanged(in), NewUser: factory})

	if gotName != "argus" || gotUID != 1000 {
		t.Errorf("factory called with (%q,%d), want (argus,1000)", gotName, gotUID)
	}
	// The user generator is reloaded once (a source changed), then services start
	// network-before-container.
	calls := fu.Calls()
	assertBefore(t, calls, "DaemonReload", "Start(argus-egress-network.service)")
	assertBefore(t, calls, "Start(argus-egress-network.service)", "Start(argusd.service)")

	// Both workloads report applied.
	applied := 0
	for _, o := range outs {
		if o.Status == StatusApplied {
			applied++
		}
	}
	if applied != 2 {
		t.Errorf("want 2 activated services, got %d (%+v)", applied, outs)
	}
}

// The honest skip: an unready user manager stages every workload, never green,
// and never touches systemd (no reload, no start).
func TestReconcileUserWorkloadsStagedWhenNotReady(t *testing.T) {
	in := argusIR()
	fu := systemd.NewFakeUser()
	fu.SetReady(false, "/run/user/1000 not present — user@1000.service not started (linger enabled?)")

	outs := ReconcileUserWorkloads(UserWorkloads{IR: in, Changed: allChanged(in), NewUser: func(string, int) systemd.UserManager { return fu }})

	if len(outs) != 2 {
		t.Fatalf("want 2 staged outcomes, got %d", len(outs))
	}
	for _, o := range outs {
		if o.Status != StatusSkipped {
			t.Errorf("%s should be skipped (staged), got %s", o.Path, o.Status)
		}
		if !contains(o.Reason, "staged, not activated") || !contains(o.Reason, "/run/user/1000") {
			t.Errorf("reason should carry the dependency: %q", o.Reason)
		}
	}
	for _, c := range fu.Calls() {
		if c == "DaemonReload" || contains(c, "Start(") {
			t.Errorf("an unready manager must not be driven; saw %q", c)
		}
	}
}

// Steady state: nothing changed and services already active → no reload, no
// start/restart, everything unchanged (idempotent, "Nothing to apply" honest).
func TestReconcileUserWorkloadsIdempotentWhenActive(t *testing.T) {
	in := argusIR()
	fu := systemd.NewFakeUser()
	fu.SetActiveState("argusd.service", "active")
	fu.SetActiveState("argus-egress-network.service", "active")

	outs := ReconcileUserWorkloads(UserWorkloads{IR: in, Changed: map[string]bool{}, NewUser: func(string, int) systemd.UserManager { return fu }})

	for _, o := range outs {
		if o.Status != StatusUnchanged {
			t.Errorf("%s should be unchanged in steady state, got %s (%s)", o.Path, o.Status, o.Reason)
		}
	}
	for _, c := range fu.Calls() {
		if c == "DaemonReload" || contains(c, "Start(") || contains(c, "Restart(") {
			t.Errorf("steady state must be a no-op; saw %q", c)
		}
	}
}

// A changed source on an already-active service restarts it (not start).
func TestReconcileUserWorkloadsRestartsOnChange(t *testing.T) {
	in := argusIR()
	fu := systemd.NewFakeUser()
	fu.SetActiveState("argusd.service", "active")
	fu.SetActiveState("argus-egress-network.service", "active")
	changed := map[string]bool{"/var/home/argus/.config/containers/systemd/argusd.container": true}

	outs := ReconcileUserWorkloads(UserWorkloads{IR: in, Changed: changed, NewUser: func(string, int) systemd.UserManager { return fu }})

	var restarted bool
	for _, o := range outs {
		if o.Path == "argusd.service" && contains(o.Reason, "restarted") {
			restarted = true
		}
	}
	if !restarted {
		t.Errorf("changed source on active service should restart: %+v", outs)
	}
}

// No factory or no user workloads → nothing to do (the common all-system case).
func TestReconcileUserWorkloadsNoop(t *testing.T) {
	if outs := ReconcileUserWorkloads(UserWorkloads{IR: argusIR()}); outs != nil {
		t.Errorf("nil factory disables activation; got %+v", outs)
	}
	sysOnly := &ir.IR{Quadlets: []ir.Quadlet{{Name: "x.container", Scope: ir.ScopeSystem}}}
	if outs := ReconcileUserWorkloads(UserWorkloads{IR: sysOnly, NewUser: func(string, int) systemd.UserManager { return systemd.NewFakeUser() }}); outs != nil {
		t.Errorf("no user workloads → no outcomes; got %+v", outs)
	}
}

// A user daemon-reload failure stages the workloads (fail-closed), not errored-
// green.
func TestReconcileUserWorkloadsReloadFailureStages(t *testing.T) {
	in := argusIR()
	fu := systemd.NewFakeUser()
	fu.FailNext("DaemonReload", errTest)

	outs := ReconcileUserWorkloads(UserWorkloads{IR: in, Changed: allChanged(in), NewUser: func(string, int) systemd.UserManager { return fu }})
	for _, o := range outs {
		if o.Status != StatusSkipped || !contains(o.Reason, "daemon-reload failed") {
			t.Errorf("reload failure should stage: %+v", o)
		}
	}
}

// A refused/unreconciled principal (Blocked) never gets its workload activated —
// it stages, with the owner reason, and the user manager is never touched (P1 #2).
func TestReconcileUserWorkloadsBlockedOwnerStaged(t *testing.T) {
	in := argusIR()
	fu := systemd.NewFakeUser()
	outs := ReconcileUserWorkloads(UserWorkloads{
		IR:      in,
		Changed: allChanged(in),
		Blocked: map[string]string{"argus": `already in privileged group "docker" without a policy grant`},
		NewUser: func(string, int) systemd.UserManager { return fu },
	})
	if len(outs) != 2 {
		t.Fatalf("want 2 staged outcomes, got %d", len(outs))
	}
	for _, o := range outs {
		if o.Status != StatusSkipped || !contains(o.Reason, "owner principal not reconciled") || !contains(o.Reason, "docker") {
			t.Errorf("blocked owner should stage with reason: %+v", o)
		}
	}
	if len(fu.Calls()) != 0 {
		t.Errorf("a blocked owner's manager must never be driven; saw %v", fu.Calls())
	}
}

// A quadlet whose SOURCE magus refused this apply (a conflict/skip) is staged,
// never activated — magus must not start a service generated from content it
// declined to write (Codex round-2 fail-open activation).
func TestReconcileUserWorkloadsRefusedSourceStaged(t *testing.T) {
	in := argusIR()
	fu := systemd.NewFakeUser()
	refusedPath := "/var/home/argus/.config/containers/systemd/argusd.container"
	outs := ReconcileUserWorkloads(UserWorkloads{
		IR:      in,
		Changed: allChanged(in),
		Refused: map[string]bool{refusedPath: true},
		NewUser: func(string, int) systemd.UserManager { return fu },
	})
	var argusdStaged bool
	for _, o := range outs {
		if o.Path == refusedPath {
			if o.Status != StatusSkipped || !contains(o.Reason, "source not reconciled") {
				t.Errorf("refused source should stage: %+v", o)
			}
			argusdStaged = true
		}
	}
	if !argusdStaged {
		t.Errorf("refused quadlet not staged: %+v", outs)
	}
	// The refused source's service is never started.
	for _, c := range fu.Calls() {
		if c == "Start(argusd.service)" {
			t.Errorf("a refused source must never be started; saw %q", c)
		}
	}
}

// A refused owner's quadlet write is marked a CONFLICT (withheld, surfaced) —
// never removed from the plan (which would delete an existing source). A
// non-refused owner's action and system quadlets are untouched.
func TestStageRefusedOwnerQuadlets(t *testing.T) {
	in := &ir.IR{Quadlets: []ir.Quadlet{
		{Name: "argusd.container", Path: "/var/home/argus/.config/containers/systemd/argusd.container", Scope: ir.ScopeUser, Owner: "argus"},
		{Name: "ok.container", Path: "/var/home/bob/.config/containers/systemd/ok.container", Scope: ir.ScopeUser, Owner: "bob"},
	}}
	plan := &diff.Plan{Actions: []diff.ResourceAction{
		{Path: "/var/home/argus/.config/containers/systemd/argusd.container", Kind: diff.KindQuadlet, Action: diff.ActionUpdate},
		{Path: "/var/home/bob/.config/containers/systemd/ok.container", Kind: diff.KindQuadlet, Action: diff.ActionCreate},
		{Path: "/etc/core/x", Kind: diff.KindFile, Action: diff.ActionCreate},
	}}
	StageRefusedOwnerQuadlets(plan, in, map[string]string{"argus": "in docker without a grant"})

	byPath := map[string]diff.ResourceAction{}
	for _, a := range plan.Actions {
		byPath[a.Path] = a
	}
	// argus's quadlet: rewritten to conflict (withheld, NOT deleted).
	argus := byPath["/var/home/argus/.config/containers/systemd/argusd.container"]
	if argus.Action != diff.ActionConflict || !contains(argus.Reason, "docker") {
		t.Errorf("refused owner's quadlet should be a conflict: %+v", argus)
	}
	// bob's quadlet and the system file are untouched.
	if byPath["/var/home/bob/.config/containers/systemd/ok.container"].Action != diff.ActionCreate {
		t.Errorf("non-refused owner's action must be untouched")
	}
	if byPath["/etc/core/x"].Action != diff.ActionCreate {
		t.Errorf("system file action must be untouched")
	}
}

// The bounded config-tree chown: only ancestors STRICTLY below a real user home
// are returned; a system-path home (the escalation Codex flagged) yields nothing.
func TestConfigTreeDirsBounded(t *testing.T) {
	home := "/var/home/argus"
	q := "/var/home/argus/.config/containers/systemd/argusd.container"
	got := configTreeDirs("argus", home, q)
	want := []string{
		"/var/home/argus/.config",
		"/var/home/argus/.config/containers",
		"/var/home/argus/.config/containers/systemd",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("configTreeDirs = %v\nwant %v (strictly below home, shallowest-first)", got, want)
	}
	// The home itself and anything above it are never included.
	for _, d := range got {
		if d == home || len(d) <= len(home) {
			t.Errorf("%q is not strictly below the home", d)
		}
	}
	// A system-path home is refused outright — no /etc/.config chown vector.
	if dirs := configTreeDirs("argus", "/etc", "/etc/.config/containers/systemd/x.container"); dirs != nil {
		t.Errorf("system-path home must own nothing, got %v", dirs)
	}
	// Another user's home is refused — argus may own only /var/home/argus.
	if dirs := configTreeDirs("argus", "/var/home/core", "/var/home/core/.config/x/y.container"); dirs != nil {
		t.Errorf("a home that isn't the owner's must own nothing, got %v", dirs)
	}
}

// ownConfigTrees chowns exactly the below-home ancestors to the owner uid, and a
// chown failure fails closed (surfaced as an error the caller stages on).
func TestOwnConfigTrees(t *testing.T) {
	fc := &fakeChowner{}
	quads := []ir.Quadlet{{Path: "/var/home/argus/.config/containers/systemd/argusd.container"}}
	if err := ownConfigTrees(fc, "argus", "/var/home/argus", quads, 1000); err != nil {
		t.Fatal(err)
	}
	if len(fc.chowned) != 3 {
		t.Errorf("want 3 dirs chowned, got %v", fc.chowned)
	}
	for _, c := range fc.chowned {
		if c.uid != 1000 {
			t.Errorf("chown to %d, want 1000", c.uid)
		}
	}
	// A system-path home chowns nothing (bounded, even if the caller passes it).
	fc2 := &fakeChowner{}
	_ = ownConfigTrees(fc2, "argus", "/etc", []ir.Quadlet{{Path: "/etc/.config/x/y.container"}}, 1000)
	if len(fc2.chowned) != 0 {
		t.Errorf("system home must chown nothing, got %v", fc2.chowned)
	}
}

func TestFilterUnmanagedUserQuadlets(t *testing.T) {
	in := &ir.IR{Quadlets: []ir.Quadlet{
		{Name: "argusd.container", Scope: ir.ScopeUser, Owner: "argus"}, // managed → kept
		{Name: "core-x.container", Scope: ir.ScopeUser, Owner: "core"},  // unmanaged → dropped
		{Name: "sys.container", Scope: ir.ScopeSystem},                  // system → kept
	}}
	managed := func(n string) bool { return n == "argus" }
	got := FilterUnmanagedUserQuadlets(in, managed)
	if len(got.Quadlets) != 2 {
		t.Fatalf("want 2 kept (argus user + system), got %d: %+v", len(got.Quadlets), got.Quadlets)
	}
	for _, q := range got.Quadlets {
		if q.Owner == "core" {
			t.Errorf("unmanaged owner's quadlet leaked through: %+v", q)
		}
	}
	// The input is not mutated.
	if len(in.Quadlets) != 3 {
		t.Errorf("filter mutated the input IR")
	}
}

type chownCall struct {
	path string
	uid  int
}
type fakeChowner struct{ chowned []chownCall }

func (f *fakeChowner) Chown(path string, uid, gid *int) error {
	u := -1
	if uid != nil {
		u = *uid
	}
	f.chowned = append(f.chowned, chownCall{path, u})
	return nil
}

// assertBefore checks a appears before b in calls.
func assertBefore(t *testing.T, calls []string, a, b string) {
	t.Helper()
	ia, ib := slices.Index(calls, a), slices.Index(calls, b)
	if ia < 0 || ib < 0 || ia >= ib {
		t.Errorf("expected %q before %q in %v", a, b, calls)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

var errTest = errString("boom")

type errString string

func (e errString) Error() string { return string(e) }
