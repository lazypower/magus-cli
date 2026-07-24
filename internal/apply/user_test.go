package apply

import (
	"slices"
	"strings"
	"testing"

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

	outs := ReconcileUserWorkloads(in, allChanged(in), factory)

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

	outs := ReconcileUserWorkloads(in, allChanged(in), func(string, int) systemd.UserManager { return fu })

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

	outs := ReconcileUserWorkloads(in, map[string]bool{}, func(string, int) systemd.UserManager { return fu })

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

	outs := ReconcileUserWorkloads(in, changed, func(string, int) systemd.UserManager { return fu })

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
	if outs := ReconcileUserWorkloads(argusIR(), nil, nil); outs != nil {
		t.Errorf("nil factory disables activation; got %+v", outs)
	}
	sysOnly := &ir.IR{Quadlets: []ir.Quadlet{{Name: "x.container", Scope: ir.ScopeSystem}}}
	if outs := ReconcileUserWorkloads(sysOnly, nil, func(string, int) systemd.UserManager { return systemd.NewFakeUser() }); outs != nil {
		t.Errorf("no user workloads → no outcomes; got %+v", outs)
	}
}

// A user daemon-reload failure stages the workloads (fail-closed), not errored-
// green.
func TestReconcileUserWorkloadsReloadFailureStages(t *testing.T) {
	in := argusIR()
	fu := systemd.NewFakeUser()
	fu.FailNext("DaemonReload", errTest)

	outs := ReconcileUserWorkloads(in, allChanged(in), func(string, int) systemd.UserManager { return fu })
	for _, o := range outs {
		if o.Status != StatusSkipped || !contains(o.Reason, "daemon-reload failed") {
			t.Errorf("reload failure should stage: %+v", o)
		}
	}
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
