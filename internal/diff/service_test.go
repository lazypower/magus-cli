package diff

import (
	"errors"
	"testing"

	"github.com/lazypower/magus-cli/internal/ir"
	"github.com/lazypower/magus-cli/internal/systemd"
)

func boolPtr(b bool) *bool { return &b }

func TestEnablementOp(t *testing.T) {
	cases := []struct {
		name    string
		desired *bool
		current systemd.Enablement
		wantOp  ServiceOp
	}{
		{"undeclared", nil, systemd.EnablementEnabled, ""},
		{"enable-drift", boolPtr(true), systemd.EnablementDisabled, ServiceEnable},
		{"enable-unknown", boolPtr(true), systemd.EnablementUnknown, ServiceEnable},
		{"already-enabled", boolPtr(true), systemd.EnablementEnabled, ""},
		{"enable-masked", boolPtr(true), systemd.EnablementMasked, ServiceSkip},
		{"enable-static", boolPtr(true), systemd.EnablementStatic, ServiceSkip},
		{"enable-notfound", boolPtr(true), systemd.EnablementNotFound, ServiceSkip},
		{"disable-drift", boolPtr(false), systemd.EnablementEnabled, ServiceDisable},
		{"already-disabled", boolPtr(false), systemd.EnablementDisabled, ""},
		{"disable-masked-noop", boolPtr(false), systemd.EnablementMasked, ""},
		{"disable-static-noop", boolPtr(false), systemd.EnablementStatic, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			op, reason := EnablementOp(c.desired, c.current)
			if op != c.wantOp {
				t.Errorf("op = %q, want %q", op, c.wantOp)
			}
			if op != "" && reason == "" {
				t.Errorf("op %q should carry a reason", op)
			}
		})
	}
}

func TestPlanServiceStateExistingDrift(t *testing.T) {
	sd := systemd.NewFake()
	sd.SetEnablement("magus-foo.service", systemd.EnablementDisabled)
	in := &ir.IR{Units: []ir.Unit{{Name: "magus-foo.service", Enabled: boolPtr(true)}}}
	plan := &Plan{}
	PlanServiceState(in, plan, sd)

	if len(plan.ServiceActions) != 1 {
		t.Fatalf("ServiceActions = %d, want 1: %+v", len(plan.ServiceActions), plan.ServiceActions)
	}
	if plan.ServiceActions[0].Op != ServiceEnable || plan.ServiceActions[0].Unit != "magus-foo.service" {
		t.Errorf("got %+v", plan.ServiceActions[0])
	}
}

func TestPlanServiceStateMaskedSkip(t *testing.T) {
	sd := systemd.NewFake()
	sd.SetEnablement("magus-foo.service", systemd.EnablementMasked)
	in := &ir.IR{Units: []ir.Unit{{Name: "magus-foo.service", Enabled: boolPtr(true)}}}
	plan := &Plan{}
	PlanServiceState(in, plan, sd)

	if len(plan.ServiceActions) != 1 || plan.ServiceActions[0].Op != ServiceSkip {
		t.Fatalf("want one skip row, got %+v", plan.ServiceActions)
	}
}

func TestPlanServiceStateUndeclaredNoRow(t *testing.T) {
	sd := systemd.NewFake()
	sd.SetEnablement("magus-foo.service", systemd.EnablementDisabled)
	in := &ir.IR{Units: []ir.Unit{{Name: "magus-foo.service", Enabled: nil}}}
	plan := &Plan{}
	PlanServiceState(in, plan, sd)

	if len(plan.ServiceActions) != 0 {
		t.Errorf("undeclared enablement must produce no rows, got %+v", plan.ServiceActions)
	}
}

func TestPlanServiceStateNewUnitEnables(t *testing.T) {
	sd := systemd.NewFake()
	in := &ir.IR{Units: []ir.Unit{{Name: "magus-foo.service", Enabled: boolPtr(true)}}}
	// A create action for the unit body marks it as new.
	plan := &Plan{Actions: []ResourceAction{{
		Path:     UnitPath("magus-foo.service"),
		Kind:     KindUnit,
		UnitName: "magus-foo.service",
		Action:   ActionCreate,
	}}}
	PlanServiceState(in, plan, sd)

	if len(plan.ServiceActions) != 1 || plan.ServiceActions[0].Op != ServiceEnable {
		t.Fatalf("new enabled unit should yield one enable row, got %+v", plan.ServiceActions)
	}
}

func TestPlanServiceStateSystemdUnavailableSkips(t *testing.T) {
	sd := systemd.NewFake()
	sd.FailNext("IsEnabled(magus-foo.service)", errors.New("no systemctl"))
	in := &ir.IR{Units: []ir.Unit{{Name: "magus-foo.service", Enabled: boolPtr(true)}}}
	plan := &Plan{}
	PlanServiceState(in, plan, sd)

	if len(plan.ServiceActions) != 0 {
		t.Errorf("unavailable systemd must not produce rows, got %+v", plan.ServiceActions)
	}
}
