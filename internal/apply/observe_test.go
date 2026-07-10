package apply

import (
	"errors"
	"testing"

	"github.com/lazypower/magus-cli/internal/ir"
	"github.com/lazypower/magus-cli/internal/systemd"
)

func TestObserveUnitsReportsRawState(t *testing.T) {
	sd := systemd.NewFake()
	sd.SetActiveState("a.service", "failed") // raw state preserved, not "inactive"
	sd.SetActive("b.service", true)          // falls back to "active"
	sd.FailNext("Show(c.service)", errors.New("systemd unreachable"))

	in := &ir.IR{Units: []ir.Unit{
		{Name: "a.service"}, {Name: "b.service"}, {Name: "c.service"},
	}}
	got := ObserveUnits(in, sd)

	if got["a.service"] != "failed" {
		t.Errorf("a.service = %q, want failed (raw state must survive)", got["a.service"])
	}
	if got["b.service"] != "active" {
		t.Errorf("b.service = %q, want active", got["b.service"])
	}
	if got["c.service"] != "unknown" {
		t.Errorf("c.service = %q, want unknown on query error", got["c.service"])
	}
}

func TestObserveUnitsCoversQuadletServices(t *testing.T) {
	sd := systemd.NewFake()
	sd.SetActiveState("app.service", "activating")
	in := &ir.IR{Quadlets: []ir.Quadlet{{Name: "app.container", Path: "/etc/containers/systemd/app.container"}}}
	if got := ObserveUnits(in, sd); got["app.service"] != "activating" {
		t.Errorf("quadlet generated service = %q, want activating", got["app.service"])
	}
}
