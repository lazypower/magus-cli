package systemd

import (
	"errors"
	"testing"
)

// TestFakeRecordsCallsInOrder validates the test double the apply suite relies
// on: every operation is recorded in invocation order so tests can assert
// sequencing (e.g. daemon-reload once, after writes).
func TestFakeRecordsCallsInOrder(t *testing.T) {
	f := NewFake()
	_ = f.DaemonReload()
	_ = f.Enable("a.service")
	_ = f.EnableNow("b.service")
	_ = f.Disable("c.service")
	_ = f.DisableNow("d.service")
	_ = f.Restart("e.service")
	_ = f.Start("f.service")
	_ = f.Stop("g.service")

	want := []string{
		"DaemonReload",
		"Enable(a.service)",
		"EnableNow(b.service)",
		"Disable(c.service)",
		"DisableNow(d.service)",
		"Restart(e.service)",
		"Start(f.service)",
		"Stop(g.service)",
	}
	got := f.Calls()
	if len(got) != len(want) {
		t.Fatalf("calls = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("call %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestFakeFailNext validates per-call error injection (used to test apply's
// per-resource error isolation).
func TestFakeFailNext(t *testing.T) {
	f := NewFake()
	boom := errors.New("boom")
	f.FailNext("Restart(x.service)", boom)
	if err := f.Restart("x.service"); !errors.Is(err, boom) {
		t.Errorf("FailNext not honored: %v", err)
	}
	// One-shot: the next call succeeds.
	if err := f.Restart("x.service"); err != nil {
		t.Errorf("FailNext should be one-shot: %v", err)
	}
}

func TestFakeEnablementAndActivity(t *testing.T) {
	f := NewFake()
	if s, _ := f.Show("x.service"); s.Enablement != EnablementDisabled {
		t.Errorf("default enablement = %q, want disabled", s.Enablement)
	}
	f.SetEnablement("x.service", EnablementEnabled)
	if s, _ := f.Show("x.service"); s.Enablement != EnablementEnabled {
		t.Errorf("SetEnablement not honored: %q", s.Enablement)
	}
	if s, _ := f.Show("x.service"); s.IsActive() {
		t.Errorf("default activity should be inactive")
	}
	f.SetActive("x.service", true)
	if s, _ := f.Show("x.service"); !s.IsActive() {
		t.Errorf("SetActive not honored")
	}
}

// TestUnavailableManager covers the no-systemd substitute: every method returns
// ErrUnavailable so apply surfaces unit ops as per-resource errors on a host
// without systemd, rather than crashing.
func TestUnavailableManager(t *testing.T) {
	var m Manager = unavailableManager{}
	if err := m.DaemonReload(); !errors.Is(err, ErrUnavailable) {
		t.Errorf("DaemonReload: %v", err)
	}
	if s, err := m.Show("x"); !errors.Is(err, ErrUnavailable) || s.Active != "unknown" {
		t.Errorf("Show: %+v %v", s, err)
	}
	for name, fn := range map[string]func(string) error{
		"Enable": m.Enable, "EnableNow": m.EnableNow,
		"Disable": m.Disable, "DisableNow": m.DisableNow, "Restart": m.Restart,
		"Start": m.Start, "Stop": m.Stop,
	} {
		if err := fn("x"); !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestOSReturnsManager confirms OS() always yields a usable Manager (the real
// systemctl one when present, the unavailable substitute otherwise).
func TestOSReturnsManager(t *testing.T) {
	if OS() == nil {
		t.Fatal("OS() returned nil")
	}
}
