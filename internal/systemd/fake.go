package systemd

import (
	"fmt"
	"sync"
)

// Fake is an in-memory Manager for tests. It records every call into Calls()
// in order so tests can assert sequencing (e.g., daemon-reload happens once,
// after all writes), and it lets tests preload enablement / activity state.
type Fake struct {
	mu          sync.Mutex
	calls       []string
	enablement  map[string]Enablement
	activity    map[string]bool
	states      map[string]string // raw is-active state override (for ActiveState)
	failOn      map[string]error  // method-name → error to return on next call
	failCounter map[string]int
}

// NewFake returns a Fake with empty state and reasonable defaults: every
// unit reports EnablementDisabled and inactive until explicitly set.
func NewFake() *Fake {
	return &Fake{
		enablement:  map[string]Enablement{},
		activity:    map[string]bool{},
		states:      map[string]string{},
		failOn:      map[string]error{},
		failCounter: map[string]int{},
	}
}

// SetEnablement preloads what IsEnabled returns for unit.
func (f *Fake) SetEnablement(unit string, e Enablement) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enablement[unit] = e
}

// SetActive preloads what IsActive returns for unit.
func (f *Fake) SetActive(unit string, active bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.activity[unit] = active
}

// FailNext makes the next call to method (e.g., "Enable", "Restart") return
// err. Used to test per-resource error isolation.
func (f *Fake) FailNext(method string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failOn[method] = err
}

// Calls returns the call log in invocation order. Each entry is the method
// name plus its argument(s), e.g., "DaemonReload" or "Enable(magus-foo.service)".
func (f *Fake) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

func (f *Fake) record(method string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, method)
	if err, ok := f.failOn[method]; ok {
		delete(f.failOn, method)
		return err
	}
	return nil
}

func (f *Fake) DaemonReload() error {
	return f.record("DaemonReload")
}

// SetActiveState preloads the raw is-active state Show returns for unit.
func (f *Fake) SetActiveState(unit, state string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.states[unit] = state
}

// Show returns the preloaded enablement + active state in one call, mirroring
// the real `systemctl show` consolidation. Enablement defaults to disabled and
// active state to inactive until set via SetEnablement / SetActive(State).
func (f *Fake) Show(unit string) (UnitStatus, error) {
	if err := f.record(fmt.Sprintf("Show(%s)", unit)); err != nil {
		return UnitStatus{Enablement: EnablementUnknown, Active: "unknown"}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	enb := EnablementDisabled
	if e, ok := f.enablement[unit]; ok {
		enb = e
	}
	active := "inactive"
	if s, ok := f.states[unit]; ok {
		active = s
	} else if f.activity[unit] {
		active = "active"
	}
	return UnitStatus{Enablement: enb, Active: active}, nil
}

func (f *Fake) Enable(unit string) error {
	if err := f.record(fmt.Sprintf("Enable(%s)", unit)); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enablement[unit] = EnablementEnabled
	return nil
}

func (f *Fake) EnableNow(unit string) error {
	if err := f.record(fmt.Sprintf("EnableNow(%s)", unit)); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enablement[unit] = EnablementEnabled
	f.activity[unit] = true
	return nil
}

func (f *Fake) Disable(unit string) error {
	if err := f.record(fmt.Sprintf("Disable(%s)", unit)); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enablement[unit] = EnablementDisabled
	return nil
}

func (f *Fake) DisableNow(unit string) error {
	if err := f.record(fmt.Sprintf("DisableNow(%s)", unit)); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enablement[unit] = EnablementDisabled
	f.activity[unit] = false
	return nil
}

func (f *Fake) Restart(unit string) error {
	if err := f.record(fmt.Sprintf("Restart(%s)", unit)); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.activity[unit] = true
	return nil
}

func (f *Fake) Start(unit string) error {
	if err := f.record(fmt.Sprintf("Start(%s)", unit)); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.activity[unit] = true
	return nil
}

func (f *Fake) Stop(unit string) error {
	if err := f.record(fmt.Sprintf("Stop(%s)", unit)); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.activity[unit] = false
	return nil
}

// FakeUser is an in-memory UserManager for tests. Like Fake it records calls in
// order and supports fail injection; additionally it models the readiness gate
// (Ready) that the rootless spine's honest-skip turns on.
type FakeUser struct {
	mu       sync.Mutex
	calls    []string
	states   map[string]string // unit → raw active state
	ready    bool
	notReady string           // reason returned when !ready
	failOn   map[string]error // method-name → error on next call
}

// NewFakeUser returns a FakeUser that is operational (Ready → true) by default,
// so the common path activates; call SetReady(false, reason) to exercise the
// staged-not-activated skip.
func NewFakeUser() *FakeUser {
	return &FakeUser{
		states: map[string]string{},
		ready:  true,
		failOn: map[string]error{},
	}
}

// SetReady controls what Ready reports (reason is used only when ready is false).
func (f *FakeUser) SetReady(ready bool, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ready, f.notReady = ready, reason
}

// SetActiveState preloads the raw active state Show returns for unit.
func (f *FakeUser) SetActiveState(unit, state string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.states[unit] = state
}

// FailNext makes the next call to method return err.
func (f *FakeUser) FailNext(method string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failOn[method] = err
}

// Calls returns the call log in invocation order.
func (f *FakeUser) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

func (f *FakeUser) record(method string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, method)
	if err, ok := f.failOn[method]; ok {
		delete(f.failOn, method)
		return err
	}
	return nil
}

func (f *FakeUser) DaemonReload() error     { return f.record("DaemonReload") }
func (f *FakeUser) Start(unit string) error { return f.record(fmt.Sprintf("Start(%s)", unit)) }
func (f *FakeUser) Restart(unit string) error {
	if err := f.record(fmt.Sprintf("Restart(%s)", unit)); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.states[unit] = "active"
	return nil
}

func (f *FakeUser) Show(unit string) (UnitStatus, error) {
	if err := f.record(fmt.Sprintf("Show(%s)", unit)); err != nil {
		return UnitStatus{Enablement: EnablementUnknown, Active: "unknown"}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	active := "inactive"
	if s, ok := f.states[unit]; ok {
		active = s
	}
	return UnitStatus{Enablement: EnablementStatic, Active: active}, nil
}

func (f *FakeUser) Ready() (bool, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "Ready")
	if f.ready {
		return true, ""
	}
	return false, f.notReady
}
