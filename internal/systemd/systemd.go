// Package systemd is the interaction surface apply uses to drive systemd.
//
// The Manager interface keeps the call sites narrow and testable: real
// production paths shell out to /usr/bin/systemctl via osManager; unit tests
// use a fake that records calls and returns scripted responses.
//
// Why shell-out instead of dbus: dbus would be more idiomatic, but it
// requires a live bus connection and a much more elaborate fake to drive
// reliably in tests. Shell-out has well-defined exit codes per systemctl(1)
// and runs anywhere systemctl exists. The Manager interface is opaque enough
// that swapping in dbus later is a private implementation change.
package systemd

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Enablement is the subset of systemctl is-enabled output magus reasons over.
// systemd's full vocabulary (enabled-runtime, indirect, alias, generated, ...)
// collapses into one of these for reconciliation purposes.
type Enablement string

const (
	EnablementEnabled  Enablement = "enabled"
	EnablementDisabled Enablement = "disabled"
	EnablementMasked   Enablement = "masked"
	EnablementStatic   Enablement = "static" // can't be enabled/disabled
	EnablementNotFound Enablement = "not-found"
	EnablementUnknown  Enablement = "unknown"
)

// ErrUnavailable is returned by all Manager methods when systemctl cannot be
// invoked — typically because magus is running on a system without systemd
// (development on macOS, for example). Apply turns this into a per-resource
// error rather than halting the whole apply.
var ErrUnavailable = errors.New("systemctl is unavailable on this host")

// UnitStatus is a unit's persistent + runtime state, fetched in a single
// `systemctl show` call: Enablement (from UnitFileState) and Active (the raw
// is-active vocabulary). Combining the two into one query replaces the separate
// is-enabled + is-active forks the reconcile/observe paths used to make.
type UnitStatus struct {
	Enablement Enablement
	Active     string // "active"/"inactive"/"failed"/… or "unknown"
}

// IsActive reports whether the unit is currently running.
func (s UnitStatus) IsActive() bool { return s.Active == "active" }

// Manager is the operation surface apply needs. Keep it narrow — every method
// here corresponds to a step in the spec's apply mechanics for units.
type Manager interface {
	// DaemonReload re-reads unit files. Run exactly once per apply, after
	// all unit filesystem mutations and before enablement reconciliation.
	DaemonReload() error
	// Show returns the unit's enablement and runtime state in one query
	// (`systemctl show`), replacing the separate is-enabled/is-active forks.
	Show(unit string) (UnitStatus, error)
	// Enable persists the enablement symlinks but does not start the unit.
	Enable(unit string) error
	// EnableNow enables and starts the unit in one operation.
	EnableNow(unit string) error
	// Disable removes enablement symlinks but does not stop the unit.
	Disable(unit string) error
	// DisableNow disables and stops the unit in one operation.
	DisableNow(unit string) error
	// Restart restarts the unit. Used on content change for already-active
	// units.
	Restart(unit string) error
	// Start starts the unit without touching enablement. Used for quadlet
	// generated services, which CANNOT be enabled (systemd refuses to enable a
	// generated unit) — their boot persistence comes from the [Install] section
	// the quadlet generator processes, so magus only needs to start them.
	Start(unit string) error
	// Stop stops the unit without touching enablement. Used to tear down a
	// quadlet's generated service before its source is unlinked.
	Stop(unit string) error
}

// OS returns a Manager backed by the real systemctl binary. If systemctl
// isn't on PATH at construction time, the returned Manager will return
// ErrUnavailable for every call — this lets magus run on dev machines
// without systemd and surface unit operations as per-resource errors rather
// than crashing.
func OS() Manager {
	path, err := exec.LookPath("systemctl")
	if err != nil {
		return unavailableManager{}
	}
	return &osManager{path: path}
}

type osManager struct{ path string }

func (m *osManager) run(args ...string) error {
	cmd := exec.Command(m.path, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *osManager) runOutput(args ...string) (string, error) {
	cmd := exec.Command(m.path, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (m *osManager) DaemonReload() error          { return m.run("daemon-reload") }
func (m *osManager) Enable(unit string) error     { return m.run("enable", unit) }
func (m *osManager) EnableNow(unit string) error  { return m.run("enable", "--now", unit) }
func (m *osManager) Disable(unit string) error    { return m.run("disable", unit) }
func (m *osManager) DisableNow(unit string) error { return m.run("disable", "--now", unit) }
func (m *osManager) Restart(unit string) error    { return m.run("restart", unit) }
func (m *osManager) Start(unit string) error      { return m.run("start", unit) }
func (m *osManager) Stop(unit string) error       { return m.run("stop", unit) }

func (m *osManager) Show(unit string) (UnitStatus, error) {
	// `systemctl show` prints KEY=value lines and exits 0 even for a not-found
	// unit (LoadState=not-found), so — like the old is-enabled/is-active — we
	// parse the text and ignore the exit code.
	out, _ := m.runOutput("show", unit,
		"--property=LoadState", "--property=UnitFileState", "--property=ActiveState")
	return parseShow(out), nil
}

// parseEnablement maps `systemctl is-enabled` output to the Enablement subset
// magus reasons over. Pure so it's unit-testable without systemctl.
func parseEnablement(out string) Enablement {
	switch out {
	case "enabled", "enabled-runtime", "alias", "indirect":
		return EnablementEnabled
	case "disabled":
		return EnablementDisabled
	case "masked", "masked-runtime":
		return EnablementMasked
	case "static", "transient", "generated":
		return EnablementStatic
	}
	if strings.Contains(out, "not loaded") || strings.Contains(out, "No such file") {
		return EnablementNotFound
	}
	return EnablementUnknown
}

// parseShow parses `systemctl show -p LoadState -p UnitFileState -p ActiveState`
// output (KEY=value lines) into a UnitStatus. Pure so it's unit-testable without
// systemctl.
func parseShow(out string) UnitStatus {
	var loadState, unitFileState, activeState string
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "LoadState":
			loadState = val
		case "UnitFileState":
			unitFileState = val
		case "ActiveState":
			activeState = val
		}
	}
	return UnitStatus{
		Enablement: enablementFromShow(loadState, unitFileState),
		Active:     parseActiveState(activeState),
	}
}

// enablementFromShow maps a unit's LoadState + UnitFileState to the Enablement
// subset, matching `is-enabled` semantics. not-found and masked are recognized
// by LoadState; otherwise UnitFileState carries the same vocabulary is-enabled
// prints (enabled/disabled/static/…). An empty UnitFileState — a loaded unit
// with no [Install] — is treated as static (is-enabled reports "static" for
// these), so magus never tries to enable an un-enableable unit.
func enablementFromShow(loadState, unitFileState string) Enablement {
	switch loadState {
	case "not-found":
		return EnablementNotFound
	case "masked", "masked-runtime":
		return EnablementMasked
	}
	if unitFileState == "" {
		return EnablementStatic
	}
	return parseEnablement(unitFileState)
}

// parseActiveState maps `systemctl is-active` output to the known state
// vocabulary, or "unknown" for anything unexpected (e.g. systemd unreachable
// noise on stderr). Pure so it's unit-testable without systemctl.
func parseActiveState(out string) string {
	switch out {
	case "active", "inactive", "failed", "activating", "deactivating", "reloading":
		return out
	}
	return "unknown"
}

// unavailableManager is the substitute returned when systemctl isn't on PATH.
type unavailableManager struct{}

func (unavailableManager) DaemonReload() error { return ErrUnavailable }
func (unavailableManager) Show(string) (UnitStatus, error) {
	return UnitStatus{Enablement: EnablementUnknown, Active: "unknown"}, ErrUnavailable
}
func (unavailableManager) Enable(string) error     { return ErrUnavailable }
func (unavailableManager) EnableNow(string) error  { return ErrUnavailable }
func (unavailableManager) Disable(string) error    { return ErrUnavailable }
func (unavailableManager) DisableNow(string) error { return ErrUnavailable }
func (unavailableManager) Restart(string) error    { return ErrUnavailable }
func (unavailableManager) Start(string) error      { return ErrUnavailable }
func (unavailableManager) Stop(string) error       { return ErrUnavailable }
