package systemd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// UserManager reconciles a single principal's user-scope systemd — its
// user@<uid> manager — so magus can activate the rootless quadlets that
// principal owns. It is the sibling of Manager (system scope): the same
// start-not-enable posture, but reached over the per-user bus.
//
// The transport is settled empirically (ADR-0003; proven on FCOS): every
// operation runs as
//
//	runuser -u <name> -- env XDG_RUNTIME_DIR=/run/user/<uid> systemctl --user <op>
//
// which connects straight to the user's private bus. `systemctl --user -M
// <name>@` is a trap — it needs systemd-machined, which is inactive by default
// on FCOS, and passes the Mac libkrun shim while failing on real iron. There is
// no Enable/Disable here: a user quadlet's generated service is started, never
// enabled (boot persistence is linger + the quadlet [Install]).
type UserManager interface {
	// DaemonReload re-reads the user generator so a newly written quadlet
	// materializes its .service. Run once per apply per user, after the user's
	// quadlet sources are written and before its services are started.
	DaemonReload() error
	// Start starts a user-scope unit without touching enablement.
	Start(unit string) error
	// Restart restarts a user-scope unit (content change on an active service).
	Restart(unit string) error
	// Show returns the user unit's enablement + runtime state in one query.
	Show(unit string) (UnitStatus, error)
	// Ready reports whether the user manager is operational — /run/user/<uid>
	// present AND `systemctl --user is-system-running` in {running, degraded}.
	// When it is not, reason is the honest-skip message ("staged, not
	// activated") the spine cascades to a user quadlet that can't yet activate.
	Ready() (ok bool, reason string)
}

// OSUser returns a UserManager for principal name (uid) backed by real
// runuser+systemctl. If runuser isn't on PATH, every call returns ErrUnavailable
// — magus degrades to per-resource errors rather than crashing off-host.
func OSUser(name string, uid int) UserManager {
	if _, err := exec.LookPath("runuser"); err != nil {
		return unavailableUser{}
	}
	return &osUser{
		name: name,
		uid:  uid,
		run: func(args ...string) (string, error) {
			cmd := exec.Command("runuser", userTransportArgs(name, uid, args...)...)
			out, err := cmd.CombinedOutput()
			return strings.TrimSpace(string(out)), err
		},
		runtimeReady: func() bool {
			fi, err := os.Stat(runtimeDir(uid))
			return err == nil && fi.IsDir()
		},
	}
}

type osUser struct {
	name         string
	uid          int
	run          func(args ...string) (string, error) // systemctl --user <args>, trimmed combined output
	runtimeReady func() bool                          // /run/user/<uid> present
}

func (u *osUser) DaemonReload() error       { return u.wrap("daemon-reload") }
func (u *osUser) Start(unit string) error   { return u.wrap("start", unit) }
func (u *osUser) Restart(unit string) error { return u.wrap("restart", unit) }

func (u *osUser) wrap(args ...string) error {
	if out, err := u.run(args...); err != nil {
		return fmt.Errorf("systemctl --user %s (as %s): %w: %s",
			strings.Join(args, " "), u.name, err, out)
	}
	return nil
}

func (u *osUser) Show(unit string) (UnitStatus, error) {
	// Same as system Show: `systemctl show` prints KEY=value and exits 0 even for
	// not-found, so parse the text and ignore the exit code.
	out, _ := u.run("show", unit,
		"--property=LoadState", "--property=UnitFileState", "--property=ActiveState")
	return parseShow(out), nil
}

func (u *osUser) Ready() (bool, string) {
	if !u.runtimeReady() {
		return false, fmt.Sprintf("/run/user/%d not present — user@%d.service not started (linger enabled?)", u.uid, u.uid)
	}
	out, _ := u.run("is-system-running")
	if userManagerOperational(out) {
		return true, ""
	}
	return false, fmt.Sprintf("user@%d is %q, not operational", u.uid, strings.TrimSpace(out))
}

// runtimeDir is the XDG runtime dir for uid — the presence of which is the first
// half of "is the user manager up".
func runtimeDir(uid int) string { return fmt.Sprintf("/run/user/%d", uid) }

// userTransportArgs builds the runuser argv that runs `systemctl --user op...`
// as name over its private bus. Pure — unit-tested; it is the one place the
// settled transport shape is encoded.
func userTransportArgs(name string, uid int, op ...string) []string {
	return append([]string{
		"-u", name, "--",
		"env", "XDG_RUNTIME_DIR=" + runtimeDir(uid),
		"systemctl", "--user",
	}, op...)
}

// userManagerOperational reports whether `is-system-running` output means the
// user manager can activate units. running is the happy path; degraded means
// some unit failed but the manager and bus are up — activation still works, so
// magus treats it as operational (matching the readiness gate proven on FCOS).
func userManagerOperational(isSystemRunning string) bool {
	switch strings.TrimSpace(isSystemRunning) {
	case "running", "degraded":
		return true
	}
	return false
}

// unavailableUser is returned when runuser isn't on PATH (dev off-host).
type unavailableUser struct{}

func (unavailableUser) DaemonReload() error  { return ErrUnavailable }
func (unavailableUser) Start(string) error   { return ErrUnavailable }
func (unavailableUser) Restart(string) error { return ErrUnavailable }
func (unavailableUser) Show(string) (UnitStatus, error) {
	return UnitStatus{Enablement: EnablementUnknown, Active: "unknown"}, ErrUnavailable
}
func (unavailableUser) Ready() (bool, string) { return false, "runuser is unavailable on this host" }
