package systemd

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestUserTransportArgs(t *testing.T) {
	got := userTransportArgs("argus", 1000, "start", "argusd.service")
	want := []string{
		"-u", "argus", "--",
		"env", "XDG_RUNTIME_DIR=/run/user/1000",
		"systemctl", "--user",
		"start", "argusd.service",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("userTransportArgs =\n %v\nwant\n %v", got, want)
	}
}

func TestUserManagerOperational(t *testing.T) {
	for _, s := range []string{"running", "degraded", "  running\n"} {
		if !userManagerOperational(s) {
			t.Errorf("%q should be operational", s)
		}
	}
	for _, s := range []string{"starting", "stopping", "maintenance", "offline", "", "unknown"} {
		if userManagerOperational(s) {
			t.Errorf("%q must not be operational", s)
		}
	}
}

// newTestUser builds an osUser with injected seams so the transport and
// readiness logic are provable without runuser/systemctl.
func newTestUser(uid int, run func(args ...string) (string, error), runtimeReady func() bool) *osUser {
	return &osUser{name: "argus", uid: uid, run: run, runtimeReady: runtimeReady}
}

func TestUserManagerReady(t *testing.T) {
	// runtime dir missing → not ready, with a linger-pointing reason; is-system-
	// running is never consulted (the manager can't be up without /run/user).
	consulted := false
	u := newTestUser(1000,
		func(args ...string) (string, error) { consulted = true; return "", nil },
		func() bool { return false })
	if ok, reason := u.Ready(); ok || reason == "" {
		t.Errorf("missing runtime dir → not ready with reason; got %v,%q", ok, reason)
	}
	if consulted {
		t.Error("is-system-running must not be consulted when /run/user is absent")
	}

	// runtime present + running → ready.
	u2 := newTestUser(1000,
		func(args ...string) (string, error) { return "running", nil },
		func() bool { return true })
	if ok, reason := u2.Ready(); !ok || reason != "" {
		t.Errorf("running manager → ready; got %v,%q", ok, reason)
	}

	// runtime present but manager starting → not ready (staged, not activated).
	u3 := newTestUser(1000,
		func(args ...string) (string, error) { return "starting", nil },
		func() bool { return true })
	if ok, reason := u3.Ready(); ok || reason == "" {
		t.Errorf("starting manager → not ready; got %v,%q", ok, reason)
	}
}

func TestUserManagerOpsUseTransport(t *testing.T) {
	var got [][]string
	run := func(args ...string) (string, error) {
		got = append(got, args)
		return "", nil
	}
	u := newTestUser(1000, run, func() bool { return true })
	if err := u.DaemonReload(); err != nil {
		t.Fatal(err)
	}
	if err := u.Start("argusd.service"); err != nil {
		t.Fatal(err)
	}
	if err := u.Restart("argusd.service"); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"daemon-reload"},
		{"start", "argusd.service"},
		{"restart", "argusd.service"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ops sent %v, want %v", got, want)
	}
}

func TestUserManagerWrapsError(t *testing.T) {
	u := newTestUser(1000,
		func(args ...string) (string, error) { return "Failed to start", errors.New("exit 1") },
		func() bool { return true })
	err := u.Start("argusd.service")
	if err == nil {
		t.Fatal("a failed systemctl --user must return an error")
	}
	// The message names the user and folds stderr for diagnosability.
	if got := err.Error(); !strings.Contains(got, "as argus") || !strings.Contains(got, "Failed to start") {
		t.Errorf("error missing context: %q", got)
	}
}

func TestUserManagerShowParses(t *testing.T) {
	u := newTestUser(1000, func(args ...string) (string, error) {
		return "LoadState=loaded\nUnitFileState=static\nActiveState=active", nil
	}, func() bool { return true })
	st, err := u.Show("argusd.service")
	if err != nil {
		t.Fatal(err)
	}
	if !st.IsActive() {
		t.Errorf("Show should report active, got %+v", st)
	}
}
