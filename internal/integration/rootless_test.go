//go:build integration

package integration

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// These fixtures prove ADR-0003's rootless spine end to end on real systemd:
// magus creates a principal, provisions its subuid + linger, writes its
// user-scope quadlets, and activates them through the user manager — day-2, no
// reimage. They need a REAL kernel (real logind + user@<uid>); under nested
// libkrun on macOS logind ENODEVs, so they skip there. Run them on a real-kernel
// host (the magus KVM substrate).

// rootlessPolicy manages argus and roots its home so the user-scope quadlet
// sources can be written there. The home root is the identity analogue of a
// workload file_root: magus may write under a principal's home once it owns the
// principal.
const rootlessPolicy = `version: 1
file_roots:
  - /etc/core
  - /var/lib/magus
  - /var/home/argus
unit_patterns:
  - "magus-*"
manage_users:
  - argus
deny:
  paths:
    - /etc/shadow
    - /etc/passwd
`

// argusRootlessButane declares argus plus a single rootless container quadlet
// under argus's home. home_dir is REQUIRED for path-derived user scope (without
// it the quadlet silently degrades to an ordinary file — proven on real iron).
// Network=none keeps the proof to magus's activation, not the nested container's
// networking; the image is pre-loaded into argus's store so no registry pull is
// needed. No [Install]: magus itself starts the service (not default.target),
// proving magus drives activation.
func argusRootlessButane(uid string) string {
	return butaneHeader + `passwd:
  users:
    - name: argus
      uid: ` + uid + `
      home_dir: /var/home/argus
      shell: /usr/sbin/nologin
storage:
  files:
    - path: /var/home/argus/.config/containers/systemd/argusd.container
      mode: 0644
      contents:
        inline: |
          [Unit]
          Description=argus worker
          [Container]
          Image=docker.io/library/busybox
          Network=none
          Exec=sleep 3600
`
}

// TestRootlessActivation is acceptance #1: fresh host, no argus. Apply a Butane
// declaring argus + its rootless quadlet → the generated service reaches active
// under user@<uid>, day-2, no reimage.
//
// It converges over two reconcile ticks, which is honest reconciler behavior:
// `loginctl enable-linger` starts user@<uid> asynchronously, so on the first
// apply the manager isn't up yet and magus honestly stages the workload; the
// next tick (once the manager is operational) activates it. A timer-driven
// reconciler reaches this in seconds without a reimage.
func TestRootlessActivation(t *testing.T) {
	c := setup(t, rootlessPolicy)
	requireUserScope(t, c)
	bu := argusRootlessButane("1000")

	// Tick 1: provision identity + subuid + linger, write the quadlet. The user
	// manager isn't up yet, so the workload is staged (not activated), exit 2.
	out1, code1 := c.apply(bu)
	if _, idCode := c.exec("id", "argus"); idCode != 0 {
		t.Fatalf("argus was not created:\n%s", out1)
	}
	if !hasSubidRange(c, "argus") {
		t.Errorf("argus was not granted a subuid/subgid range")
	}
	if !c.exists("/var/lib/systemd/linger/argus") {
		t.Errorf("linger was not enabled for argus (no marker)")
	}
	if code1 != 2 || !strings.Contains(out1, "staged, not activated") {
		t.Errorf("tick 1 should stage the workload (exit 2), got %d\n%s", code1, out1)
	}

	// The manager comes up under linger; preload the workload image so the nested
	// rootless container needs no registry egress.
	if !waitUserManager(c, 1000, 90*time.Second) {
		t.Fatal("user@1000 never became operational after linger")
	}
	preloadUserImage(t, c, "argus", 1000, "docker.io/library/busybox")

	// Tick 2: manager up → magus starts the generated service → active.
	out2, code2 := c.apply(bu)
	t.Logf("tick 2 exit %d\n%s", code2, out2)
	if !waitUserActive(c, "argus", 1000, "argusd.service", 60*time.Second) {
		st := userSystemctl(c, "argus", 1000, "status", "argusd.service")
		t.Fatalf("argusd.service did not reach active under user@1000\ntick2:\n%s\nstatus:\n%s", out2, st)
	}

	// Idempotence: a third apply neither recreates the principal nor disturbs the
	// healthy workload — argus is adopted, argusd stays up.
	sig := c.statSig("/etc/passwd")
	out3, _ := c.apply(bu)
	if userActive(c, "argus", 1000, "argusd.service") != "active" {
		t.Errorf("third apply disturbed a healthy workload:\n%s", out3)
	}
	if after := c.statSig("/etc/passwd"); after != sig {
		t.Errorf("third apply rewrote /etc/passwd — argus was not adopted")
	}
}

// TestRootlessStagedWhenManagerDown is acceptance #2: hold the user manager down
// (mask user@<uid>) and assert magus reports the workload staged, not activated —
// never a green that lies — then unmask and re-apply to prove it resumes.
func TestRootlessStagedWhenManagerDown(t *testing.T) {
	c := setup(t, rootlessPolicy)
	requireUserScope(t, c)

	// Mask the templated user manager so linger can be enabled but user@1000 can
	// never start — /run/user/1000 stays absent, the readiness gate stays closed.
	if out, code := c.exec("systemctl", "mask", "user@1000.service"); code != 0 {
		t.Fatalf("mask user@1000: %s", out)
	}

	out, code := c.apply(argusRootlessButane("1000"))
	if code != 2 {
		t.Errorf("staged workload should exit 2 (skips present), got %d\n%s", code, out)
	}
	if !strings.Contains(out, "staged, not activated") {
		t.Errorf("magus did not report the workload staged:\n%s", out)
	}
	if userActive(c, "argus", 1000, "argusd.service") == "active" {
		t.Errorf("argusd is active though the user manager was held down — the honest-skip lied")
	}

	// Resume: unmask and re-apply → the manager comes up and the workload activates
	// (no recreate, linger already present).
	if out, code := c.exec("systemctl", "unmask", "user@1000.service"); code != 0 {
		t.Fatalf("unmask user@1000: %s", out)
	}
	if out, code := c.apply(argusRootlessButane("1000")); code != 0 && code != 2 {
		t.Logf("resume apply exit %d\n%s", code, out)
	}
	if !waitUserActive(c, "argus", 1000, "argusd.service", 120*time.Second) {
		t.Errorf("workload did not resume to active after the manager came back")
	}
}

// TestRootlessPartialSuccessResumes is acceptance #3: the principal is created
// but enable-linger fails mid-apply. Status is staged (not errored-green), the
// created principal is recorded, and a re-apply resumes from it — linger retried,
// no orphan, no recreate.
func TestRootlessPartialSuccessResumes(t *testing.T) {
	c := setup(t, rootlessPolicy)
	requireUserScope(t, c)

	// Break loginctl so magus's enable-linger fails mid-apply. Detection uses the
	// /var/lib/systemd/linger marker (not loginctl), so only provisioning breaks.
	if out, code := c.exec("mv", "/usr/bin/loginctl", "/usr/bin/loginctl.bak"); code != 0 {
		// Some layouts ship loginctl under /bin; tolerate either.
		if out2, code2 := c.exec("sh", "-c", "command -v loginctl"); code2 == 0 {
			path := strings.TrimSpace(out2)
			c.exec("mv", path, path+".bak")
		} else {
			t.Fatalf("could not locate loginctl to break it: %s / %s", out, out2)
		}
	}

	out, _ := c.apply(argusRootlessButane("1000"))
	// The principal is created and recorded even though linger provisioning failed.
	if _, idCode := c.exec("id", "argus"); idCode != 0 {
		t.Fatalf("argus should be created before the linger failure:\n%s", out)
	}
	if c.exists("/var/lib/systemd/linger/argus") {
		t.Errorf("linger marker exists though loginctl was broken — test precondition wrong")
	}
	if userActive(c, "argus", 1000, "argusd.service") == "active" {
		t.Errorf("argusd active though linger never succeeded — should be staged")
	}

	// Restore loginctl and re-apply: linger is retried (adopted-then-provisioned),
	// argus is adopted (not recreated), and the workload resumes over the next
	// tick once the manager is up.
	restoreLoginctl(c)
	sig := c.statSig("/etc/passwd")
	out2, _ := c.apply(argusRootlessButane("1000"))
	if !c.exists("/var/lib/systemd/linger/argus") {
		t.Errorf("re-apply did not retry linger:\n%s", out2)
	}
	if after := c.statSig("/etc/passwd"); after != sig {
		t.Errorf("re-apply recreated argus (identity file changed) — resume should adopt")
	}
	if !waitUserManager(c, 1000, 90*time.Second) {
		t.Fatal("user@1000 never came up after linger was restored")
	}
	preloadUserImage(t, c, "argus", 1000, "docker.io/library/busybox")
	c.apply(argusRootlessButane("1000")) // activation tick
	if !waitUserActive(c, "argus", 1000, "argusd.service", 60*time.Second) {
		t.Errorf("workload did not resume to active after linger was restored")
	}
}

// --- rootless-specific harness helpers ---------------------------------------

// requireUserScope skips the test unless the container can actually run a user
// manager (real logind + user@<uid>). Uses a throwaway probe user so it never
// perturbs the argus fixture.
func requireUserScope(t *testing.T, c *container) {
	t.Helper()
	const pu, puid = "lprobe", "1234"
	c.exec("useradd", "-u", puid, "-m", pu)
	defer c.exec("userdel", "-r", pu)
	if _, code := c.exec("loginctl", "enable-linger", pu); code != 0 {
		t.Skip("loginctl enable-linger unavailable — run on a real-kernel host (magus KVM)")
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, code := c.exec("test", "-d", "/run/user/"+puid); code == 0 {
			s := strings.TrimSpace(userSystemctl(c, pu, 1234, "is-system-running"))
			if s == "running" || s == "degraded" {
				return
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Skip("user-scope logind unavailable (nested libkrun?) — run on a real-kernel host (magus KVM)")
}

// userSystemctl runs `systemctl --user <args>` as user over the settled transport.
func userSystemctl(c *container, user string, uid int, args ...string) string {
	full := append([]string{"runuser", "-u", user, "--", "env",
		fmt.Sprintf("XDG_RUNTIME_DIR=/run/user/%d", uid), "systemctl", "--user"}, args...)
	out, _ := c.exec(full...)
	return out
}

func userActive(c *container, user string, uid int, svc string) string {
	return strings.TrimSpace(userSystemctl(c, user, uid, "is-active", svc))
}

func waitUserActive(c *container, user string, uid int, svc string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if userActive(c, user, uid, svc) == "active" {
			return true
		}
		time.Sleep(3 * time.Second)
	}
	return false
}

// waitUserManager waits until user@<uid> is operational: /run/user/<uid> present
// and is-system-running in {running,degraded}. This is the readiness the honest-
// skip gates on, and the signal that the next reconcile tick will activate.
func waitUserManager(c *container, uid int, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if _, code := c.exec("test", "-d", fmt.Sprintf("/run/user/%d", uid)); code == 0 {
			s := strings.TrimSpace(userSystemctl(c, "argus", uid, "is-system-running"))
			if s == "running" || s == "degraded" {
				return true
			}
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

// preloadUserImage loads image into the user's rootless store from a tar exported
// on the host, so a Network=none workload runs without any registry pull — the
// nested rootless container has no egress DNS, and the proof is about magus's
// activation, not the container's networking.
func preloadUserImage(t *testing.T, c *container, user string, uid int, image string) {
	t.Helper()
	if _, code := podman("image", "exists", image); code != 0 {
		if out, code := podman("pull", image); code != 0 {
			t.Skipf("cannot pull %s to preload into %s's store: %s", image, user, out)
		}
	}
	tar, err := os.CreateTemp("", "preload-*.tar")
	if err != nil {
		t.Fatal(err)
	}
	tar.Close()
	defer os.Remove(tar.Name())
	if out, code := podman("save", "-o", tar.Name(), image); code != 0 {
		t.Fatalf("podman save %s: %s", image, out)
	}
	c.cp(tar.Name(), "/tmp/preload.tar")
	c.exec("chown", user+":"+user, "/tmp/preload.tar")
	if out, code := c.exec("runuser", "-u", user, "--", "env",
		fmt.Sprintf("XDG_RUNTIME_DIR=/run/user/%d", uid), "podman", "load", "-i", "/tmp/preload.tar"); code != 0 {
		t.Fatalf("load %s into %s store: %s", image, user, out)
	}
}

// hasSubidRange reports whether name has a line in both /etc/subuid and
// /etc/subgid.
func hasSubidRange(c *container, name string) bool {
	for _, f := range []string{"/etc/subuid", "/etc/subgid"} {
		out, code := c.exec("grep", "-q", "^"+name+":", f)
		if code != 0 {
			_ = out
			return false
		}
	}
	return true
}

func restoreLoginctl(c *container) {
	if _, code := c.exec("test", "-e", "/usr/bin/loginctl.bak"); code == 0 {
		c.exec("mv", "/usr/bin/loginctl.bak", "/usr/bin/loginctl")
		return
	}
	c.exec("sh", "-c", "for p in /bin/loginctl.bak /usr/sbin/loginctl.bak; do [ -e \"$p\" ] && mv \"$p\" \"${p%.bak}\"; done")
}
