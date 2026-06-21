//go:build integration

package integration

import (
	"strings"
	"testing"
)

// workloadPolicy mirrors ../core-image/config/magus/policy.yaml — the REAL
// boundary magus runs under on a core-base host. Quadlets + /etc/core files are
// the workload surface; standalone units and /etc/systemd/system are NOT in
// file_roots here (that is deliberate on core-base). Tests that need standalone
// units use examplePolicy instead.
const workloadPolicy = `version: 1
file_roots:
  - /etc/containers/systemd
  - /etc/core
  - /var/lib/magus
unit_patterns:
  - "*.d/10-magus.conf"
deny:
  paths:
    - /etc/shadow
    - /etc/passwd
    - /etc/sudoers
    - /etc/sudoers.d/*
  units:
    - "sshd.*"
    - "systemd-*"
`

// examplePolicy mirrors policy.example.yaml — broader file_roots + magus-*
// unit_patterns, used to exercise the standalone-unit engine path that the
// tighter workload policy intentionally forbids.
const examplePolicy = `version: 1
file_roots:
  - /etc/magus.d
  - /etc/systemd/system
  - /etc/containers/systemd
  - /var/lib/magus
  - /var/data
unit_patterns:
  - "magus-*"
  - "*.d/10-magus.conf"
deny:
  paths:
    - /etc/shadow
    - /etc/passwd
  units:
    - "sshd.*"
    - "systemd-*"
`

const butaneHeader = "variant: fcos\nversion: 1.5.0\n"

// setup writes the policy and ensures the manifest dir exists, returning a
// ready container.
func setup(t *testing.T, policy string) *container {
	c := newContainer(t)
	c.put("/policy.yaml", policy)
	c.exec("mkdir", "-p", "/var/lib/magus")
	return c
}

func (c *container) apply(bu string) (string, int) {
	c.t.Helper()
	c.put("/host.bu", bu)
	return c.magus("apply", "--yes", "--policy", "/policy.yaml", "/host.bu")
}

// TestFileLifecycle proves create → idempotent no-op → delete-on-omission for a
// plain file under the real workload policy.
func TestFileLifecycle(t *testing.T) {
	c := setup(t, workloadPolicy)

	bu := butaneHeader + `storage:
  files:
    - path: /etc/core/hello.conf
      mode: 0644
      contents:
        inline: |
          hello world
`
	out, code := c.apply(bu)
	if code != 0 {
		t.Fatalf("apply create: exit %d\n%s", code, out)
	}
	if got := c.readFile("/etc/core/hello.conf"); !strings.Contains(got, "hello world") {
		t.Fatalf("content = %q, want hello world", got)
	}
	if m := c.mode("/etc/core/hello.conf"); m != "644" {
		t.Errorf("mode = %s, want 644", m)
	}

	// Idempotence: a second apply with no input change is a clean no-op.
	out2, code2 := c.apply(bu)
	if code2 != 0 {
		t.Fatalf("apply idempotent: exit %d\n%s", code2, out2)
	}
	if !strings.Contains(out2, "Nothing to apply") {
		t.Errorf("second apply not a no-op:\n%s", out2)
	}

	// Delete-on-omission: drop the file from the IR (declare a different one);
	// magus owns it, so omission deletes it.
	bu2 := butaneHeader + `storage:
  files:
    - path: /etc/core/other.conf
      contents:
        inline: kept
`
	out3, code3 := c.apply(bu2)
	if code3 != 0 {
		t.Fatalf("apply delete: exit %d\n%s", code3, out3)
	}
	if c.exists("/etc/core/hello.conf") {
		t.Errorf("hello.conf should have been deleted on omission")
	}
	if !c.exists("/etc/core/other.conf") {
		t.Errorf("other.conf should have been created")
	}
}

// TestConflictSkips proves an unowned file that differs from the IR is reported
// as a conflict, skipped (not overwritten), and yields exit 2.
func TestConflictSkips(t *testing.T) {
	c := setup(t, workloadPolicy)
	c.put("/etc/core/conf.env", "OLD=1\n")

	bu := butaneHeader + `storage:
  files:
    - path: /etc/core/conf.env
      contents:
        inline: |
          NEW=1
`
	out, code := c.apply(bu)
	if code != 2 {
		t.Fatalf("conflict apply: exit %d (want 2)\n%s", code, out)
	}
	if !strings.Contains(out, "conflict") {
		t.Errorf("expected conflict in output:\n%s", out)
	}
	if got := c.readFile("/etc/core/conf.env"); !strings.Contains(got, "OLD=1") {
		t.Errorf("conflict file was overwritten: %q", got)
	}
}

// TestAdoption proves a pre-existing file whose content matches the IR exactly
// is adopted (no write) and thereafter owned (next apply is a no-op).
func TestAdoption(t *testing.T) {
	c := setup(t, workloadPolicy)
	c.put("/etc/core/match.env", "K=V\n")
	c.exec("chmod", "644", "/etc/core/match.env")

	bu := butaneHeader + `storage:
  files:
    - path: /etc/core/match.env
      mode: 0644
      contents:
        inline: |
          K=V
`
	out, code := c.apply(bu)
	if code != 0 {
		t.Fatalf("adopt apply: exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "adopt") {
		t.Errorf("expected adopt in output:\n%s", out)
	}
	out2, code2 := c.apply(bu)
	if code2 != 0 || !strings.Contains(out2, "Nothing to apply") {
		t.Errorf("post-adopt apply not a no-op: exit %d\n%s", code2, out2)
	}
}

// TestIgnitionOnlyIgnored proves the two-consumer promise: a Butane file
// carrying Ignition-only sections (passwd.users) validates and applies cleanly,
// ignoring them rather than erroring (Codex #12).
func TestIgnitionOnlyIgnored(t *testing.T) {
	c := setup(t, workloadPolicy)

	bu := butaneHeader + `passwd:
  users:
    - name: alice
      groups:
        - wheel
storage:
  files:
    - path: /etc/core/ok.conf
      contents:
        inline: ok
`
	c.put("/host.bu", bu)
	vout, vcode := c.magus("validate", "--policy", "/policy.yaml", "/host.bu")
	if vcode != 0 {
		t.Fatalf("validate rejected ignition-only sections: exit %d\n%s", vcode, vout)
	}
	out, code := c.apply(bu)
	if code != 0 {
		t.Fatalf("apply: exit %d\n%s", code, out)
	}
	if !c.exists("/etc/core/ok.conf") {
		t.Errorf("magus file not created alongside ignored sections")
	}
}

// TestDirectory proves directories are created with the declared mode and are
// NOT deleted on IR omission (the documented v1 asymmetry).
func TestDirectory(t *testing.T) {
	c := setup(t, workloadPolicy)

	bu := butaneHeader + `storage:
  directories:
    - path: /etc/core/data
      mode: 0750
`
	out, code := c.apply(bu)
	if code != 0 {
		t.Fatalf("apply dir: exit %d\n%s", code, out)
	}
	if m := c.mode("/etc/core/data"); m != "750" {
		t.Errorf("dir mode = %s, want 750", m)
	}

	// Omit the directory; v1 never deletes directories.
	bu2 := butaneHeader + `storage:
  files:
    - path: /etc/core/keep.conf
      contents:
        inline: keep
`
	if _, code := c.apply(bu2); code != 0 {
		t.Fatalf("apply omit-dir: exit %d", code)
	}
	if !c.exists("/etc/core/data") {
		t.Errorf("directory was deleted on omission; v1 must keep it")
	}
}

// TestStandaloneUnit proves the full unit path against real systemd: write a
// unit body, daemon-reload, enable --now, and observe it active. Uses the
// example policy since the workload policy forbids standalone units.
func TestStandaloneUnit(t *testing.T) {
	c := setup(t, examplePolicy)

	bu := butaneHeader + `systemd:
  units:
    - name: magus-smoke.service
      enabled: true
      contents: |
        [Unit]
        Description=magus integration smoke
        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStart=/usr/bin/true
        [Install]
        WantedBy=multi-user.target
`
	out, code := c.apply(bu)
	if code != 0 {
		t.Fatalf("apply unit: exit %d\n%s", code, out)
	}
	if e := c.isEnabled("magus-smoke.service"); e != "enabled" {
		t.Errorf("is-enabled = %q, want enabled", e)
	}
	if a := c.isActive("magus-smoke.service"); a != "active" {
		t.Errorf("is-active = %q, want active", a)
	}
}

// TestQuadlet proves quadlet generation: a .container source under the workload
// root is written and the quadlet generator materializes its .service at
// daemon-reload. The container runtime start depends on image egress, so this
// asserts generation (reliable) and logs the activation result.
func TestQuadlet(t *testing.T) {
	c := setup(t, workloadPolicy)

	bu := butaneHeader + `storage:
  files:
    - path: /etc/containers/systemd/hello.container
      contents:
        inline: |
          [Unit]
          Description=hello quadlet
          [Container]
          Image=quay.io/podman/hello:latest
          [Install]
          WantedBy=multi-user.target
`
	out, code := c.apply(bu)
	if !c.exists("/etc/containers/systemd/hello.container") {
		t.Fatalf("quadlet source not written\n%s", out)
	}
	// After magus' daemon-reload the generator must know hello.service.
	if _, ccode := c.exec("systemctl", "cat", "hello.service"); ccode != 0 {
		t.Errorf("quadlet generator did not materialize hello.service (apply exit %d)\n%s", code, out)
	}
	t.Logf("quadlet apply exit %d; hello.service is-active=%s", code, c.isActive("hello.service"))
}
