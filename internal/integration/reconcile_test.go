//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lazypower/magus-cli/internal/policy"
)

// workloadPolicy is a byte-faithful copy of ../core-image/config/magus/policy.yaml
// — the REAL boundary magus runs under on a core-base host. Kept in sync
// deliberately (not simplified) so the harness proves the actual deployment
// boundary, including the secret/substrate denies. Quadlets + /etc/core files
// are the workload surface; unit *names* are unrestricted (unit_patterns: "*"),
// but standalone units and /etc/systemd/system are NOT in file_roots here, so
// the path gate — not the name pattern — is what keeps unit bodies out (see the
// note on TestDropIn). Tests that need standalone units use examplePolicy;
// unit_patterns gating itself is proven directly in internal/policy.
const workloadPolicy = `version: 1
file_roots:
  - /etc/containers/systemd
  - /etc/core
  - /var/lib/magus
unit_patterns:
  - "*"
deny:
  paths:
    - /etc/shadow
    - /etc/passwd
    - /etc/sudoers
    - /etc/sudoers.d/*
    - /etc/core/reconcile.env
    - /etc/core/labmap.env
  units:
    - "sshd.*"
    - "systemd-*"
    - "labmap-agent.*"
    - "core-reconcile.*"
    - "bootc-*"
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

func (c *container) plan(bu string) (string, int) {
	c.t.Helper()
	c.put("/host.bu", bu)
	return c.magus("plan", "--policy", "/policy.yaml", "/host.bu")
}

// statSig returns "inode:mtime" of a path — used to prove a "no write"
// operation (adoption) did not touch the file at all (a tmp+rename replaces the
// inode; any rewrite bumps mtime).
func (c *container) statSig(path string) string {
	c.t.Helper()
	out, code := c.exec("stat", "-c", "%i:%Y", path)
	if code != 0 {
		c.t.Fatalf("stat %s: %s", path, out)
	}
	return strings.TrimSpace(out)
}

// manifestOrigin parses the on-disk manifest and returns the recorded origin
// ("create"/"adopt"/"force-adopt") for a path, or "" if absent.
func (c *container) manifestOrigin(path string) string {
	c.t.Helper()
	raw := c.readFile("/var/lib/magus/manifest.json")
	var m struct {
		Resources map[string]struct {
			Origin string `json:"origin"`
		} `json:"resources"`
	}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		c.t.Fatalf("parse manifest: %v\n%s", err, raw)
	}
	return m.Resources[path].Origin
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

	// An UNOWNED neighbor inside the same file_root must survive deletion —
	// proves delete is manifest-bounded, not "prune everything undeclared".
	c.put("/etc/core/manual.conf", "hand-placed\n")

	// Delete-on-omission: drop the owned file from the IR (declare a different
	// one); magus owns hello.conf, so omission deletes it.
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
		t.Errorf("owned hello.conf should have been deleted on omission")
	}
	if !c.exists("/etc/core/other.conf") {
		t.Errorf("other.conf should have been created")
	}
	if !c.exists("/etc/core/manual.conf") {
		t.Errorf("UNOWNED manual.conf was deleted — deletion is not manifest-bounded")
	}
}

// TestConflictSkips proves an unowned file that differs from the IR is reported
// as a conflict, skipped (not overwritten), and yields exit 2.
func TestConflictSkips(t *testing.T) {
	c := setup(t, workloadPolicy)
	c.put("/etc/core/conf.env", "OLD=1\n")

	// Declare the conflicting file AND a clean neighbor: the conflict must skip
	// while the neighbor still converges (per-resource skip never halts apply).
	bu := butaneHeader + `storage:
  files:
    - path: /etc/core/conf.env
      contents:
        inline: |
          NEW=1
    - path: /etc/core/clean.conf
      contents:
        inline: |
          converged
`
	out, code := c.apply(bu)
	if code != 2 {
		t.Fatalf("conflict apply: exit %d (want 2)\n%s", code, out)
	}
	if !strings.Contains(out, "conflict") {
		t.Errorf("expected conflict in output:\n%s", out)
	}
	// Byte-exact: not overwritten, not appended, not partially written.
	if got := c.readFile("/etc/core/conf.env"); got != "OLD=1\n" {
		t.Errorf("conflict file mutated: %q, want exactly \"OLD=1\\n\"", got)
	}
	// The non-conflicting neighbor must have converged in the same apply.
	if got := c.readFile("/etc/core/clean.conf"); !strings.Contains(got, "converged") {
		t.Errorf("conflict halted apply — clean neighbor not converged: %q", got)
	}
}

// TestAdoption proves a pre-existing file whose content matches the IR exactly
// is adopted (no write) and thereafter owned (next apply is a no-op).
func TestAdoption(t *testing.T) {
	c := setup(t, workloadPolicy)
	c.put("/etc/core/match.env", "K=V\n")
	c.exec("chmod", "644", "/etc/core/match.env")
	sigBefore := c.statSig("/etc/core/match.env")

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
	// The per-resource line proves a real adopt, not the "0 adopts" footer.
	if !strings.Contains(out, "adopted, no write") {
		t.Errorf("expected an adopted-no-write outcome:\n%s", out)
	}
	// No-op for content: inode AND mtime unchanged (any write would move one).
	if after := c.statSig("/etc/core/match.env"); after != sigBefore {
		t.Errorf("adoption touched the file: stat %s -> %s (must be a no-op)", sigBefore, after)
	}
	// Ownership is recorded with origin=adopt, not create.
	if o := c.manifestOrigin("/etc/core/match.env"); o != "adopt" {
		t.Errorf("manifest origin = %q, want adopt", o)
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

	// Two Ignition-only sections magus must ignore (not reject): a disk layout
	// (storage.disks) and a user (passwd.users), alongside one magus file.
	bu := butaneHeader + `passwd:
  users:
    - name: alice
      groups:
        - wheel
storage:
  disks:
    - device: /dev/vdb
      wipe_table: false
      partitions:
        - label: data
          number: 1
          size_mib: 64
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
	// "Ignored" must mean no effect: magus is not Ignition, so it must NOT have
	// created the declared user.
	if _, idCode := c.exec("id", "alice"); idCode == 0 {
		t.Errorf("magus acted on passwd.users — user alice exists, but magus must ignore it")
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
	// The observation file records the unit's observed runtime state.
	if r := c.statusJSON(t); r.Units["magus-smoke.service"] != "active" {
		t.Errorf("status units[magus-smoke.service] = %q, want active (units=%+v)", r.Units["magus-smoke.service"], r.Units)
	}
}

// TestExistingUnitEnablementViaShow drives the path the standalone/adopt-unit
// tests miss: enablement reconciliation of an EXISTING unit, which reads live
// state through `systemctl show` (reconcileServiceState → sd.Show →
// enablementFromShow → EnablementOp) at both plan and apply time. A *new* unit
// takes the `enable --now` branch and never touches Show, so without this the
// show-based UnitFileState→Enablement mapping had zero real-systemd coverage.
//
// Both drift directions are exercised against identical-content (adopted, not
// created) units, so a broken enablement mapping fails to converge here.
func TestExistingUnitEnablementViaShow(t *testing.T) {
	c := setup(t, examplePolicy)

	// Bodies match what the butane below declares, so each unit is ADOPTED
	// (content-equal, unowned) rather than created — forcing the existing-unit
	// enablement path instead of enable --now.
	onBody := "[Unit]\nDescription=drift-on\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\n[Install]\nWantedBy=multi-user.target\n"
	offBody := "[Unit]\nDescription=drift-off\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\n[Install]\nWantedBy=multi-user.target\n"
	c.put("/etc/systemd/system/magus-drift-on.service", onBody)
	c.put("/etc/systemd/system/magus-drift-off.service", offBody)
	c.exec("systemctl", "daemon-reload")
	// Establish the drift: drift-off is enabled (IR will declare it disabled);
	// drift-on stays disabled (IR will declare it enabled).
	if out, code := c.exec("systemctl", "enable", "magus-drift-off.service"); code != 0 {
		t.Fatalf("precondition enable: %s", out)
	}
	if e := c.isEnabled("magus-drift-on.service"); e != "disabled" {
		t.Fatalf("precondition: drift-on is-enabled=%q, want disabled", e)
	}
	if e := c.isEnabled("magus-drift-off.service"); e != "enabled" {
		t.Fatalf("precondition: drift-off is-enabled=%q, want enabled", e)
	}

	bu := butaneHeader + `systemd:
  units:
    - name: magus-drift-on.service
      enabled: true
      contents: |
        [Unit]
        Description=drift-on
        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStart=/usr/bin/true
        [Install]
        WantedBy=multi-user.target
    - name: magus-drift-off.service
      enabled: false
      contents: |
        [Unit]
        Description=drift-off
        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStart=/usr/bin/true
        [Install]
        WantedBy=multi-user.target
`
	out, code := c.apply(bu)
	if code != 0 {
		t.Fatalf("apply: exit %d\n%s", code, out)
	}
	// These converge only if magus read each unit's current enablement
	// correctly via `systemctl show` (enablementFromShow) and EnablementOp
	// decided the right operation.
	if e := c.isEnabled("magus-drift-on.service"); e != "enabled" {
		t.Errorf("enable-drift not reconciled via systemctl show: is-enabled=%q, want enabled", e)
	}
	if e := c.isEnabled("magus-drift-off.service"); e != "disabled" {
		t.Errorf("disable-drift not reconciled via systemctl show: is-enabled=%q, want disabled", e)
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

	// Write correctness, independent of image egress: the source must be on
	// disk byte-for-byte as declared.
	if got := c.readFile("/etc/containers/systemd/hello.container"); !strings.Contains(got, "Image=quay.io/podman/hello:latest") {
		t.Fatalf("quadlet source not written as declared: %q\n%s", got, out)
	}
	// After magus' daemon-reload the generator must materialize hello.service.
	if _, ccode := c.exec("systemctl", "cat", "hello.service"); ccode != 0 {
		t.Fatalf("quadlet generator did not materialize hello.service (apply exit %d)\n%s", code, out)
	}

	// Attribute the exit code so a real regression can't hide behind the
	// egress-dependent container start:
	//   - exit 0 + active        → full success (image was pullable)
	//   - exit 1 + not-active     → expected when the nested container has no
	//     image egress; magus must have attributed the failure to hello
	//   - anything else           → a real regression
	active := c.isActive("hello.service")
	switch {
	case code == 0 && active == "active":
		// full success
	case code == 1 && active != "active":
		// The failure must be the generated service's start, surfaced as an
		// errored outcome for hello.service — not the path echoed in the plan.
		if !(strings.Contains(out, "hello.service") && strings.Contains(out, "errored")) {
			t.Errorf("exit 1 not attributed to hello.service start:\n%s", out)
		}
		t.Logf("quadlet start skipped (no image egress); generation verified, exit attributed to hello.service")
	default:
		t.Fatalf("unexpected quadlet state: apply exit %d, hello.service is-active=%s\n%s", code, active, out)
	}
}

// TestPlanAndStatus proves the read-only verbs against real state: plan reports
// pending changes (exit 2) before apply and a clean tree (exit 0) after, and
// status --json reflects the resource magus now manages.
func TestPlanAndStatus(t *testing.T) {
	c := setup(t, workloadPolicy)

	bu := butaneHeader + `storage:
  files:
    - path: /etc/core/planned.conf
      contents:
        inline: |
          planned
`
	// plan before apply: a create is pending → exit 2, with the [create] action
	// tag (not the "N creates" summary footer, which is present even at 0).
	pout, pcode := c.plan(bu)
	if pcode != 2 {
		t.Fatalf("plan (pending): exit %d (want 2)\n%s", pcode, pout)
	}
	if !strings.Contains(pout, "[create]") {
		t.Errorf("plan did not report the pending [create]:\n%s", pout)
	}

	if out, code := c.apply(bu); code != 0 {
		t.Fatalf("apply: exit %d\n%s", code, out)
	}

	// plan after apply: nothing pending → exit 0, no [create] tag.
	pout2, pcode2 := c.plan(bu)
	if pcode2 != 0 {
		t.Errorf("plan (clean): exit %d (want 0)\n%s", pcode2, pout2)
	}
	if strings.Contains(pout2, "[create]") {
		t.Errorf("clean plan still shows a [create]:\n%s", pout2)
	}

	// status --json must be valid JSON that reports the managed resource.
	sout, scode := c.magus("status", "--json")
	if scode != 0 {
		t.Fatalf("status: exit %d\n%s", scode, sout)
	}
	var report struct {
		ManagedResources int               `json:"managed_resources"`
		Files            map[string]string `json:"files"`
	}
	if err := json.Unmarshal([]byte(sout), &report); err != nil {
		t.Fatalf("status --json not valid JSON: %v\n%s", err, sout)
	}
	if report.ManagedResources < 1 {
		t.Errorf("status managed_resources = %d, want >= 1", report.ManagedResources)
	}
	if _, ok := report.Files["/etc/core/planned.conf"]; !ok {
		t.Errorf("status files does not include the managed file:\n%s", sout)
	}
}

// TestDropIn proves the drop-in path against real systemd: a 10-magus.conf
// drop-in is written to the unit's .d/ directory and survives daemon-reload.
//
// NOTE: this runs under examplePolicy, not the real workload policy. The
// workload policy's file_roots omit /etc/systemd/system, so a drop-in there is
// path-denied regardless of the (permissive) unit_patterns — on core-base the
// unit surface is quadlets, not drop-ins under /etc/systemd/system.
func TestDropIn(t *testing.T) {
	c := setup(t, examplePolicy)

	bu := butaneHeader + `systemd:
  units:
    - name: magus-base.service
      contents: |
        [Unit]
        Description=magus drop-in base
        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStart=/usr/bin/true
      dropins:
        - name: 10-magus.conf
          contents: |
            [Service]
            Environment=MAGUS_DROPIN=present
`
	out, code := c.apply(bu)
	if code != 0 {
		t.Fatalf("apply drop-in: exit %d\n%s", code, out)
	}
	dropinPath := "/etc/systemd/system/magus-base.service.d/10-magus.conf"
	if !c.exists(dropinPath) {
		t.Fatalf("drop-in not written at %s\n%s", dropinPath, out)
	}
	if got := c.readFile(dropinPath); !strings.Contains(got, "MAGUS_DROPIN=present") {
		t.Errorf("drop-in content wrong: %q", got)
	}
	// systemd must have merged the drop-in (proves precedence-named file is live).
	props, _ := c.exec("systemctl", "show", "magus-base.service", "-p", "Environment")
	if !strings.Contains(props, "MAGUS_DROPIN=present") {
		t.Errorf("systemd did not merge the drop-in: %q", props)
	}
}

// TestDenyEnforcement proves the policy deny list is enforced: an IR declaring a
// path the real workload policy denies (the fleet credential) is rejected at
// validate, applies nothing, and never writes the file.
func TestDenyEnforcement(t *testing.T) {
	c := setup(t, workloadPolicy)

	// One denied path + one perfectly-allowed neighbor. A denied IR path is
	// input-bad: it must HALT the whole apply (nothing written), not skip the
	// denied path while converging the rest.
	bu := butaneHeader + `storage:
  files:
    - path: /etc/core/reconcile.env
      contents:
        inline: |
          STOLEN=1
    - path: /etc/core/allowed.conf
      contents:
        inline: |
          should-not-exist-yet
`
	c.put("/host.bu", bu)
	vout, vcode := c.magus("validate", "--policy", "/policy.yaml", "/host.bu")
	if vcode == 0 {
		t.Fatalf("validate accepted a denied path:\n%s", vout)
	}
	if !strings.Contains(vout, "reconcile.env") {
		t.Errorf("validate error did not name the denied path:\n%s", vout)
	}
	// apply must refuse (input-bad halts) and write NEITHER file.
	aout, acode := c.apply(bu)
	if acode == 0 {
		t.Fatalf("apply proceeded on a denied path:\n%s", aout)
	}
	if c.exists("/etc/core/reconcile.env") {
		t.Errorf("denied file was written despite policy deny")
	}
	if c.exists("/etc/core/allowed.conf") {
		t.Errorf("allowed neighbor was written — deny was treated as per-resource skip, not a halt")
	}
}

// statusJSON parses `magus status --json` from inside the container.
func (c *container) statusJSON(t *testing.T) struct {
	LastApply *string           `json:"last_apply"`
	Result    string            `json:"result"`
	Managed   int               `json:"managed_resources"`
	Units     map[string]string `json:"units"`
	Files     map[string]string `json:"files"`
	Conflicts []struct {
		Path      string `json:"path"`
		FirstSeen string `json:"first_seen"`
	} `json:"conflicts"`
	Errors []struct {
		Path string `json:"path"`
	} `json:"errors"`
} {
	t.Helper()
	var report struct {
		LastApply *string           `json:"last_apply"`
		Result    string            `json:"result"`
		Managed   int               `json:"managed_resources"`
		Units     map[string]string `json:"units"`
		Files     map[string]string `json:"files"`
		Conflicts []struct {
			Path      string `json:"path"`
			FirstSeen string `json:"first_seen"`
		} `json:"conflicts"`
		Errors []struct {
			Path string `json:"path"`
		} `json:"errors"`
	}
	out, code := c.magus("status", "--json")
	if code != 0 {
		t.Fatalf("status --json: exit %d\n%s", code, out)
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("status --json invalid: %v\n%s", err, out)
	}
	return report
}

// TestStatusObservation proves the Phase-4 observation file end-to-end: after an
// apply, `magus status --json` reports last_apply, the managed file, the
// conflict, and result=ok-with-skips — and a recurring conflict's first_seen is
// carried forward across applies (not reset).
func TestStatusObservation(t *testing.T) {
	c := setup(t, workloadPolicy)
	c.put("/etc/core/conf.env", "OLD=1\n") // unowned → conflict

	bu := butaneHeader + `storage:
  files:
    - path: /etc/core/app.conf
      contents:
        inline: |
          hello
    - path: /etc/core/conf.env
      contents:
        inline: |
          NEW=1
`
	if out, code := c.apply(bu); code != 2 {
		t.Fatalf("apply: exit %d (want 2)\n%s", code, out)
	}

	r := c.statusJSON(t)
	if r.LastApply == nil || *r.LastApply == "" {
		t.Errorf("status missing last_apply")
	}
	if r.Result != "ok-with-skips" {
		t.Errorf("result = %q, want ok-with-skips", r.Result)
	}
	if _, ok := r.Files["/etc/core/app.conf"]; !ok {
		t.Errorf("managed file not in status files: %+v", r.Files)
	}
	var firstSeen string
	for _, cf := range r.Conflicts {
		if cf.Path == "/etc/core/conf.env" {
			firstSeen = cf.FirstSeen
		}
	}
	if firstSeen == "" {
		t.Fatalf("conflict /etc/core/conf.env not reported with first_seen: %+v", r.Conflicts)
	}

	// Re-apply: the conflict persists; its first_seen must be carried forward.
	if _, code := c.apply(bu); code != 2 {
		t.Fatalf("second apply exit %d", code)
	}
	r2 := c.statusJSON(t)
	var firstSeen2 string
	for _, cf := range r2.Conflicts {
		if cf.Path == "/etc/core/conf.env" {
			firstSeen2 = cf.FirstSeen
		}
	}
	if firstSeen2 != firstSeen {
		t.Errorf("first_seen not carried forward: %q → %q", firstSeen, firstSeen2)
	}
}

// TestAdoptUnit proves `magus adopt` works on a unit (the spec's example
// adopts a .service), not just files — the generalized findDeclared path.
func TestAdoptUnit(t *testing.T) {
	c := setup(t, examplePolicy)
	unit := "/etc/systemd/system/magus-adopt.service"
	c.put(unit, "[Service]\nExecStart=/usr/bin/old\n")

	bu := butaneHeader + `systemd:
  units:
    - name: magus-adopt.service
      contents: |
        [Service]
        ExecStart=/usr/bin/new
`
	c.put("/host.bu", bu)
	out, code := c.magus("adopt", "--yes", "--policy", "/policy.yaml", "/host.bu", unit)
	if code != 0 {
		t.Fatalf("adopt unit: exit %d\n%s", code, out)
	}
	if got := c.readFile(unit); !strings.Contains(got, "ExecStart=/usr/bin/new") {
		t.Errorf("unit not overwritten with IR content: %q", got)
	}
	// Recorded under force-adopt ownership (kind unit).
	if o := c.manifestOrigin(unit); o != "force-adopt" {
		t.Errorf("manifest origin = %q, want force-adopt", o)
	}
}

// TestPlanExplain proves the Phase-3 --explain contract end-to-end: a conflict
// (unowned) row shows hashes only by default — the unowned file's content is
// never written to output — and -v reveals the unified diff.
func TestPlanExplain(t *testing.T) {
	c := setup(t, workloadPolicy)
	c.put("/etc/core/conf.env", "SECRET_OLD=1\n")
	bu := butaneHeader + `storage:
  files:
    - path: /etc/core/conf.env
      contents:
        inline: |
          SECRET_NEW=1
`
	c.put("/host.bu", bu)

	// Default: hashes only, no leaked content.
	out, code := c.magus("plan", "--explain", "--policy", "/policy.yaml", "/host.bu")
	if code != 2 {
		t.Fatalf("plan --explain: exit %d (want 2)\n%s", code, out)
	}
	if !strings.Contains(out, "hashes only") || !strings.Contains(out, "sha256:") {
		t.Errorf("conflict not rendered hashes-only:\n%s", out)
	}
	if strings.Contains(out, "SECRET_OLD") || strings.Contains(out, "SECRET_NEW") {
		t.Errorf("--explain leaked unowned conflict content without -v:\n%s", out)
	}

	// -v reveals the diff.
	vout, _ := c.magus("plan", "--explain", "-v", "--policy", "/policy.yaml", "/host.bu")
	if !strings.Contains(vout, "-SECRET_OLD=1") || !strings.Contains(vout, "+SECRET_NEW=1") {
		t.Errorf("-v did not reveal the conflict diff:\n%s", vout)
	}
}

// TestQuadletDeniedGeneratedService proves the Phase-2 quadlet policy gate: a
// quadlet whose GENERATED service matches a deny.units rule
// (core-reconcile.container → core-reconcile.service) is rejected at validate
// and apply, and the source is never written — even though its path is inside
// file_roots.
func TestQuadletDeniedGeneratedService(t *testing.T) {
	c := setup(t, workloadPolicy)

	bu := butaneHeader + `storage:
  files:
    - path: /etc/containers/systemd/core-reconcile.container
      contents:
        inline: |
          [Container]
          Image=quay.io/podman/hello:latest
`
	c.put("/host.bu", bu)
	vout, vcode := c.magus("validate", "--policy", "/policy.yaml", "/host.bu")
	if vcode == 0 {
		t.Fatalf("validate accepted a quadlet generating a denied service:\n%s", vout)
	}
	if !strings.Contains(vout, "generated service denied") {
		t.Errorf("validate error did not cite the denied generated service:\n%s", vout)
	}
	aout, acode := c.apply(bu)
	if acode == 0 {
		t.Fatalf("apply proceeded on a denied quadlet:\n%s", aout)
	}
	if c.exists("/etc/containers/systemd/core-reconcile.container") {
		t.Errorf("denied quadlet source was written")
	}
}

// TestSymlinkEscapeBlocked proves symlink-resolved containment: a path that is
// lexically inside file_roots but whose parent is a symlink pointing OUT (here
// /etc/core/evil -> /etc) is downgraded to a conflict and skipped, so magus
// never writes through the symlink to /etc.
func TestSymlinkEscapeBlocked(t *testing.T) {
	c := setup(t, workloadPolicy)
	c.exec("mkdir", "-p", "/etc/core")
	// /etc/core/evil -> /etc (an allowed-root child that redirects outside).
	if out, code := c.exec("ln", "-sfn", "/etc", "/etc/core/evil"); code != 0 {
		t.Fatalf("create symlink: %s", out)
	}

	bu := butaneHeader + `storage:
  files:
    - path: /etc/core/evil/magus-escape-probe
      contents:
        inline: |
          escaped
`
	out, code := c.apply(bu)
	if code != 2 {
		t.Fatalf("symlink-escape apply: exit %d (want 2 conflict)\n%s", code, out)
	}
	if !strings.Contains(out, "conflict") && !strings.Contains(out, "resolves outside") {
		t.Errorf("escape not reported as a containment conflict:\n%s", out)
	}
	// The write must NOT have landed at the symlink target (/etc/magus-escape-probe).
	if c.exists("/etc/magus-escape-probe") {
		t.Errorf("write escaped through the symlink to /etc")
	}
}

// TestOrphanOnNewDeny proves manifest↔policy contention: a path magus owns,
// once the policy denies it (and it leaves the IR), is ORPHANED — left on disk,
// excluded from reconciliation — not deleted by the sweep. Orphan is sticky.
func TestOrphanOnNewDeny(t *testing.T) {
	c := setup(t, workloadPolicy)

	// 1. Create + own the file under the permissive workload policy.
	bu1 := butaneHeader + `storage:
  files:
    - path: /etc/core/svc.env
      contents:
        inline: |
          OWNED=1
`
	if out, code := c.apply(bu1); code != 0 {
		t.Fatalf("initial apply: exit %d\n%s", code, out)
	}

	// 2. New policy denies the now-owned path; drop it from the IR. Without
	//    orphaning, the sweep would DELETE it; with orphaning, it's kept.
	denyPolicy := strings.Replace(workloadPolicy,
		"    - /etc/core/labmap.env",
		"    - /etc/core/labmap.env\n    - /etc/core/svc.env", 1)
	c.put("/policy.yaml", denyPolicy)
	bu2 := butaneHeader + `storage:
  files:
    - path: /etc/core/keep.conf
      contents:
        inline: keep
`
	out, code := c.apply(bu2)
	if code != 2 {
		t.Fatalf("orphan apply: exit %d (want 2)\n%s", code, out)
	}
	if !c.exists("/etc/core/svc.env") {
		t.Fatalf("owned-then-denied file was DELETED; it must be orphaned and kept")
	}
	if o := c.manifestOrigin("/etc/core/svc.env"); o == "" {
		t.Errorf("manifest entry dropped; orphan must retain the entry for audit")
	}
	// status must list it in the orphaned array (parsed, not substring-matched).
	sout, _ := c.magus("status", "--json")
	var report struct {
		Orphaned []struct {
			Path string `json:"path"`
		} `json:"orphaned"`
	}
	if err := json.Unmarshal([]byte(sout), &report); err != nil {
		t.Fatalf("status --json invalid: %v\n%s", err, sout)
	}
	found := false
	for _, o := range report.Orphaned {
		if o.Path == "/etc/core/svc.env" {
			found = true
		}
	}
	if !found {
		t.Errorf("status orphaned[] does not include the path:\n%s", sout)
	}
}

// TestWorkloadPolicyMatchesCoreImage guards against drift: the embedded
// workloadPolicy must parse to the SAME boundary (roots, unit patterns, denies)
// as the live core-image policy, so the harness keeps proving the REAL
// deployment boundary. Compares parsed semantics (via the real loader) rather
// than bytes, so comment/whitespace churn in core-image is ignored but a changed
// root/deny is caught. Skips when the core-image repo isn't checked out
// alongside (e.g. in CI), so it never blocks the gate. No container needed.
func TestWorkloadPolicyMatchesCoreImage(t *testing.T) {
	path := os.Getenv("CORE_IMAGE_POLICY")
	if path == "" {
		path = "../../../core-image/config/magus/policy.yaml"
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("core-image policy not available (%v); cannot check drift", err)
	}
	live, err := policy.Load(path)
	if err != nil {
		t.Fatalf("load live core-image policy: %v", err)
	}

	tmp, err := os.CreateTemp(t.TempDir(), "workload-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.WriteString(workloadPolicy); err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	embedded, err := policy.Load(tmp.Name())
	if err != nil {
		t.Fatalf("load embedded workloadPolicy: %v", err)
	}

	if !reflect.DeepEqual(live, embedded) {
		t.Errorf("embedded workloadPolicy has drifted from the real core-image boundary\nlive:     %+v\nembedded: %+v", live, embedded)
	}
}

// waitActive polls is-active until the unit is "active" or the timeout elapses.
func (c *container) waitActive(unit string, timeout time.Duration) bool {
	c.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if c.isActive(unit) == "active" {
			return true
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

// journal returns diagnostics for a unit on failure: status + journal + the
// container runtime view (journald may not persist in the test container).
func (c *container) journal(unit string) string {
	st, _ := c.exec("systemctl", "status", unit, "--no-pager", "-l")
	jr, _ := c.exec("journalctl", "-xeu", unit, "--no-pager", "-n", "50")
	ps, _ := c.exec("podman", "ps", "-a")
	return "## systemctl status\n" + st + "\n## journalctl\n" + jr + "\n## podman ps -a\n" + ps
}

// TestQuadletRuntime proves the REAL quadlet workload path the generation-only
// test can't: a .container quadlet is applied, the generated service actually
// pulls its image and the container RUNS (service active); a content change
// restarts it; and removing it from the IR stops the container and unlinks the
// source. This is the core core-base use case and the biggest pre-metal unknown.
//
// Needs image egress from the nested container (busybox). The generated service
// name for probe.container is probe.service.
func TestQuadletRuntime(t *testing.T) {
	// Quadlet RUNTIME (a container actually pulling + running) needs a real
	// bootc host: it's microVM → core-base container → workload container in CI,
	// and double-nested podman can't run a container reliably (confirmed failing
	// both under local emulation and on the Firecracker buildah runner). On a
	// real host it's a single nest (host → container) and works. Gate it so the
	// nested CI suite skips it; the substrate test sets MAGUS_IT_RUNTIME=1.
	// The magus logic it guards (start-not-enable) is also covered by the
	// hermetic apply unit tests.
	if os.Getenv("MAGUS_IT_RUNTIME") == "" {
		t.Skip("quadlet runtime needs a real bootc host; set MAGUS_IT_RUNTIME=1 (substrate test)")
	}
	c := setup(t, workloadPolicy)

	bu := func(sleep string) string {
		return butaneHeader + `storage:
  files:
    - path: /etc/containers/systemd/probe.container
      contents:
        inline: |
          [Container]
          Image=docker.io/library/busybox
          Exec=sleep ` + sleep + `
          [Install]
          WantedBy=multi-user.target
`
	}

	// Create → the container must actually run (service active).
	out, code := c.apply(bu("3600"))
	if !c.waitActive("probe.service", 90*time.Second) {
		t.Fatalf("quadlet container did not reach active (apply exit %d)\n%s\n--- journal ---\n%s",
			code, out, c.journal("probe.service"))
	}

	// Content change → magus restarts the running generated service.
	out2, code2 := c.apply(bu("7200"))
	if code2 != 0 {
		t.Fatalf("quadlet update apply: exit %d\n%s", code2, out2)
	}
	if !c.waitActive("probe.service", 60*time.Second) {
		t.Errorf("quadlet service not active after content-change restart\n%s", c.journal("probe.service"))
	}

	// Remove from IR → magus stops the container and unlinks the source.
	bu3 := butaneHeader + `storage:
  files:
    - path: /etc/core/keep.conf
      contents:
        inline: keep
`
	if out3, code3 := c.apply(bu3); code3 != 0 {
		t.Fatalf("quadlet delete apply: exit %d\n%s", code3, out3)
	}
	if c.exists("/etc/containers/systemd/probe.container") {
		t.Errorf("quadlet source not unlinked on omission")
	}
	if s := c.isActive("probe.service"); s == "active" {
		t.Errorf("quadlet container still running after removal: is-active=%s", s)
	}
}
