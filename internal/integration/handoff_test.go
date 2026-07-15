//go:build integration

package integration

import (
	"strings"
	"testing"

	butane "github.com/coreos/butane/config"
	"github.com/coreos/butane/config/common"
)

// ignitionApplyPath is where an FCOS image exposes the ignition binary's
// apply entrypoint (a symlink to the ignition binary). Present since Ignition
// 2.14; core-base inherits it from FCOS.
const ignitionApplyPath = "/usr/libexec/ignition-apply"

// renderIgnition translates Butane to an Ignition config using the SAME library
// call magus renders through internally (ir.LoadButane → butane.TranslateBytes).
//
// This deliberately does NOT go through magus: it simulates the *sibling*
// consumer in the two-consumer model. At first boot Ignition paves exactly this
// config; magus never sees the .ign, only the paved-on-disk result — so the
// test renders the way the platform does, then hands the disk to magus, exactly
// as production does.
func renderIgnition(t *testing.T, bu string) string {
	t.Helper()
	ign, rpt, err := butane.TranslateBytes([]byte(bu), common.TranslateBytesOptions{})
	if err != nil {
		t.Fatalf("render butane→ignition: %v\nreport: %s", err, rpt.String())
	}
	return string(ign)
}

// ignitionApply paves a Butane fixture into the container's real root exactly as
// first boot does: render it to an Ignition config, then run the image's own
// ignition-apply over it. Skips the whole test (visible reason) when the image
// lacks ignition-apply, per A1's guard.
//
//   - --ignore-unsupported: this runs in a booted container, not the initramfs,
//     so sections that only make sense pre-pivot (disks/filesystems) are skipped
//     rather than fatal — the file/unit stages still run.
//   - --offline: fixtures are inline (data: URLs); refuse any remote fetch so the
//     handoff is hermetic and can't silently depend on the network.
func (c *container) ignitionApply(bu string) {
	c.t.Helper()
	if _, code := c.exec("test", "-x", ignitionApplyPath); code != 0 {
		c.t.Skipf("%s absent — image lacks ignition-apply (need Ignition ≥ 2.14)", ignitionApplyPath)
	}
	c.put("/handoff.ign", renderIgnition(c.t, bu))
	if out, code := c.exec(ignitionApplyPath, "--ignore-unsupported", "--offline", "--root", "/", "/handoff.ign"); code != 0 {
		c.t.Fatalf("ignition-apply: exit %d\n%s", code, out)
	}
}

// TestIgnitionApplyHandoff proves the two-consumer handoff invariant: Ignition
// paves the declared state at first boot, and magus's first apply ADOPTS all of
// it — claims ownership without writing a byte — then converges idempotently.
//
// The paved unit deliberately carries cosmetic noise Ignition writes verbatim
// (a comment, a blank line, spaced "key = value") while magus's desired unit is
// in clean canonical form. Adoption must clear the canonicalization bar, not a
// byte-compare — that is what makes the handoff hold on a real host.
func TestIgnitionApplyHandoff(t *testing.T) {
	c := setup(t, examplePolicy)

	// day1 — what Ignition paves at first boot (noisy unit body).
	day1 := butaneHeader + `storage:
  files:
    - path: /etc/magus.d/app.conf
      mode: 0644
      contents:
        inline: |
          MODE=production
          WORKERS=4
systemd:
  units:
    - name: magus-handoff.service
      contents: |
        # paved by Ignition, written verbatim
        [Unit]
        Description = handoff probe

        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStart = /usr/bin/true
        [Install]
        WantedBy=multi-user.target
`
	c.ignitionApply(day1)

	// Pre-condition (not the assertion under test): Ignition actually paved.
	filePath := "/etc/magus.d/app.conf"
	unitPath := "/etc/systemd/system/magus-handoff.service"
	if !c.exists(filePath) || !c.exists(unitPath) {
		t.Fatalf("ignition-apply did not pave the declared resources (file=%v unit=%v)",
			c.exists(filePath), c.exists(unitPath))
	}
	fileSig := c.statSig(filePath)
	unitSig := c.statSig(unitPath)

	// day2 — magus's desired state: same resources, unit in clean canonical form.
	day2 := butaneHeader + `storage:
  files:
    - path: /etc/magus.d/app.conf
      mode: 0644
      contents:
        inline: |
          MODE=production
          WORKERS=4
systemd:
  units:
    - name: magus-handoff.service
      contents: |
        [Unit]
        Description=handoff probe
        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStart=/usr/bin/true
        [Install]
        WantedBy=multi-user.target
`
	out, code := c.apply(day2)
	if code != 0 {
		t.Fatalf("handoff apply: exit %d (want 0 — every resource should adopt)\n%s", code, out)
	}

	// Every declared resource must ADOPT (claim ownership, no write). A byte
	// compare on the noisy-vs-clean unit would miss here — the per-resource
	// "adopted, no write" line is the honest proof, not the summary footer.
	for _, p := range []string{filePath, unitPath} {
		if !strings.Contains(out, p) {
			t.Errorf("resource %s not named in apply output:\n%s", p, out)
		}
	}
	if n := strings.Count(out, "(adopted, no write)"); n != 2 {
		t.Errorf("expected 2 adopted-no-write rows, got %d:\n%s", n, out)
	}

	// Zero filesystem writes: adoption must not touch inode or mtime of either
	// resource — a tmp+rename bumps the inode, any rewrite bumps mtime.
	if s := c.statSig(filePath); s != fileSig {
		t.Errorf("adoption wrote to the file: %s → %s (must be a no-op)", fileSig, s)
	}
	if s := c.statSig(unitPath); s != unitSig {
		t.Errorf("adoption wrote to the canonically-equal unit: %s → %s (must be a no-op)", unitSig, s)
	}

	// Ownership recorded as adopt, not create — the manifest reflects the handoff.
	if o := c.manifestOrigin(filePath); o != "adopt" {
		t.Errorf("file manifest origin = %q, want adopt", o)
	}
	if o := c.manifestOrigin(unitPath); o != "adopt" {
		t.Errorf("unit manifest origin = %q, want adopt", o)
	}

	// Idempotent: a second apply with no input change is a clean no-op — every
	// now-owned resource skips.
	out2, code2 := c.apply(day2)
	if code2 != 0 || !strings.Contains(out2, "Nothing to apply") {
		t.Errorf("post-handoff apply not a no-op: exit %d\n%s", code2, out2)
	}
}

// TestIgnitionApplyCanonicalizationGuard is the negative half of the handoff
// canonicalization boundary: it proves adoption is NOT a blanket "units always
// match". Ignition paves a unit running /usr/bin/true; magus desires a
// behavior-different unit running /usr/bin/false. Canonicalization drops
// comments and whitespace, but ExecStart is behavior-significant — so this must
// NOT adopt. The unit is unowned and genuinely differs → conflict → exit 2, and
// magus must leave the paved unit byte-for-byte intact.
func TestIgnitionApplyCanonicalizationGuard(t *testing.T) {
	c := setup(t, examplePolicy)

	day1 := butaneHeader + `systemd:
  units:
    - name: magus-guard.service
      contents: |
        [Unit]
        Description=guard
        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStart=/usr/bin/true
        [Install]
        WantedBy=multi-user.target
`
	c.ignitionApply(day1)
	unitPath := "/etc/systemd/system/magus-guard.service"
	sig := c.statSig(unitPath)

	// Same unit shape, behavior-significant difference: ExecStart=/usr/bin/false.
	day2 := butaneHeader + `systemd:
  units:
    - name: magus-guard.service
      contents: |
        [Unit]
        Description=guard
        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStart=/usr/bin/false
        [Install]
        WantedBy=multi-user.target
`
	out, code := c.apply(day2)
	if code != 2 {
		t.Fatalf("behavior-different unit: exit %d (want 2 conflict — must NOT adopt)\n%s", code, out)
	}
	if !strings.Contains(out, "conflict") {
		t.Errorf("differing unit not reported as a conflict:\n%s", out)
	}
	if strings.Contains(out, "adopted, no write") {
		t.Errorf("canonicalization over-matched: a behavior-different unit was adopted:\n%s", out)
	}
	// The unowned, differing unit must be left exactly as Ignition paved it.
	if s := c.statSig(unitPath); s != sig {
		t.Errorf("conflict path mutated: %s → %s (must be left as paved)", sig, s)
	}
	if got := c.readFile(unitPath); !strings.Contains(got, "ExecStart=/usr/bin/true") {
		t.Errorf("on-disk unit changed; want the paved ExecStart=/usr/bin/true, got:\n%s", got)
	}
}
