//go:build integration

package integration

import (
	"strings"
	"testing"
)

// principalPolicy manages the `argus` principal (and no other), with a file_root
// so any owned files could also land. This is the identity analogue of the
// workload policy's file_roots/unit_patterns.
const principalPolicy = `version: 1
file_roots:
  - /etc/core
  - /var/lib/magus
unit_patterns:
  - "magus-*"
manage_users:
  - argus
deny:
  paths:
    - /etc/shadow
    - /etc/passwd
`

// argusButane declares the argus principal at the given uid (workload account:
// nologin, no password). Kept minimal so the test proves identity mechanics, not
// Butane breadth.
func argusButane(uid string) string {
	return butaneHeader + `passwd:
  users:
    - name: argus
      uid: ` + uid + `
      shell: /usr/sbin/nologin
`
}

// TestPrincipalCreate proves day-2 identity creation through magus on real
// shadow-utils: apply a butane declaring argus → the user exists with the
// declared uid, a nologin shell, a created home, and a LOCKED password (the safe
// default). A second apply is a clean no-op (adopted).
func TestPrincipalCreate(t *testing.T) {
	c := setup(t, principalPolicy)
	bu := argusButane("1500")

	// plan before apply: a create is pending → exit 2, previewed as [create].
	if out, code := c.plan(bu); code != 2 || !strings.Contains(out, "[create]") {
		t.Fatalf("plan (pending) exit %d, want 2 with [create]\n%s", code, out)
	}

	out, code := c.apply(bu)
	if code != 0 {
		t.Fatalf("apply exit %d\n%s", code, out)
	}
	if _, idCode := c.exec("id", "argus"); idCode != 0 {
		t.Fatalf("argus was not created\n%s", out)
	}
	// uid, shell, home from getent.
	pw := c.readFile("/etc/passwd")
	if !strings.Contains(pw, "argus:x:1500:") {
		t.Errorf("argus not at uid 1500: %s", grepLine(pw, "argus"))
	}
	if !strings.Contains(grepLine(pw, "argus"), "/usr/sbin/nologin") {
		t.Errorf("argus shell is not nologin: %s", grepLine(pw, "argus"))
	}
	if !c.exists("/var/home/argus") {
		t.Errorf("argus home was not created")
	}
	// Safe default: the account is password-locked (passwd -S reports L).
	st, _ := c.exec("passwd", "-S", "argus")
	if !strings.Contains(st, "argus L") {
		t.Errorf("created account is not password-locked: %q", strings.TrimSpace(st))
	}

	// Idempotence: a second apply adopts, no useradd, no-op.
	if out2, code2 := c.apply(bu); code2 != 0 || !strings.Contains(out2, "Nothing to apply") {
		t.Errorf("second apply not a no-op: exit %d\n%s", code2, out2)
	}
}

// TestPrincipalAdoptExisting proves an already-present matching principal
// (Ignition-made, say) is ADOPTED, not recreated: magus records no change and
// does not re-run useradd (the uid/home are left exactly as found).
func TestPrincipalAdoptExisting(t *testing.T) {
	c := setup(t, principalPolicy)
	// Pre-create argus out of band, matching what the butane will declare.
	if out, code := c.exec("useradd", "-m", "-u", "1500", "-s", "/usr/sbin/nologin", "argus"); code != 0 {
		t.Fatalf("precondition useradd: %s", out)
	}
	sigBefore := c.statSig("/etc/passwd")

	out, code := c.apply(argusButane("1500"))
	if code != 0 {
		t.Fatalf("apply exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "adopted") && !strings.Contains(out, "Nothing to apply") {
		t.Errorf("existing matching principal should adopt/no-op, got:\n%s", out)
	}
	// /etc/passwd must be untouched — adoption never rewrites an existing identity.
	if after := c.statSig("/etc/passwd"); after != sigBefore {
		t.Errorf("adoption mutated /etc/passwd (%s → %s)", sigBefore, after)
	}
}

// TestPrincipalUIDCollisionConflicts proves a declared uid already held by a
// DIFFERENT user is a conflict (skipped, exit 2), never a clobber.
func TestPrincipalUIDCollisionConflicts(t *testing.T) {
	c := setup(t, principalPolicy)
	if out, code := c.exec("useradd", "-u", "1600", "squatter"); code != 0 {
		t.Fatalf("precondition useradd squatter: %s", out)
	}

	out, code := c.apply(argusButane("1600"))
	if code != 2 {
		t.Fatalf("uid collision apply exit %d, want 2\n%s", code, out)
	}
	if !strings.Contains(out, "conflict") && !strings.Contains(out, "belongs to") {
		t.Errorf("collision not reported as a conflict:\n%s", out)
	}
	// argus must NOT have been created, and the squatter keeps uid 1600.
	if _, idCode := c.exec("id", "argus"); idCode == 0 {
		t.Errorf("argus was created despite the uid collision")
	}
	if !strings.Contains(grepLine(c.readFile("/etc/passwd"), "squatter"), ":1600:") {
		t.Errorf("squatter's uid was clobbered")
	}
}

// TestPrincipalUnmanagedIgnored proves the two-consumer boundary for identities:
// a principal not in manage_users (here `intruder`) is ignored — magus never
// creates it — exactly as it ignores storage.disks.
func TestPrincipalUnmanagedIgnored(t *testing.T) {
	c := setup(t, principalPolicy)
	bu := butaneHeader + `passwd:
  users:
    - name: intruder
      uid: 1700
`
	if out, code := c.apply(bu); code != 0 {
		t.Fatalf("apply with only an unmanaged principal should be a clean no-op, exit %d\n%s", code, out)
	}
	if _, idCode := c.exec("id", "intruder"); idCode == 0 {
		t.Errorf("magus created an unmanaged principal — the manage_users boundary leaked")
	}
}

// TestPrincipalValidateGates proves the security gates reject at validate: a
// managed principal without a uid, and one declared into a privileged group
// without a grant, are both input-bad (validate refuses, apply writes nothing).
func TestPrincipalValidateGates(t *testing.T) {
	c := setup(t, principalPolicy)

	noUID := butaneHeader + `passwd:
  users:
    - name: argus
      shell: /usr/sbin/nologin
`
	c.put("/host.bu", noUID)
	if out, code := c.magus("validate", "--policy", "/policy.yaml", "/host.bu"); code == 0 {
		t.Errorf("validate accepted a managed principal with no uid:\n%s", out)
	} else if !strings.Contains(out, "uid") {
		t.Errorf("validate error did not cite the missing uid:\n%s", out)
	}

	intoWheel := butaneHeader + `passwd:
  users:
    - name: argus
      uid: 1500
      groups:
        - wheel
`
	c.put("/host.bu", intoWheel)
	out, code := c.magus("validate", "--policy", "/policy.yaml", "/host.bu")
	if code == 0 {
		t.Errorf("validate accepted argus→wheel without a grant:\n%s", out)
	}
	if !strings.Contains(out, "privileged") {
		t.Errorf("validate error did not cite the privileged-group gate:\n%s", out)
	}
	// Apply must also refuse (input-bad halts) and create nothing.
	if _, ac := c.apply(intoWheel); ac == 0 {
		t.Errorf("apply proceeded on a denied privileged escalation")
	}
	if _, idCode := c.exec("id", "argus"); idCode == 0 {
		t.Errorf("argus was created despite the denied escalation")
	}
}

// grepLine returns the first line of text containing substr (test diagnostic).
func grepLine(text, substr string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, substr) {
			return line
		}
	}
	return ""
}
