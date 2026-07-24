package policy

import (
	"testing"

	"github.com/lazypower/magus-cli/internal/ir"
)

func pint(i int) *int { return &i }

// managePolicy is a minimal valid policy that manages `argus`, optionally with a
// wheel grant.
func managePolicy(grantWheel bool) *Policy {
	p := &Policy{
		Version:     1,
		FileRoots:   []string{"/etc/core"},
		ManageUsers: []string{"argus"},
	}
	if grantWheel {
		p.GroupGrants = map[string][]string{"argus": {"wheel"}}
	}
	return p
}

// checkUser runs Check over a single declared user and returns its violations.
// hasReason (shared test helper) matches against the reasons.
func checkUser(p *Policy, u ir.User) []Violation {
	return Check(p, &ir.IR{Users: []ir.User{u}})
}

func TestCheckPrincipalCleanUserPasses(t *testing.T) {
	got := checkUser(managePolicy(false), ir.User{Name: "argus", UID: pint(1000)})
	if len(got) != 0 {
		t.Errorf("clean managed user should pass, got %v", got)
	}
}

func TestCheckPrincipalUnmanagedIgnored(t *testing.T) {
	// `core` is not in manage_users; even declaring password/ssh/no-uid/wheel is
	// not a violation — it's Ignition's principal, ignored.
	got := checkUser(managePolicy(false), ir.User{
		Name: "core", HasPassword: true, HasSSHKeys: true, Groups: []string{"wheel"},
	})
	if len(got) != 0 {
		t.Errorf("unmanaged principal must never be a violation, got %v", got)
	}
}

func TestCheckPrincipalRequiresUID(t *testing.T) {
	got := checkUser(managePolicy(false), ir.User{Name: "argus"})
	if !hasReason(got, "must declare a uid") {
		t.Errorf("managed user without uid must be a violation, got %v", got)
	}
}

func TestCheckPrincipalRejectsSecrets(t *testing.T) {
	got := checkUser(managePolicy(false), ir.User{Name: "argus", UID: pint(1000), HasPassword: true, HasSSHKeys: true})
	if !hasReason(got, "password_hash") {
		t.Errorf("password_hash on a managed principal must be rejected, got %v", got)
	}
	if !hasReason(got, "ssh_authorized_keys") {
		t.Errorf("ssh_authorized_keys on a managed principal must be rejected, got %v", got)
	}
}

func TestCheckPrincipalPrivilegedGroupGate(t *testing.T) {
	// wheel without grant → rejected.
	got := checkUser(managePolicy(false), ir.User{Name: "argus", UID: pint(1000), Groups: []string{"wheel"}})
	if !hasReason(got, "privileged group") {
		t.Errorf("argus→wheel without grant must be rejected, got %v", got)
	}
	// wheel WITH grant → allowed.
	got = checkUser(managePolicy(true), ir.User{Name: "argus", UID: pint(1000), Groups: []string{"wheel"}})
	if hasReason(got, "privileged group") {
		t.Errorf("argus→wheel with a grant must pass, got %v", got)
	}
}

func TestCheckPrincipalPrimaryGroupPrivileged(t *testing.T) {
	// The gate covers the PRIMARY group too, not just supplementary.
	got := checkUser(managePolicy(false), ir.User{Name: "argus", UID: pint(1000), PrimaryGroup: "wheel"})
	if !hasReason(got, "privileged group") {
		t.Errorf("privileged PRIMARY group must be rejected, got %v", got)
	}
}

func TestCheckPrincipalNumericGroupRefused(t *testing.T) {
	// A numeric group token can't be verified non-privileged at validate → refuse
	// it, closing the gid-bypass fail-closed.
	got := checkUser(managePolicy(false), ir.User{Name: "argus", UID: pint(1000), Groups: []string{"0"}})
	if !hasReason(got, "numeric gid") {
		t.Errorf("numeric group token must be refused, got %v", got)
	}
}

// A rootless-workload owner must declare a home under /var/home|/home — a
// system-path home is refused at validate (defense behind the bounded chown).
func TestCheckPrincipalRootlessHomeGate(t *testing.T) {
	userQuad := func(owner string) ir.Quadlet {
		return ir.Quadlet{Name: "x.container", Scope: ir.ScopeUser, Owner: owner}
	}
	// home under /etc → rejected.
	bad := Check(managePolicy(false), &ir.IR{
		Users:    []ir.User{{Name: "argus", UID: pint(1000), HomeDir: "/etc"}},
		Quadlets: []ir.Quadlet{userQuad("argus")},
	})
	if !hasReason(bad, "home_dir under") {
		t.Errorf("rootless owner with home=/etc must be rejected, got %v", bad)
	}
	// a legitimate /var/home home → passes.
	ok := Check(managePolicy(false), &ir.IR{
		Users:    []ir.User{{Name: "argus", UID: pint(1000), HomeDir: "/var/home/argus"}},
		Quadlets: []ir.Quadlet{userQuad("argus")},
	})
	if hasReason(ok, "home_dir under") {
		t.Errorf("rootless owner with /var/home home must pass, got %v", ok)
	}
	// a principal that owns NO user workload isn't subject to the home gate.
	noWorkload := Check(managePolicy(false), &ir.IR{
		Users: []ir.User{{Name: "argus", UID: pint(1000), HomeDir: "/opt/argus"}},
	})
	if hasReason(noWorkload, "home_dir under") {
		t.Errorf("non-owner should not hit the rootless home gate, got %v", noWorkload)
	}
}

func TestIsUserHome(t *testing.T) {
	for _, h := range []string{"/var/home/argus", "/home/argus"} {
		if !isUserHome(h) {
			t.Errorf("%q should be a user home", h)
		}
	}
	for _, h := range []string{"/etc", "/var/lib/x", "/var/home", "/home", "/var/home/a/b", "/var/home/../etc", ""} {
		if isUserHome(h) {
			t.Errorf("%q must NOT be a user home", h)
		}
	}
}

func TestGateMethods(t *testing.T) {
	p := &Policy{
		Version:          1,
		FileRoots:        []string{"/etc/core"},
		ManageUsers:      []string{"argus"},
		PrivilegedGroups: []string{"kvm"},
		GroupGrants:      map[string][]string{"argus": {"wheel"}},
	}
	if !p.Manages("argus") || p.Manages("core") {
		t.Error("Manages allowlist wrong")
	}
	if !p.IsPrivilegedGroup("wheel") || !p.IsPrivilegedGroup("docker") {
		t.Error("built-in privileged groups must be recognized")
	}
	// The builtin denylist covers the well-known root-equivalent groups beyond the
	// sudo vectors — raw-device/hash/VM/container/log access are escalations too.
	for _, g := range []string{"disk", "shadow", "kvm", "lxd", "libvirt", "kmem", "adm", "systemd-journal", "sudo"} {
		if !p.IsPrivilegedGroup(g) {
			t.Errorf("builtin privileged group %q must be recognized without a policy entry", g)
		}
	}
	if !p.IsPrivilegedGroup("kvm") {
		t.Error("policy-extended privileged group must be recognized")
	}
	if p.IsPrivilegedGroup("argus") {
		t.Error("ordinary group must not be privileged")
	}
	if !p.GrantsPrivilegedGroup("argus", "wheel") || p.GrantsPrivilegedGroup("argus", "docker") {
		t.Error("grant resolution wrong")
	}
}
