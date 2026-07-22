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
