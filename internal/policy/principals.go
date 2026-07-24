package policy

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/lazypower/magus-cli/internal/ir"
)

// builtinPrivilegedGroups are always treated as root-equivalent: membership is a
// privilege escalation regardless of policy. privileged_groups in the policy
// extends this set; it never shrinks it.
//
// The set is the well-known root-equivalent groups: sudo vectors (root, wheel,
// sudo), and groups whose membership is a root-equivalent capability on its own —
// docker/lxd/libvirt (spawn privileged containers/VMs → escape), disk/kmem (raw
// block-device and kernel-memory access → read/write any file), shadow (password
// hashes), kvm (VM device), adm/systemd-journal (logs, which routinely carry
// secrets). A denylist is inherently incomplete: host-specific privileged groups
// are the operator's to add via privileged_groups.
var builtinPrivilegedGroups = []string{
	"root", "wheel", "sudo",
	"docker", "lxd", "libvirt",
	"disk", "kmem", "shadow", "kvm",
	"adm", "systemd-journal",
}

// Manages reports whether name is in the manage_users allowlist — the principals
// magus may create or modify. A principal outside the allowlist is ignored
// (Ignition's concern), so this is also how the two-consumer boundary is drawn
// for identities. Satisfies principal.Gate.
func (p *Policy) Manages(name string) bool {
	for _, u := range p.ManageUsers {
		if u == name {
			return true
		}
	}
	return false
}

// IsPrivilegedGroup reports whether a group name is root-equivalent. Satisfies
// principal.Gate. Callers pass group names (getent-resolved); numeric-gid
// targeting is refused at validate (see CheckPrincipals), so a privileged group
// cannot be smuggled past this by number.
func (p *Policy) IsPrivilegedGroup(group string) bool {
	for _, g := range builtinPrivilegedGroups {
		if g == group {
			return true
		}
	}
	for _, g := range p.PrivilegedGroups {
		if g == group {
			return true
		}
	}
	return false
}

// GrantsPrivilegedGroup reports whether policy explicitly permits principal to
// hold a privileged group membership. Satisfies principal.Gate.
func (p *Policy) GrantsPrivilegedGroup(principal, group string) bool {
	for _, g := range p.GroupGrants[principal] {
		if g == group {
			return true
		}
	}
	return false
}

// checkPrincipals appends the validate-time violations for declared principals:
// the manage_users boundary, deterministic-uid requirement, the privileged-group
// gate (name and numeric forms, supplementary and primary), and the v1-deferred
// secret fields. Only *managed* principals are checked — an unmanaged principal
// is ignored, so it is never a violation. Existing-state escalations (adopting a
// principal already in a privileged group) are caught later, at diff time.
func (p *Policy) checkPrincipals(in *ir.IR) []Violation {
	var v []Violation

	// Principals that own rootless (user-scope) workloads: their home is where
	// magus writes and CHOWNS a config tree, so the home must be a real user home,
	// never a system path — else magus could be steered into chowning /etc/... to
	// an unprivileged uid (defense in depth behind the bounded chown).
	rootlessOwners := map[string]bool{}
	for _, q := range in.Quadlets {
		if q.Scope == ir.ScopeUser && q.Owner != "" {
			rootlessOwners[q.Owner] = true
		}
	}

	for _, u := range in.Users {
		if !p.Manages(u.Name) {
			continue // unmanaged principal: Ignition's, not magus's
		}
		res := "user:" + u.Name

		if u.UID == nil {
			v = append(v, Violation{Resource: res, Reason: "managed principal must declare a uid (deterministic UIDs — no implicit allocation)"})
		}
		if rootlessOwners[u.Name] && !isUserHome(u.HomeDir) {
			v = append(v, Violation{Resource: res, Reason: fmt.Sprintf("a rootless-workload owner must declare home_dir under /var/home/<name> or /home/<name> (got %q); magus owns the config tree there and must never chown a system path", u.HomeDir)})
		}
		if u.HasPassword {
			v = append(v, Violation{Resource: res, Reason: "password_hash is not supported in v1 for a managed principal (created accounts are password-locked; a workload account is not a login account)"})
		}
		if u.HasSSHKeys {
			v = append(v, Violation{Resource: res, Reason: "ssh_authorized_keys is not supported in v1 for a managed principal (identity-adjacent, deferred)"})
		}

		// The privileged-group gate, on both supplementary and primary group.
		for _, g := range u.Groups {
			v = appendGroupGateViolation(v, p, res, u.Name, g)
		}
		if u.PrimaryGroup != "" {
			v = appendGroupGateViolation(v, p, res, u.Name, u.PrimaryGroup)
		}
	}

	for _, g := range in.Groups {
		if !p.Manages(g.Name) {
			continue
		}
		if g.GID == nil {
			v = append(v, Violation{Resource: "group:" + g.Name, Reason: "managed group must declare a gid"})
		}
	}

	return v
}

// isUserHome reports whether home is directly beneath a user-home root
// (/var/home/<name> or /home/<name>, one component, no traversal) — the only
// place a managed rootless principal's home may live.
func isUserHome(home string) bool {
	if strings.Contains(home, "..") {
		return false
	}
	for _, root := range []string{"/var/home/", "/home/"} {
		if rest, ok := strings.CutPrefix(home, root); ok && rest != "" && !strings.Contains(rest, "/") {
			return true
		}
	}
	return false
}

// appendGroupGateViolation enforces the privileged-group gate for one declared
// group token. A numeric token is refused outright (declare groups by name so the
// gate can't be bypassed by naming a privileged group by its gid); a named
// privileged group is refused unless policy grants it.
func appendGroupGateViolation(v []Violation, p *Policy, resource, principal, group string) []Violation {
	if _, err := strconv.Atoi(group); err == nil {
		return append(v, Violation{Resource: resource, Reason: fmt.Sprintf("declare groups by name, not numeric gid (%q): magus cannot verify a numeric group is not privileged", group)})
	}
	if p.IsPrivilegedGroup(group) && !p.GrantsPrivilegedGroup(principal, group) {
		return append(v, Violation{Resource: resource, Reason: fmt.Sprintf("adding %s to privileged group %q requires an explicit policy grant (group_grants)", principal, group)})
	}
	return v
}
