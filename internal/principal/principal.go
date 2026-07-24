// Package principal reconciles operating-system identities — users and groups —
// as day-2 resources, the extension ADR-0003 makes to magus's authority.
//
// A principal is diffed like any other resource: declared (Butane
// passwd.users/groups, in the IR) vs actual (getent), producing create / adopt /
// converge / conflict. It reuses the reconciler shape (a Reader observes state,
// an Executor mutates it, both fakeable) but with more conservative destructive
// semantics: identity attributes (uid, primary gid, home path) are immutable
// after create, mutable attributes (shell, supplementary groups) converge, and
// magus never deletes a principal. See docs/adr-0003-principal-reconciliation.md.
//
// magus reconciles a principal only when policy's manage_users allowlist permits
// it (the Gate). An unmanaged principal — Ignition's `core`, or anything a
// hostile Butane declares outside the allowlist — is ignored, exactly as
// storage.disks is: not magus's to touch.
package principal

import (
	"fmt"
	"sort"

	"github.com/lazypower/magus-cli/internal/ir"
)

// Kind distinguishes the two principal types.
type Kind string

const (
	KindUser  Kind = "user"
	KindGroup Kind = "group"
	// KindSubid and KindLinger are the rootless prerequisites magus *provisions*
	// (never declared) for a principal that owns rootless workloads — the first
	// two links of ADR-0003's spine. Their Name is the owning principal. subuid
	// grants a subordinate uid/gid range (rootless userns); linger keeps the
	// principal's user@<uid> manager running at boot without a login session.
	KindSubid  Kind = "subuid"
	KindLinger Kind = "linger"
)

// Action is what reconciliation will do to one principal.
type Action string

const (
	// ActionCreate — the principal does not exist; create it (useradd/groupadd).
	ActionCreate Action = "create"
	// ActionConverge — exists, identity matches, a mutable attribute drifted;
	// bring it back (usermod). Shell and supplementary-group drift only.
	ActionConverge Action = "converge"
	// ActionAdopt — exists and already matches the declaration; claim it, no write.
	ActionAdopt Action = "adopt"
	// ActionConflict — cannot converge safely: an identity attribute differs, a
	// declared uid/gid is taken by a different principal, or an existing principal
	// sits in a privileged group without a policy grant. Surfaced and skipped,
	// never forced.
	ActionConflict Action = "conflict"
)

// PrincipalAction is one planned change to a user or group.
type PrincipalAction struct {
	Kind   Kind // user or group
	Name   string
	Action Action
	Reason string // human-facing: why this action / why a conflict
}

// Gate is the policy surface principal reconciliation consults. It is an
// interface so the principal package does not import policy (and so tests can
// drive the gates directly). The real implementation is policy.Policy.
type Gate interface {
	// Manages reports whether name is in the manage_users allowlist — the
	// principals magus may create/modify. Everything else is ignored.
	Manages(name string) bool
	// IsPrivilegedGroup reports whether a group (by name) is root-equivalent
	// (wheel/sudo/docker/…). The policy resolves numeric gids to names before
	// asking, so a gid-targeted privileged group is caught too.
	IsPrivilegedGroup(group string) bool
	// GrantsPrivilegedGroup reports whether policy explicitly permits principal
	// to hold membership in a privileged group.
	GrantsPrivilegedGroup(principal, group string) bool
}

// Reader observes host principal state. Fakeable; the OS implementation shells
// out to getent.
type Reader interface {
	// LookupUser returns the actual user, with Exists=false if absent.
	LookupUser(name string) (ActualUser, error)
	// UserByID returns the name owning uid, and whether any user does — for
	// collision detection on a declared uid.
	UserByID(uid int) (name string, exists bool, err error)
	// LookupGroup returns the gid of a group and whether it exists.
	LookupGroup(name string) (gid int, exists bool, err error)
	// GroupByID returns the name owning gid, and whether any group does.
	GroupByID(gid int) (name string, exists bool, err error)
	// HasSubid reports whether name already holds a subordinate uid/gid range
	// (/etc/subuid + /etc/subgid). Detect-then-provision: useradd auto-allocates
	// on FCOS, so a freshly created rootless owner usually already has one, which
	// magus adopts rather than adding a duplicate.
	HasSubid(name string) (bool, error)
	// Linger reports whether lingering is enabled for name — detected via the
	// /var/lib/systemd/linger/<name> marker, which is readable even when logind
	// is not running (so this probe never depends on the thing it gates).
	Linger(name string) (bool, error)
}

// ActualUser is the observed state of a user (getent passwd + id -Gn).
type ActualUser struct {
	Exists       bool
	Name         string
	UID          int
	GID          int      // primary group id
	PrimaryGroup string   // primary group name
	Groups       []string // supplementary group names (excludes the primary)
	Shell        string
	Home         string
}

// Executor performs principal mutations. Fakeable; the OS implementation runs
// useradd/usermod/groupadd as root.
type Executor interface {
	// UserAdd creates u. locked and nologin carry the safe defaults magus
	// applies to every created principal (password locked, login shell nologin)
	// unless the declaration overrode the shell.
	UserAdd(u ir.User, locked bool) error
	// UserSetShell converges a user's login shell.
	UserSetShell(name, shell string) error
	// UserAddGroups adds supplementary group memberships (additive only; never
	// removes a membership magus did not add).
	UserAddGroups(name string, groups []string) error
	// GroupAdd creates a group.
	GroupAdd(g ir.Group) error
	// EnsureSubid idempotently guarantees name holds a subordinate uid/gid range,
	// picking the next free range so every other principal's line is preserved
	// (/etc/subuid is a shared registry, never a managed file). A no-op when a
	// range already exists — safe to run even if useradd auto-allocated one
	// earlier in the same apply.
	EnsureSubid(name string) error
	// EnableLinger enables lingering for name (loginctl enable-linger). Idempotent:
	// re-enabling an already-lingering principal is a clean no-op.
	EnableLinger(name string) error
}

// Plan is the ordered set of principal actions a Diff produced.
type Plan struct {
	Actions []PrincipalAction
}

// HasWork reports whether the plan changes anything (create/converge) vs pure
// adopt/conflict.
func (p *Plan) HasWork() bool {
	for _, a := range p.Actions {
		if a.Action == ActionCreate || a.Action == ActionConverge {
			return true
		}
	}
	return false
}

// HasConflict reports whether any principal is a conflict — a pending,
// exit-2 state that a converged-vs-not signal (plan --json has_changes) must
// reflect even though it is not "work" magus will perform.
func (p *Plan) HasConflict() bool {
	for _, a := range p.Actions {
		if a.Action == ActionConflict {
			return true
		}
	}
	return false
}

// privilegedMemberships returns the privileged groups a principal holds
// (declared or actual) that policy does not grant — the escalation the gate must
// refuse. Sorted for deterministic diagnostics.
func privilegedMemberships(g Gate, principal string, groups []string) []string {
	var out []string
	for _, grp := range groups {
		if g.IsPrivilegedGroup(grp) && !g.GrantsPrivilegedGroup(principal, grp) {
			out = append(out, grp)
		}
	}
	sort.Strings(out)
	return out
}

// pluralGroups renders a group list for a conflict reason.
func pluralGroups(groups []string) string {
	if len(groups) == 1 {
		return fmt.Sprintf("group %q", groups[0])
	}
	return fmt.Sprintf("groups %v", groups)
}
