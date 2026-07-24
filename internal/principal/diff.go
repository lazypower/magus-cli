package principal

import (
	"fmt"
	"strings"

	"github.com/lazypower/magus-cli/internal/ir"
)

// Diff computes the principal actions for the managed subset of desired. Groups
// are diffed before users so a user's declared primary group exists first. Only
// principals the Gate manages are considered; the rest are ignored (Ignition's).
//
// A Reader error (getent itself failed, not "absent") is returned — fail-closed;
// magus does not guess a principal's state.
func Diff(desired *ir.IR, r Reader, g Gate) (*Plan, error) {
	p := &Plan{}
	for _, grp := range desired.Groups {
		if !g.Manages(grp.Name) {
			continue
		}
		a, err := diffGroup(grp, r)
		if err != nil {
			return nil, err
		}
		p.Actions = append(p.Actions, a)
	}
	for _, u := range desired.Users {
		if !g.Manages(u.Name) {
			continue
		}
		a, err := diffUser(u, r, g)
		if err != nil {
			return nil, err
		}
		p.Actions = append(p.Actions, a)
	}
	// Rootless prerequisites (subuid, linger) for principals that own user-scoped
	// workloads — appended after the users so the owner is created first: the
	// spine principal ⊳ subuid ⊳ linger.
	rootless, err := diffRootless(desired, r, g)
	if err != nil {
		return nil, err
	}
	p.Actions = append(p.Actions, rootless...)
	return p, nil
}

func diffUser(u ir.User, r Reader, g Gate) (PrincipalAction, error) {
	act := PrincipalAction{Kind: KindUser, Name: u.Name}
	actual, err := r.LookupUser(u.Name)
	if err != nil {
		return act, fmt.Errorf("lookup user %s: %w", u.Name, err)
	}

	if !actual.Exists {
		// A declared uid taken by a different principal is a conflict, never a
		// clobber (deterministic UIDs — ADR).
		if u.UID != nil {
			if owner, taken, err := r.UserByID(*u.UID); err != nil {
				return act, fmt.Errorf("check uid %d: %w", *u.UID, err)
			} else if taken && owner != u.Name {
				act.Action, act.Reason = ActionConflict,
					fmt.Sprintf("uid %d already belongs to %q", *u.UID, owner)
				return act, nil
			}
		}
		// A create must not join a privileged group without a grant. This is also
		// rejected at validate; enforced here so apply is fail-closed on its own.
		if bad := privilegedMemberships(g, u.Name, u.Groups); len(bad) > 0 {
			act.Action, act.Reason = ActionConflict,
				fmt.Sprintf("declared into privileged %s without a policy grant", pluralGroups(bad))
			return act, nil
		}
		act.Action, act.Reason = ActionCreate, createReason(u)
		return act, nil
	}

	// Exists. Identity attributes are immutable — a mismatch is a conflict, never
	// a live migration.
	if u.UID != nil && actual.UID != *u.UID {
		act.Action, act.Reason = ActionConflict,
			fmt.Sprintf("declared uid %d but %s has uid %d (identity is immutable; remove and recreate to renumber)", *u.UID, u.Name, actual.UID)
		return act, nil
	}
	if u.PrimaryGroup != "" && actual.PrimaryGroup != u.PrimaryGroup {
		act.Action, act.Reason = ActionConflict,
			fmt.Sprintf("declared primary group %q but %s has %q (immutable)", u.PrimaryGroup, u.Name, actual.PrimaryGroup)
		return act, nil
	}
	if u.HomeDir != "" && actual.Home != u.HomeDir {
		act.Action, act.Reason = ActionConflict,
			fmt.Sprintf("declared home %q but %s has %q (home path is immutable)", u.HomeDir, u.Name, actual.Home)
		return act, nil
	}

	// Adoption never absorbs an escalation `create` would refuse: an existing
	// principal already in a privileged group without a grant is a conflict, not a
	// silent adopt. Resolve with a policy grant or by removing the principal.
	held := append(append([]string(nil), actual.Groups...), actual.PrimaryGroup)
	if bad := privilegedMemberships(g, u.Name, held); len(bad) > 0 {
		act.Action, act.Reason = ActionConflict,
			fmt.Sprintf("already in privileged %s without a policy grant (grant it in policy, or remove the principal so magus recreates it clean)", pluralGroups(bad))
		return act, nil
	}

	// Mutable attributes converge.
	var reasons []string
	if u.Shell != "" && actual.Shell != u.Shell {
		reasons = append(reasons, fmt.Sprintf("shell %q→%q", actual.Shell, u.Shell))
	}
	if missing := groupsMissing(u.Groups, actual); len(missing) > 0 {
		reasons = append(reasons, fmt.Sprintf("add %s", pluralGroups(missing)))
	}
	if len(reasons) > 0 {
		act.Action, act.Reason = ActionConverge, strings.Join(reasons, ", ")
		return act, nil
	}

	act.Action, act.Reason = ActionAdopt, "attributes match"
	return act, nil
}

func diffGroup(grp ir.Group, r Reader) (PrincipalAction, error) {
	act := PrincipalAction{Kind: KindGroup, Name: grp.Name}
	gid, exists, err := r.LookupGroup(grp.Name)
	if err != nil {
		return act, fmt.Errorf("lookup group %s: %w", grp.Name, err)
	}
	if !exists {
		if grp.GID != nil {
			if owner, taken, err := r.GroupByID(*grp.GID); err != nil {
				return act, fmt.Errorf("check gid %d: %w", *grp.GID, err)
			} else if taken && owner != grp.Name {
				act.Action, act.Reason = ActionConflict,
					fmt.Sprintf("gid %d already belongs to %q", *grp.GID, owner)
				return act, nil
			}
		}
		act.Action, act.Reason = ActionCreate, "create group"
		return act, nil
	}
	if grp.GID != nil && gid != *grp.GID {
		act.Action, act.Reason = ActionConflict,
			fmt.Sprintf("declared gid %d but %s has gid %d (immutable)", *grp.GID, grp.Name, gid)
		return act, nil
	}
	act.Action, act.Reason = ActionAdopt, "attributes match"
	return act, nil
}

// groupsMissing returns the declared supplementary groups the user is not yet a
// member of (additive model — magus only ever adds).
func groupsMissing(declared []string, actual ActualUser) []string {
	have := map[string]bool{actual.PrimaryGroup: true}
	for _, g := range actual.Groups {
		have[g] = true
	}
	var missing []string
	for _, g := range declared {
		if !have[g] {
			missing = append(missing, g)
		}
	}
	return missing
}

func createReason(u ir.User) string {
	if u.UID != nil {
		return fmt.Sprintf("create user (uid %d, locked, %s)", *u.UID, shellOrNologin(u.Shell))
	}
	return "create user"
}

func shellOrNologin(shell string) string {
	if shell == "" {
		return "nologin"
	}
	return shell
}
