package principal

import (
	"fmt"

	"github.com/lazypower/magus-cli/internal/ir"
)

// Status records what happened to one principal during apply.
type Status string

const (
	StatusApplied   Status = "applied"   // created or converged
	StatusUnchanged Status = "unchanged" // adopted / already in desired state
	StatusSkipped   Status = "skipped"   // conflict — cannot converge safely
	StatusErrored   Status = "errored"   // a useradd/usermod call failed
)

// Outcome is the per-principal report apply emits.
type Outcome struct {
	Kind   Kind
	Name   string
	Action Action
	Status Status
	Reason string
	Err    error
}

// Result is the collected outcome of one principal Apply.
type Result struct {
	Outcomes []Outcome
}

// ExitCode mirrors the file reconciler: errors > skips > clean.
func (r *Result) ExitCode() int {
	var hasSkip, hasErr bool
	for _, o := range r.Outcomes {
		switch o.Status {
		case StatusSkipped:
			hasSkip = true
		case StatusErrored:
			hasErr = true
		}
	}
	switch {
	case hasErr:
		return 1
	case hasSkip:
		return 2
	default:
		return 0
	}
}

// Counts groups outcomes by status for the summary line.
func (r *Result) Counts() (applied, unchanged, skipped, errored int) {
	for _, o := range r.Outcomes {
		switch o.Status {
		case StatusApplied:
			applied++
		case StatusUnchanged:
			unchanged++
		case StatusSkipped:
			skipped++
		case StatusErrored:
			errored++
		}
	}
	return
}

// Apply executes plan against ex. desired supplies the declared attributes the
// plan rows reference by name. Per-principal errors do not halt — one bad
// useradd does not take the rest hostage (the reconciler posture). Created
// accounts get magus's safe defaults: password locked, login shell nologin
// unless the declaration set one.
func Apply(plan *Plan, desired *ir.IR, ex Executor) *Result {
	userByName := make(map[string]ir.User, len(desired.Users))
	for _, u := range desired.Users {
		userByName[u.Name] = u
	}
	groupByName := make(map[string]ir.Group, len(desired.Groups))
	for _, g := range desired.Groups {
		groupByName[g.Name] = g
	}

	r := &Result{Outcomes: make([]Outcome, 0, len(plan.Actions))}
	for _, a := range plan.Actions {
		r.Outcomes = append(r.Outcomes, applyOne(a, userByName, groupByName, ex))
	}
	return r
}

func applyOne(a PrincipalAction, users map[string]ir.User, groups map[string]ir.Group, ex Executor) Outcome {
	oc := Outcome{Kind: a.Kind, Name: a.Name, Action: a.Action}

	switch a.Action {
	case ActionConflict:
		oc.Status, oc.Reason = StatusSkipped, a.Reason
		return oc
	case ActionAdopt:
		oc.Status, oc.Reason = StatusUnchanged, "adopted, no write"
		return oc
	}

	switch a.Kind {
	case KindGroup:
		g := groups[a.Name]
		if err := ex.GroupAdd(g); err != nil {
			return errored(oc, err)
		}
		oc.Status, oc.Reason = StatusApplied, "created group"
		return oc

	case KindUser:
		u := users[a.Name]
		switch a.Action {
		case ActionCreate:
			// Safe defaults: every created principal is password-locked; the login
			// shell is nologin unless declared. A workload account is not a login
			// account.
			if err := ex.UserAdd(u, true); err != nil {
				return errored(oc, err)
			}
			if len(u.Groups) > 0 {
				if err := ex.UserAddGroups(u.Name, u.Groups); err != nil {
					return errored(oc, err)
				}
			}
			oc.Status, oc.Reason = StatusApplied, a.Reason
			return oc

		case ActionConverge:
			if u.Shell != "" {
				if err := ex.UserSetShell(u.Name, u.Shell); err != nil {
					return errored(oc, err)
				}
			}
			if len(u.Groups) > 0 {
				if err := ex.UserAddGroups(u.Name, u.Groups); err != nil {
					return errored(oc, err)
				}
			}
			oc.Status, oc.Reason = StatusApplied, a.Reason
			return oc
		}
	}

	oc.Status, oc.Err = StatusErrored, fmt.Errorf("internal: unhandled %s %s %s", a.Kind, a.Action, a.Name)
	return oc
}

func errored(oc Outcome, err error) Outcome {
	oc.Status, oc.Err = StatusErrored, err
	return oc
}
