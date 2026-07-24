package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/lazypower/magus-cli/internal/apply"
	"github.com/lazypower/magus-cli/internal/diff"
	"github.com/lazypower/magus-cli/internal/hostfs"
	"github.com/lazypower/magus-cli/internal/lock"
	"github.com/lazypower/magus-cli/internal/manifest"
	"github.com/lazypower/magus-cli/internal/policy"
	"github.com/lazypower/magus-cli/internal/principal"
	"github.com/lazypower/magus-cli/internal/status"
	"github.com/lazypower/magus-cli/internal/systemd"
)

const applyUsage = `magus apply — reconcile the system toward the declared state

Usage: magus apply [--yes] [--policy <path>] [--manifest <path>] <butane-source>

<butane-source> is either a local filesystem path or an http(s) URL.
URLs are fetched on every apply — no caching, no fallback to a prior copy.

Flags:
  --yes               Skip the confirmation prompt
  --policy <path>     Override policy file (default: /etc/magus/policy.yaml)
  --manifest <path>   Override manifest file (default: /var/lib/magus/manifest.json)
  --status <path>     Override status observation file (default: /var/lib/magus/status.json)
  --insecure-http     Allow fetching Butane over plain HTTP (https required by default)

Exit codes:
  0   all declared resources are in their desired state
  2   one or more resources skipped (conflicts, orphaned, drift), OR the
      confirmation was declined with changes still pending
  1   one or more resources errored mid-apply, OR input-bad (parse, policy)
`

func runApply(args []string) int {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, applyUsage) }
	policyPath := fs.String("policy", policy.DefaultPath, "policy file path")
	manifestPath := fs.String("manifest", manifest.DefaultPath, "manifest file path")
	statusPath := fs.String("status", status.DefaultPath, "status observation file path")
	yes := fs.Bool("yes", false, "skip confirmation prompt")
	insecureHTTP := fs.Bool("insecure-http", false, "allow fetching Butane over plain HTTP")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() != 1 {
		fmt.Fprint(os.Stderr, applyUsage)
		return 1
	}
	butanePath := fs.Arg(0)

	// Serialize with any other manifest-mutating operation (a concurrent timer
	// apply, or a human adopt/reclaim) for the whole plan→apply→save window.
	// The manifest is the consent ledger; a lost record reads later as a
	// spurious conflict or a skipped delete.
	release, err := lock.Acquire(*manifestPath)
	if err != nil {
		if errors.Is(err, lock.ErrBusy) {
			fmt.Fprintln(os.Stderr, "error: another magus apply is in progress (manifest is locked)")
			return 1
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer func() { _ = release() }()

	p, parsed, m, ok := loadReconcileInputs(*policyPath, *manifestPath, *statusPath, butanePath, *insecureHTTP)
	if !ok {
		return 1
	}
	// A user-scope quadlet under an UNMANAGED principal's home is Ignition's, not
	// magus's — drop it before any reconciliation so it is never written or run as
	// that user (the manage_users boundary, for workloads).
	parsed = apply.FilterUnmanagedUserQuadlets(parsed, p.Manages)

	now := time.Now().UTC()

	// Manifest↔policy contention: transition any owned path the current policy
	// now denies to orphaned BEFORE diff, so the sweep skips+warns instead of
	// deleting it. Persist the transition immediately — the sticky-orphan
	// guarantee must hold even if this apply later aborts (e.g. conflicts-only,
	// declined at the prompt) before the end-of-apply Save.
	if orphaned := policy.OrphanDenied(p, m, now); len(orphaned) > 0 {
		for _, path := range orphaned {
			fmt.Fprintf(os.Stderr, "warning: %s orphaned (policy now denies it; `magus reclaim` to restore)\n", path)
		}
		if err := m.Save(*manifestPath); err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to persist orphan transitions: %v\n", err)
			return 1
		}
	}

	w := hostfs.OS()
	sd := systemd.OS()

	// Principals (passwd.users/groups) are diffed FIRST — before the file plan —
	// for two reasons: a file owned by a freshly-created uid needs its owner in
	// place, and a REFUSED principal (a conflict: uid collision, ungranted
	// privileged group) must not have its rootless quadlet written into its
	// generator search path, or a later boot/daemon-reload would run it as the
	// refused identity. So drop refused owners' user quadlets before the file plan.
	pplan, err := principal.Diff(parsed, principal.OSReader(), p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	plan, err := diff.ComputeWithPolicy(p, parsed, m, w)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	// A refused principal (a conflict: uid collision, ungranted privileged group,
	// immutable-attr change) must not have its rootless quadlet written or
	// activated — but its EXISTING resources must be LEFT INTACT, never deleted
	// (dropping the quadlet from the IR would make the sweep delete a running
	// workload's source). So mark those quadlets' file actions as conflicts:
	// magus withholds the write, preserves the manifest, and surfaces the refusal.
	apply.StageRefusedOwnerQuadlets(plan, parsed, blockedOwners(pplan, nil))
	// Enablement is persistent state reconciled every apply — model it as plan
	// rows so it's previewed like everything else and a drift can't hide behind
	// a clean file diff ("Nothing to apply" stays honest).
	diff.PlanServiceState(parsed, plan, sd)

	printPlan(os.Stdout, butanePath, plan, nil)
	printPrincipalPlan(os.Stdout, pplan)

	changes, conflicts, errored := planCounts(plan)
	pChanges, pConflicts := principalPlanCounts(pplan)
	changes += pChanges
	conflicts += pConflicts
	// A user workload can be staged-but-not-activated with everything on disk in
	// place (its user manager wasn't up last apply), so a converged file/principal
	// plan is NOT sufficient to early-exit — the activation step must still run to
	// (re)attempt it. Configs with no user workloads are unaffected.
	hasUserWork := apply.HasUserWorkloads(parsed)
	if changes == 0 && conflicts == 0 && errored == 0 && !hasUserWork {
		// Already converged. Refresh the observation (keeps last_apply current
		// on a timer that mostly runs no-op applies) and exit.
		saveStatusObservation(*statusPath, plan, nil, pplan, nil, apply.ObserveUnits(parsed, sd), now)
		fmt.Println("\nNothing to apply.")
		return 0
	}
	if changes == 0 && errored == 0 && !hasUserWork {
		// Conflicts only: nothing to apply, but the conflicts must still be
		// recorded so `magus status` reflects them (and the exit code is 2,
		// "conflicts present") — regardless of --yes. No prompt: there's nothing
		// to confirm.
		saveStatusObservation(*statusPath, plan, nil, pplan, nil, apply.ObserveUnits(parsed, sd), now)
		fmt.Printf("\n%d conflict%s present, nothing to apply.\n", conflicts, plural(conflicts))
		return 2
	}

	// There is real work (changes) and/or diff errors to surface. Confirm only
	// when there are changes to apply; errored-only plans run straight through
	// to record the failure (nothing is written — ActionError is fail-closed).
	if changes > 0 && !*yes {
		if !confirm(os.Stdin, os.Stdout, changes, conflicts) {
			// Exit 2 (changes pending), not 0 — declining with work outstanding
			// is not "converged", and a wrapper needs to tell them apart (UX5).
			fmt.Println("Aborted.")
			return 2
		}
	}
	fmt.Println()

	// Principals reconcile first: an owner must exist before a file it owns is
	// written. A per-principal conflict (e.g. uid collision) is skipped like any
	// other resource and does not halt the file pass.
	var presult *principal.Result
	if len(pplan.Actions) > 0 {
		presult = principal.Apply(pplan, parsed, principal.OSExecutor())
		for _, oc := range presult.Outcomes {
			printPrincipalOutcome(os.Stdout, oc)
		}
	}

	result := apply.ApplyWithPolicy(p, plan, parsed, w, m, sd, now)
	for _, oc := range result.Outcomes {
		printOutcome(os.Stdout, oc)
	}

	// Rootless user workloads activate last, over each owner's user manager —
	// after identity + subuid + linger (above) and the source writes (just now).
	// Their outcomes fold into the result so the summary, exit code, and status
	// observation account for them (a staged workload is exit 2, never green).
	if hasUserWork {
		uOutcomes := apply.ReconcileUserWorkloads(apply.UserWorkloads{
			IR:      parsed,
			Changed: appliedPaths(result),
			Refused: refusedPaths(result),
			Blocked: blockedOwners(pplan, presult),
			Chown:   w,
			NewUser: func(name string, uid int) systemd.UserManager { return systemd.OSUser(name, uid) },
		})
		for _, oc := range uOutcomes {
			printOutcome(os.Stdout, oc)
		}
		result.Outcomes = append(result.Outcomes, uOutcomes...)
	}

	if err := m.Save(*manifestPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to save manifest: %v\n", err)
		return 1
	}

	saveStatusObservation(*statusPath, plan, result, pplan, presult, nil, now)

	a, _, s, e := result.Counts()
	exit := result.ExitCode()
	pa, ps, pe := 0, 0, 0
	if presult != nil {
		pApplied, _, pSkipped, pErrored := presult.Counts()
		pa, ps, pe = pApplied, pSkipped, pErrored
		exit = worstExit(exit, presult.ExitCode())
	}
	fmt.Println()
	fmt.Printf("Applied %d changes, %d skipped, %d errors.  exit %d\n",
		a+pa, s+ps, e+pe, exit)
	return exit
}

// blockedOwners maps each principal that did NOT reconcile cleanly — a refused
// conflict (uid collision, ungranted privileged group) or a failed
// create/subuid/linger — to the reason. Its rootless workloads are then staged,
// never activated: magus must not run a workload as an identity the gate refused
// or whose prerequisites failed (Codex P1 #2).
func blockedOwners(pplan *principal.Plan, presult *principal.Result) map[string]string {
	blocked := map[string]string{}
	// Plan-level conflicts. A workload owner is a USER, so only a user conflict
	// (or a subuid/linger prerequisite) blocks it — NOT a same-named group. The
	// manifest namespaces user:argus and group:argus separately; collapsing them
	// here would let a group-gid collision block an otherwise-valid user's
	// workload (Codex round-3).
	for _, a := range pplan.Actions {
		if a.Action == principal.ActionConflict && ownerKind(a.Kind) {
			blocked[a.Name] = a.Reason
		}
	}
	// Apply-level skips/errors (the conflict's skip, or a failed provision step
	// keyed by the owning principal's name — never a group).
	if presult != nil {
		for _, oc := range presult.Outcomes {
			if (oc.Status == principal.StatusSkipped || oc.Status == principal.StatusErrored) && ownerKind(oc.Kind) {
				reason := oc.Reason
				if oc.Err != nil {
					reason = oc.Err.Error()
				}
				blocked[oc.Name] = reason
			}
		}
	}
	return blocked
}

// ownerKind reports whether a principal action kind identifies a workload OWNER
// (a user, or its subuid/linger prerequisites) rather than a group.
func ownerKind(k principal.Kind) bool {
	return k == principal.KindUser || k == principal.KindSubid || k == principal.KindLinger
}

// appliedPaths is the set of resource paths this apply actually wrote (applied),
// so the user-workload reconciler can tell a freshly-written quadlet source
// (start/restart) from an unchanged one (leave the running service alone).
func appliedPaths(result *apply.Result) map[string]bool {
	out := map[string]bool{}
	for _, oc := range result.Outcomes {
		if oc.Status == apply.StatusApplied {
			out[oc.Path] = true
		}
	}
	return out
}

// refusedPaths is the set of resource paths this apply did NOT reconcile (a
// conflict it refused to write, a skip, an error), so the user-workload
// reconciler never activates a service the generator produced from a source
// magus itself declined (Codex round-2 fail-open activation).
func refusedPaths(result *apply.Result) map[string]bool {
	out := map[string]bool{}
	for _, oc := range result.Outcomes {
		if oc.Status == apply.StatusSkipped || oc.Status == apply.StatusErrored {
			out[oc.Path] = true
		}
	}
	return out
}

// worstExit combines two apply exit codes by the spec priority: errors (1) beat
// skips (2) beat clean (0).
func worstExit(a, b int) int {
	if a == 1 || b == 1 {
		return 1
	}
	if a == 2 || b == 2 {
		return 2
	}
	return 0
}

// printPrincipalPlan previews the principal actions alongside the file plan.
func printPrincipalPlan(w io.Writer, pplan *principal.Plan) {
	if pplan == nil || len(pplan.Actions) == 0 {
		return
	}
	for _, a := range pplan.Actions {
		fmt.Fprintf(w, "  [%s]  %s %s  (%s)\n", a.Action, a.Kind, a.Name, a.Reason)
	}
}

// principalPlanCounts splits principal actions into changes (create/converge)
// and conflicts, mirroring planCounts for files so the "nothing to apply" and
// confirmation gates account for identity work too.
func principalPlanCounts(pplan *principal.Plan) (changes, conflicts int) {
	if pplan == nil {
		return 0, 0
	}
	for _, a := range pplan.Actions {
		switch a.Action {
		case principal.ActionCreate, principal.ActionConverge:
			changes++
		case principal.ActionConflict:
			conflicts++
		}
	}
	return changes, conflicts
}

// printPrincipalOutcome renders one principal apply outcome, matching the file
// outcome style (✓ applied/unchanged, ✗ skipped/errored).
func printPrincipalOutcome(w io.Writer, oc principal.Outcome) {
	mark := "✓"
	if oc.Status == principal.StatusSkipped || oc.Status == principal.StatusErrored {
		mark = "✗"
	}
	suffix := ""
	switch {
	case oc.Err != nil:
		suffix = fmt.Sprintf("  (errored: %v)", oc.Err)
	case oc.Status == principal.StatusSkipped:
		suffix = fmt.Sprintf("  (skipped: %s)", oc.Reason)
	case oc.Reason != "":
		suffix = fmt.Sprintf("  (%s)", oc.Reason)
	}
	fmt.Fprintf(w, "  %s %s %s%s\n", mark, oc.Kind, oc.Name, suffix)
}

// saveStatusObservation writes the post-apply observation file. Conflicts are
// taken from the plan (so they're recorded whether or not Apply ran); errors and
// the result come from the apply Result when Apply ran, otherwise it's a clean
// no-op (result=ok) with the supplied observed unit states. first_seen for
// recurring conflicts is carried forward by status.Build. A write failure is a
// warning, never fatal — the apply already succeeded and the manifest is saved.
func saveStatusObservation(statusPath string, plan *diff.Plan, result *apply.Result, pplan *principal.Plan, presult *principal.Result, fallbackUnits map[string]string, now time.Time) {
	conflicts := []status.Conflict{}
	for _, a := range plan.Actions {
		if a.Action == diff.ActionConflict {
			conflicts = append(conflicts, status.Conflict{Path: a.Path, Reason: a.Reason})
		}
	}
	// Enablement skips (declared enabled but masked/static/not-found) are
	// unresolved-by-magus states too — record them so `magus status` reflects
	// the unachievable intent instead of dropping it.
	for _, sa := range plan.ServiceActions {
		if sa.Op == diff.ServiceSkip {
			conflicts = append(conflicts, status.Conflict{Path: sa.Unit, Reason: sa.Reason})
		}
	}
	// A refused principal escalation (uid collision, ungranted privileged group)
	// is an in-scope conflict too — record it so a principal-only escalation
	// refusal reaches `magus status` instead of reading as a clean result.
	for _, a := range pplan.Actions {
		if a.Action == principal.ActionConflict {
			conflicts = append(conflicts, status.Conflict{Path: principalRef(a.Kind, a.Name), Reason: a.Reason})
		}
	}
	// A staged user workload (the activation reconciler skipped it — user manager
	// down, owner refused, tree unownable) is an unresolved state too: record it
	// so `magus status` names the staged workload and its reason instead of a bare
	// ok-with-skips (Codex P2 #5). Deduped by path against the conflicts above.
	idx := map[string]int{}
	for i, c := range conflicts {
		idx[c.Path] = i
	}
	if result != nil {
		for _, oc := range result.Outcomes {
			if oc.Status != apply.StatusSkipped {
				continue
			}
			if i, ok := idx[oc.Path]; ok {
				// The path already has a conflict recorded (e.g. a file conflict AND a
				// staged activation for the same path) — MERGE the reasons so status
				// shows both, never silently dropping the staged state.
				if !strings.Contains(conflicts[i].Reason, oc.Reason) {
					conflicts[i].Reason = conflicts[i].Reason + "; " + oc.Reason
				}
				continue
			}
			conflicts = append(conflicts, status.Conflict{Path: oc.Path, Reason: oc.Reason})
			idx[oc.Path] = len(conflicts) - 1
		}
	}

	errs := []status.ErrEntry{}
	res := status.ResultOK
	units := fallbackUnits
	if result != nil {
		for _, oc := range result.Outcomes {
			if oc.Status == apply.StatusErrored {
				msg := oc.Reason
				if oc.Err != nil {
					msg = oc.Err.Error()
				}
				errs = append(errs, status.ErrEntry{Path: oc.Path, Reason: msg})
			}
		}
		res = statusResultString(result.ExitCode())
		units = result.UnitStates
	}
	// Principal apply errors (a useradd/usermod that failed mid-apply) are
	// recorded like file errors so status never reads green over a real failure.
	if presult != nil {
		for _, oc := range presult.Outcomes {
			if oc.Status == principal.StatusErrored {
				msg := oc.Reason
				if oc.Err != nil {
					msg = oc.Err.Error()
				}
				errs = append(errs, status.ErrEntry{Path: principalRef(oc.Kind, oc.Name), Reason: msg})
			}
		}
	}
	// Escalate the recorded result to match what was actually observed: any error
	// dominates; otherwise a conflict (file, enablement, or principal) is a skip.
	// This keeps status honest on the no-apply paths (result==nil) too.
	switch {
	case len(errs) > 0:
		res = status.ResultError
	case len(conflicts) > 0 && res == status.ResultOK:
		res = status.ResultWithSkips
	}

	prior, _ := status.Load(statusPath)
	rep := status.Build(now, res, units, conflicts, errs, prior)
	if err := rep.Save(statusPath); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to write status observation: %v\n", err)
	}
}

// principalRef renders a principal's status/error path as "<kind>:<name>" (e.g.
// "user:argus") so identity conflicts and errors are distinguishable from file
// paths in the observation.
func principalRef(kind principal.Kind, name string) string {
	return string(kind) + ":" + name
}

// statusResultString maps an apply exit code to the observation result string.
func statusResultString(code int) string {
	switch code {
	case 0:
		return status.ResultOK
	case 2:
		return status.ResultWithSkips
	default:
		return status.ResultError
	}
}

// planCounts splits actions into the numbers the apply flow needs: changes that
// will run, conflicts that will be skipped, and resources that errored during
// diff (undeterminable state, fail-closed). Enablement operations count too:
// enable/disable are changes, a masked/static skip is a conflict.
func planCounts(p *diff.Plan) (changes, conflicts, errored int) {
	for _, a := range p.Actions {
		switch a.Action {
		case diff.ActionCreate, diff.ActionUpdate, diff.ActionAdopt,
			diff.ActionDelete, diff.ActionCleanup:
			changes++
		case diff.ActionConflict, diff.ActionOrphaned:
			conflicts++
		case diff.ActionError:
			errored++
		}
	}
	for _, sa := range p.ServiceActions {
		switch sa.Op {
		case diff.ServiceEnable, diff.ServiceDisable:
			changes++
		case diff.ServiceSkip:
			conflicts++
		}
	}
	return
}

// confirm prompts the user with the spec-shaped message. Anything other than
// "y" / "yes" (case-insensitive) is treated as decline. EOF (e.g., piped
// input) is also a decline — we never proceed without explicit consent.
func confirm(in io.Reader, out io.Writer, changes, conflicts int) bool {
	switch {
	case changes > 0 && conflicts > 0:
		fmt.Fprintf(out, "\nApply %d changes? (%d conflict%s will be skipped) [y/N] ",
			changes, conflicts, plural(conflicts))
	case changes > 0:
		fmt.Fprintf(out, "\nApply %d changes? [y/N] ", changes)
	default:
		// Conflicts only and no changes — nothing to apply, no prompt needed.
		// printPlan already showed the conflicts; just decline.
		fmt.Fprintf(out, "\n%d conflict%s present, nothing to apply.\n",
			conflicts, plural(conflicts))
		return false
	}
	return readYesNo(in)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// printOutcome renders one apply outcome with ✓ for applied/unchanged and ✗
// for skipped/errored, matching the spec example.
func printOutcome(w io.Writer, oc apply.Outcome) {
	mark := "✓"
	if oc.Status == apply.StatusSkipped || oc.Status == apply.StatusErrored {
		mark = "✗"
	}
	suffix := ""
	switch {
	case oc.Err != nil:
		suffix = fmt.Sprintf("  (errored: %v)", oc.Err)
	case oc.Status == apply.StatusSkipped:
		suffix = fmt.Sprintf("  (skipped: %s)", oc.Reason)
	case oc.Reason != "":
		suffix = fmt.Sprintf("  (%s)", oc.Reason)
	}
	fmt.Fprintf(w, "  %s %s%s\n", mark, oc.Path, suffix)
}
