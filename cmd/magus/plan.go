package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/lazypower/magus-cli/internal/diff"
	"github.com/lazypower/magus-cli/internal/explain"
	"github.com/lazypower/magus-cli/internal/hostfs"
	"github.com/lazypower/magus-cli/internal/ir"
	"github.com/lazypower/magus-cli/internal/manifest"
	"github.com/lazypower/magus-cli/internal/policy"
	"github.com/lazypower/magus-cli/internal/systemd"
)

const planUsage = `magus plan — show what apply would do

Usage: magus plan [--explain] [-v] [--policy <path>] [--manifest <path>] <butane-source>

<butane-source> is either a local filesystem path or an http(s) URL.

Flags:
  --explain           Show per-resource diffs for update/conflict rows
  -v, --verbose       With --explain, reveal the content diff for conflicts
                      (unowned). Default: conflicts show hashes only, so an
                      unowned file's content is never written to logs.
  --json              Emit the plan as machine-readable JSON (actions, service
                      actions, hashes, summary) for a scriptable review→apply loop
  --policy <path>     Override policy file (default: /etc/magus/policy.yaml)
  --manifest <path>   Override manifest file (default: /var/lib/magus/manifest.json)

Exit codes:
  0   no changes needed
  2   changes pending or conflicts present
  1   input-bad (parse error, policy/IR contradiction, manifest version mismatch)
`

func runPlan(args []string) int {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, planUsage) }
	policyPath := fs.String("policy", policy.DefaultPath, "policy file path")
	manifestPath := fs.String("manifest", manifest.DefaultPath, "manifest file path")
	explainFlag := fs.Bool("explain", false, "show per-resource diffs")
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON plan")
	var verbose bool
	fs.BoolVar(&verbose, "v", false, "reveal conflict content with --explain")
	fs.BoolVar(&verbose, "verbose", false, "reveal conflict content with --explain")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() != 1 {
		fmt.Fprint(os.Stderr, planUsage)
		return 1
	}
	butanePath := fs.Arg(0)

	p, err := policy.Load(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	parsed, warnings, err := ir.LoadButane(butanePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	printButaneWarnings(warnings)
	if violations := policy.Check(p, parsed, *manifestPath, *policyPath); len(violations) > 0 {
		for _, v := range violations {
			fmt.Fprintf(os.Stderr, "error: %s\n", v)
		}
		return 1
	}
	m, err := manifest.Load(*manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	// Surface (but don't persist — plan is read-only) any owned paths the
	// current policy now denies: they show as [orphaned], not as deletes.
	policy.OrphanDenied(p, m, time.Now().UTC())

	fsys := hostfs.OS()
	plan, err := diff.ComputeWithPolicy(p, parsed, m, fsys)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	// Preview enablement operations too (read-only is-enabled queries) so plan
	// honestly shows the enable/disable/skip work apply will do. No-op when
	// systemd is unavailable.
	diff.PlanServiceState(parsed, plan, systemd.OS())

	if *jsonOut {
		if code := emitPlanJSON(os.Stdout, butanePath, plan); code != 0 {
			return code
		}
	} else {
		var details map[string]string
		if *explainFlag {
			details = buildExplanations(parsed, fsys, plan, verbose)
		}
		printPlan(os.Stdout, butanePath, plan, details)
	}

	if plan.HasChanges() {
		return 2
	}
	return 0
}

// planJSON is the machine-readable shape of a plan. The spec calls Butane the
// LLM-facing contract and status the structured surface — plan, the thing an
// agent gates on before `apply --yes`, gets a structured surface too (UX3).
type planJSON struct {
	Source         string              `json:"source"`
	HasChanges     bool                `json:"has_changes"`
	Actions        []actionJSON        `json:"actions"`
	ServiceActions []serviceActionJSON `json:"service_actions"`
}

type actionJSON struct {
	Path       string `json:"path"`
	Kind       string `json:"kind"`
	Action     string `json:"action"`
	Reason     string `json:"reason,omitempty"`
	OnDiskHash string `json:"on_disk_hash,omitempty"`
	IRHash     string `json:"ir_hash,omitempty"`
}

type serviceActionJSON struct {
	Unit   string `json:"unit"`
	Op     string `json:"op"`
	Reason string `json:"reason,omitempty"`
}

// emitPlanJSON writes the plan as indented JSON. Returns 0 on success, 1 on a
// (near-impossible) encode error.
func emitPlanJSON(w io.Writer, source string, p *diff.Plan) int {
	out := planJSON{
		Source:         source,
		HasChanges:     p.HasChanges(),
		Actions:        make([]actionJSON, 0, len(p.Actions)),
		ServiceActions: make([]serviceActionJSON, 0, len(p.ServiceActions)),
	}
	for _, a := range p.Actions {
		out.Actions = append(out.Actions, actionJSON{
			Path:       a.Path,
			Kind:       string(a.Kind),
			Action:     string(a.Action),
			Reason:     a.Reason,
			OnDiskHash: a.OnDiskHash,
			IRHash:     a.IRHash,
		})
	}
	for _, sa := range p.ServiceActions {
		out.ServiceActions = append(out.ServiceActions, serviceActionJSON{
			Unit:   sa.Unit,
			Op:     string(sa.Op),
			Reason: sa.Reason,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

// buildExplanations renders the --explain detail block for each update/conflict
// action. Content is canonicalized per kind (matching the equivalence hash) so
// the diff reflects what actually drove the action; unowned conflicts are
// rendered hashes-only unless verbose.
func buildExplanations(irx *ir.IR, fsys hostfs.Reader, plan *diff.Plan, verbose bool) map[string]string {
	out := map[string]string{}
	for _, a := range plan.Actions {
		if a.Action != diff.ActionUpdate && a.Action != diff.ActionConflict {
			continue
		}
		inp := explain.Input{
			OnDiskMode: a.OnDiskMode,
			IRMode:     a.IRMode,
			Owned:      a.Action == diff.ActionUpdate,
			Verbose:    verbose,
		}
		if declared, ok := findDeclared(irx, a.Path); ok {
			onDisk, _ := fsys.ReadFile(a.Path)
			irc := declared.contents
			if declared.diffKind == diff.KindUnit || declared.diffKind == diff.KindQuadlet {
				onDisk = []byte(diff.CanonicalizeUnit(string(onDisk)))
				irc = []byte(diff.CanonicalizeUnit(string(irc)))
			}
			inp.OnDisk, inp.IR = onDisk, irc
			inp.IRUID, inp.IRGID = declared.uid, declared.gid
			if st, err := fsys.Stat(a.Path); err == nil {
				inp.OnDiskUID, inp.OnDiskGID = st.UID, st.GID
			}
		}
		if d := explain.Render(inp); d != "" {
			out[a.Path] = d
		}
	}
	return out
}

// printPlan renders the spec-shaped plan output. The order is stable: actions
// are printed in the order Compute emitted them (IR order, then orphans).
func printPlan(w io.Writer, butanePath string, p *diff.Plan, details map[string]string) {
	fmt.Fprintf(w, "%s → %d resources\n\n", butanePath, len(p.Actions))

	for _, a := range p.Actions {
		fmt.Fprintf(w, "  %-12s%s", actionTag(a.Action), a.Path)
		if a.Reason != "" {
			fmt.Fprintf(w, "  (%s)", a.Reason)
		}
		fmt.Fprintln(w)
		if d := details[a.Path]; d != "" {
			fmt.Fprintln(w, d)
		}
	}

	// Enablement operations, rendered like resource rows: [enable]/[disable]/
	// [skip] against the unit name.
	for _, sa := range p.ServiceActions {
		fmt.Fprintf(w, "  %-12s%s", fmt.Sprintf("[%s]", sa.Op), sa.Unit)
		if sa.Reason != "" {
			fmt.Fprintf(w, "  (%s)", sa.Reason)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, summary(p))
}

func actionTag(a diff.Action) string {
	return fmt.Sprintf("[%s]", a)
}

func summary(p *diff.Plan) string {
	var c, u, ad, d, s, cf, or, sc, er int
	for _, a := range p.Actions {
		switch a.Action {
		case diff.ActionCreate:
			c++
		case diff.ActionUpdate:
			u++
		case diff.ActionAdopt:
			ad++
		case diff.ActionDelete:
			d++
		case diff.ActionSkip:
			s++
		case diff.ActionConflict:
			cf++
		case diff.ActionOrphaned:
			or++
		case diff.ActionCleanup:
			sc++
		case diff.ActionError:
			er++
		}
	}
	out := fmt.Sprintf("%d creates, %d updates, %d adopts, %d deletes, %d skipped",
		c, u, ad, d, s)
	if cf > 0 {
		out += fmt.Sprintf(", %d conflicts", cf)
	}
	if or > 0 {
		out += fmt.Sprintf(", %d orphaned", or)
	}
	if sc > 0 {
		out += fmt.Sprintf(", %d manifest cleanup", sc)
	}
	if er > 0 {
		out += fmt.Sprintf(", %d errored", er)
	}
	if en, dis, sk := serviceCounts(p); en+dis+sk > 0 {
		out += fmt.Sprintf(", %d enable, %d disable", en, dis)
		if sk > 0 {
			out += fmt.Sprintf(", %d enablement skipped", sk)
		}
	}
	return out
}

// serviceCounts tallies the plan's enablement operations by kind.
func serviceCounts(p *diff.Plan) (enable, disable, skip int) {
	for _, sa := range p.ServiceActions {
		switch sa.Op {
		case diff.ServiceEnable:
			enable++
		case diff.ServiceDisable:
			disable++
		case diff.ServiceSkip:
			skip++
		}
	}
	return
}
