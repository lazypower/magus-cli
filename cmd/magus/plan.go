package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"gitea.wabash.place/lab/magus-cli/internal/diff"
	"gitea.wabash.place/lab/magus-cli/internal/explain"
	"gitea.wabash.place/lab/magus-cli/internal/hostfs"
	"gitea.wabash.place/lab/magus-cli/internal/ir"
	"gitea.wabash.place/lab/magus-cli/internal/manifest"
	"gitea.wabash.place/lab/magus-cli/internal/policy"
)

const planUsage = `magus plan — show what apply would do

Usage: magus plan [--explain] [-v] [--policy <path>] [--manifest <path>] <butane-source>

<butane-source> is either a local filesystem path or an http(s) URL.

Flags:
  --explain           Show per-resource diffs for update/conflict rows
  -v, --verbose       With --explain, reveal the content diff for conflicts
                      (unowned). Default: conflicts show hashes only, so an
                      unowned file's content is never written to logs.
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
	parsed, _, err := ir.LoadButane(butanePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
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

	var details map[string]string
	if *explainFlag {
		details = buildExplanations(parsed, fsys, plan, verbose)
	}
	printPlan(os.Stdout, butanePath, plan, details)

	if plan.HasChanges() {
		return 2
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

	fmt.Fprintln(w)
	fmt.Fprintln(w, summary(p))
}

func actionTag(a diff.Action) string {
	return fmt.Sprintf("[%s]", a)
}

func summary(p *diff.Plan) string {
	var c, u, ad, d, s, cf, or, sc int
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
	return out
}
