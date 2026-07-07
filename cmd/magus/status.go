package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/lazypower/magus-cli/internal/manifest"
	"github.com/lazypower/magus-cli/internal/status"
)

const statusUsage = `magus status — print reconciler state

Usage: magus status [--json] [--manifest <path>] [--status <path>]

Status merges two sources: the manifest (what magus OWNS — managed files and
orphaned paths) and the observation file written by the last apply (what it
OBSERVED — unit states, conflicts, errors, timestamp). It does not parse the
Butane file or stat the disk; use 'magus plan' for live diff state.

Flags:
  --json              Emit machine-readable JSON
  --check             Exit nonzero on unhealthy state (for timers/monitoring):
                      0 = converged, 2 = conflicts/orphans present, 1 = error
  --max-age <dur>     With --check, also fail (exit 1) if the last apply is older
                      than this (e.g. 30m) — catches a stopped timer
  --manifest <path>   Override manifest file (default: /var/lib/magus/manifest.json)
  --status <path>     Override observation file (default: /var/lib/magus/status.json)
`

// statusReport is the JSON shape emitted by 'magus status --json' — the full
// spec shape, merging manifest ownership with the last-apply observation.
type statusReport struct {
	LastApply        *time.Time            `json:"last_apply"`
	Result           string                `json:"result"`
	ManagedResources int                   `json:"managed_resources"`
	Units            map[string]string     `json:"units"`
	Files            map[string]string     `json:"files"`
	Conflicts        []conflictReportEntry `json:"conflicts"`
	Orphaned         []orphanedReportEntry `json:"orphaned"`
	Errors           []errReportEntry      `json:"errors"`
}

type conflictReportEntry struct {
	Path      string    `json:"path"`
	Reason    string    `json:"reason"`
	FirstSeen time.Time `json:"first_seen"`
}

type orphanedReportEntry struct {
	Path       string    `json:"path"`
	Reason     string    `json:"reason"`
	OrphanedAt time.Time `json:"orphaned_at"`
}

type errReportEntry struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

func runStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, statusUsage) }
	manifestPath := fs.String("manifest", manifest.DefaultPath, "manifest file path")
	statusPath := fs.String("status", status.DefaultPath, "status file path")
	asJSON := fs.Bool("json", false, "emit JSON")
	check := fs.Bool("check", false, "exit nonzero on unhealthy state")
	maxAge := fs.Duration("max-age", 0, "with --check, fail if last apply older than this")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() != 0 {
		fmt.Fprint(os.Stderr, statusUsage)
		return 1
	}

	m, err := manifest.Load(*manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	// nil obs = never applied (or a stale cache) — non-fatal. A genuine read
	// error (e.g. EPERM running unprivileged) is surfaced as a warning so the
	// output isn't a misleading "last apply: (never)".
	obs, err := status.Load(*statusPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v (reporting manifest state only)\n", err)
	}

	report := buildStatus(m, obs)
	if *asJSON {
		if code := emitStatusJSON(os.Stdout, report); code != 0 {
			return code
		}
	} else {
		emitStatusHuman(os.Stdout, report)
	}
	if *check {
		return statusExitCode(report, *maxAge, time.Now().UTC())
	}
	return 0
}

// statusExitCode maps the merged status to a health exit code for --check:
// error → 1, conflicts/orphans → 2, converged → 0. With maxAge > 0 a last apply
// older than maxAge (or none at all) is exit 1 — a stopped timer is unhealthy
// no matter what the last result was.
func statusExitCode(r statusReport, maxAge time.Duration, now time.Time) int {
	if maxAge > 0 && (r.LastApply == nil || now.Sub(*r.LastApply) > maxAge) {
		return 1
	}
	switch r.Result {
	case status.ResultError:
		return 1
	case status.ResultWithSkips:
		return 2
	default:
		return 0
	}
}

// buildStatus merges manifest ownership (files, orphaned, managed count) with
// the last-apply observation (units, conflicts, errors, timestamp, result).
func buildStatus(m *manifest.Manifest, obs *status.Report) statusReport {
	// Empty (non-nil) slices/maps so JSON emits []/{} rather than null.
	r := statusReport{
		Units:     map[string]string{},
		Files:     map[string]string{},
		Conflicts: []conflictReportEntry{},
		Orphaned:  []orphanedReportEntry{},
		Errors:    []errReportEntry{},
	}

	paths := make([]string, 0, len(m.Resources))
	for p := range m.Resources {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var manifestLast time.Time
	for _, p := range paths {
		entry := m.Resources[p]
		switch entry.State {
		case manifest.StateActive:
			r.Files[p] = "ok"
			r.ManagedResources++
			if entry.AppliedAt.After(manifestLast) {
				manifestLast = entry.AppliedAt
			}
		case manifest.StateOrphaned:
			oa := time.Time{}
			if entry.OrphanedAt != nil {
				oa = *entry.OrphanedAt
			}
			r.Orphaned = append(r.Orphaned, orphanedReportEntry{
				Path:       p,
				Reason:     entry.OrphanedReason,
				OrphanedAt: oa,
			})
		}
	}

	// Observation-derived fields.
	obsResult := status.ResultOK
	if obs != nil {
		for name, state := range obs.Units {
			r.Units[name] = state
		}
		for _, c := range obs.Conflicts {
			r.Conflicts = append(r.Conflicts, conflictReportEntry{
				Path: c.Path, Reason: c.Reason, FirstSeen: c.FirstSeen,
			})
		}
		for _, e := range obs.Errors {
			r.Errors = append(r.Errors, errReportEntry{Path: e.Path, Reason: e.Reason})
		}
		obsResult = obs.Result
		if !obs.LastApply.IsZero() {
			la := obs.LastApply
			r.LastApply = &la
		}
	}
	// Fall back to the manifest's newest applied_at when there's no observation
	// (e.g. a manifest written by a pre-status binary).
	if r.LastApply == nil && !manifestLast.IsZero() {
		r.LastApply = &manifestLast
	}

	r.Result = combineResult(obsResult, len(r.Orphaned) > 0)
	return r
}

// combineResult elevates the observed result for orphaned paths (a kind of
// skip): error dominates; otherwise any conflict/orphan downgrades ok to
// ok-with-skips.
func combineResult(obsResult string, hasOrphans bool) string {
	if obsResult == status.ResultError {
		return status.ResultError
	}
	if hasOrphans && obsResult == status.ResultOK {
		return status.ResultWithSkips
	}
	return obsResult
}

func emitStatusJSON(w io.Writer, r statusReport) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func emitStatusHuman(w io.Writer, r statusReport) {
	if r.LastApply != nil {
		fmt.Fprintf(w, "last apply:  %s\n", r.LastApply.Format(time.RFC3339))
	} else {
		fmt.Fprintln(w, "last apply:  (never)")
	}
	fmt.Fprintf(w, "managed:     %d resources\n", r.ManagedResources)
	fmt.Fprintf(w, "result:      %s\n", r.Result)

	if len(r.Units) > 0 {
		fmt.Fprintln(w, "\nunits:")
		for _, name := range sortedKeys(r.Units) {
			fmt.Fprintf(w, "  %s  %s\n", r.Units[name], name)
		}
	}

	if r.ManagedResources > 0 {
		fmt.Fprintln(w, "\nfiles:")
		for _, p := range sortedKeys(r.Files) {
			fmt.Fprintf(w, "  ✓ %s\n", p)
		}
	}

	if len(r.Conflicts) > 0 {
		fmt.Fprintln(w, "\nconflicts:")
		for _, c := range r.Conflicts {
			fmt.Fprintf(w, "  ✗ %s  (%s, since %s)\n", c.Path, c.Reason, c.FirstSeen.Format(time.RFC3339))
		}
	}

	if len(r.Orphaned) > 0 {
		fmt.Fprintln(w, "\norphaned:")
		for _, o := range r.Orphaned {
			fmt.Fprintf(w, "  ! %s  (%s, since %s)\n", o.Path, o.Reason, o.OrphanedAt.Format(time.RFC3339))
		}
	}

	if len(r.Errors) > 0 {
		fmt.Fprintln(w, "\nerrors:")
		for _, e := range r.Errors {
			fmt.Fprintf(w, "  ✗ %s  (%s)\n", e.Path, e.Reason)
		}
	}
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
