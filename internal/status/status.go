// Package status persists what the last apply OBSERVED, separate from the
// manifest (which records what magus OWNS). /var/lib/magus/status.json holds the
// last apply's timestamp, result, observed unit states, conflicts (carrying
// first_seen forward across applies), and errors. `magus status` reads it and
// merges it with the manifest for display.
//
// Keeping observation out of the manifest preserves the manifest as the pure
// ownership contract — conflicts and errors are not owned resources.
package status

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/lazypower/magus-cli/internal/statefile"
)

// DefaultPath is where magus reads and writes the observation file by default.
const DefaultPath = "/var/lib/magus/status.json"

// CurrentVersion tracks the observation schema. Unlike the manifest, an
// unreadable or version-mismatched status file is NOT fatal — it's a cache of
// the last apply, not a consent contract, so we treat it as "never applied"
// rather than halting.
const CurrentVersion = 1

// Result classifies the last apply outcome (mirrors the apply exit code).
const (
	ResultOK        = "ok"
	ResultWithSkips = "ok-with-skips"
	ResultError     = "error"
)

// Report is the on-disk observation shape.
type Report struct {
	Version   int               `json:"version"`
	LastApply time.Time         `json:"last_apply"`
	Result    string            `json:"result"`
	Units     map[string]string `json:"units"`
	Conflicts []Conflict        `json:"conflicts"`
	Errors    []ErrEntry        `json:"errors"`
}

// Conflict is one IR-declared path magus refuses to overwrite. FirstSeen is
// carried forward across applies so an operator can tell a fresh conflict from
// a long-standing one.
type Conflict struct {
	Path      string    `json:"path"`
	Reason    string    `json:"reason"`
	FirstSeen time.Time `json:"first_seen"`
}

// ErrEntry is one resource that errored mid-apply.
type ErrEntry struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Load reads the observation file. A missing file (never applied) and a stale
// cache (parse error or version mismatch) both return (nil, nil): the
// observation is a best-effort cache, not authoritative state, so an invalid
// one is treated as "never applied". A genuine read failure (EPERM — e.g.
// `magus status` run unprivileged) is different: it returns (nil, err) so the
// caller can distinguish "can't read it" from "never applied" and warn instead
// of silently reporting last-apply (never) (D21).
func Load(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read status %s: %w", path, err)
	}
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, nil
	}
	if r.Version != CurrentVersion {
		return nil, nil
	}
	return &r, nil
}

// Save writes the report atomically and durably (tmp + fsync + rename via
// statefile.WriteAtomic).
func (r *Report) Save(path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal status: %w", err)
	}
	if err := statefile.WriteAtomic(path, append(data, '\n')); err != nil {
		return fmt.Errorf("save status: %w", err)
	}
	return nil
}

// Build assembles a Report for an apply that just finished. Conflicts come in
// with a zero FirstSeen; Build carries forward the FirstSeen from prior for any
// conflict path that was already present, and stamps `now` for fresh ones — so a
// recurring conflict keeps its original first-seen time. prior may be nil (first
// apply, or no readable prior observation).
func Build(now time.Time, result string, units map[string]string, conflicts []Conflict, errs []ErrEntry, prior *Report) *Report {
	priorSeen := map[string]time.Time{}
	if prior != nil {
		for _, c := range prior.Conflicts {
			priorSeen[c.Path] = c.FirstSeen
		}
	}
	out := make([]Conflict, 0, len(conflicts))
	for _, c := range conflicts {
		if seen, ok := priorSeen[c.Path]; ok {
			c.FirstSeen = seen
		} else {
			c.FirstSeen = now
		}
		out = append(out, c)
	}
	if units == nil {
		units = map[string]string{}
	}
	if errs == nil {
		errs = []ErrEntry{}
	}
	return &Report{
		Version:   CurrentVersion,
		LastApply: now,
		Result:    result,
		Units:     units,
		Conflicts: out,
		Errors:    errs,
	}
}
