package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/lazypower/magus-cli/internal/diff"
	"github.com/lazypower/magus-cli/internal/hostfs"
	"github.com/lazypower/magus-cli/internal/ir"
	"github.com/lazypower/magus-cli/internal/status"
)

func TestConfirmAction(t *testing.T) {
	var out bytes.Buffer
	if !confirmAction(strings.NewReader("y\n"), &out, "Take over /x? [y/N] ") {
		t.Errorf("confirmAction(y) should be true")
	}
	if confirmAction(strings.NewReader("n\n"), &out, "Take over /x? [y/N] ") {
		t.Errorf("confirmAction(n) should be false")
	}
	if !confirmAction(strings.NewReader("yes\n"), &out, "Reclaim /x? [y/N] ") {
		t.Errorf("confirmAction(yes) should be true")
	}
	if confirmAction(strings.NewReader("\n"), &out, "Reclaim /x? [y/N] ") {
		t.Errorf("confirmAction(empty) should be false")
	}
}

func TestBuildExplanationsUpdateAndConflict(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, root+"/u.conf", "old\nkeep\n")
	writeFile(t, root+"/c.conf", "secret-old\n")
	in := &ir.IR{Files: []ir.File{
		{Path: root + "/u.conf", Contents: []byte("new\nkeep\n"), Mode: 0o644},
		{Path: root + "/c.conf", Contents: []byte("secret-new\n"), Mode: 0o644},
	}}
	plan := &diff.Plan{Actions: []diff.ResourceAction{
		{Path: root + "/u.conf", Kind: diff.KindFile, Action: diff.ActionUpdate},
		{Path: root + "/c.conf", Kind: diff.KindFile, Action: diff.ActionConflict},
	}}

	// Non-verbose: update shows diff, conflict shows hashes only (no content).
	d := buildExplanations(in, hostfs.OS(), plan, false)
	if !strings.Contains(d[root+"/u.conf"], "-old") || !strings.Contains(d[root+"/u.conf"], "+new") {
		t.Errorf("update diff missing: %q", d[root+"/u.conf"])
	}
	if strings.Contains(d[root+"/c.conf"], "secret-") || !strings.Contains(d[root+"/c.conf"], "hashes only") {
		t.Errorf("conflict leaked content without -v: %q", d[root+"/c.conf"])
	}

	// Verbose: conflict reveals the diff.
	dv := buildExplanations(in, hostfs.OS(), plan, true)
	if !strings.Contains(dv[root+"/c.conf"], "-secret-old") {
		t.Errorf("verbose conflict diff missing: %q", dv[root+"/c.conf"])
	}
}

func TestEmitStatusHumanFull(t *testing.T) {
	var b bytes.Buffer
	r := statusReport{
		Result:           status.ResultError,
		ManagedResources: 1,
		Files:            map[string]string{"/etc/core/a": "ok"},
		Units:            map[string]string{"x.service": "failed"},
		Conflicts:        []conflictReportEntry{{Path: "/etc/core/c", Reason: "differs", FirstSeen: time.Unix(1, 0).UTC()}},
		Orphaned:         []orphanedReportEntry{{Path: "/etc/core/o", Reason: "deny", OrphanedAt: time.Unix(1, 0).UTC()}},
		Errors:           []errReportEntry{{Path: "/etc/core/e", Reason: "io error"}},
	}
	emitStatusHuman(&b, r)
	out := b.String()
	for _, want := range []string{"x.service", "/etc/core/a", "conflicts:", "/etc/core/c", "orphaned:", "errors:", "io error"} {
		if !strings.Contains(out, want) {
			t.Errorf("human status missing %q:\n%s", want, out)
		}
	}
}

func TestEmitStatusHumanNeverApplied(t *testing.T) {
	var b bytes.Buffer
	emitStatusHuman(&b, statusReport{Result: status.ResultOK, Files: map[string]string{}})
	if !strings.Contains(b.String(), "(never)") {
		t.Errorf("expected '(never)' for nil last_apply: %s", b.String())
	}
}

func TestRunBadArgs(t *testing.T) {
	// Wrong arg count / unknown flags → exit 1, no panic.
	cases := []struct {
		name string
		fn   func() int
	}{
		{"plan-noargs", func() int { return runPlan(nil) }},
		{"apply-noargs", func() int { return runApply(nil) }},
		{"validate-noargs", func() int { return runValidate(nil) }},
		{"status-extra", func() int { return runStatus([]string{"extra"}) }},
		{"adopt-oneargs", func() int { return runAdopt([]string{"only-one"}) }},
		{"reclaim-oneargs", func() int { return runReclaim([]string{"only-one"}) }},
		// Positional supplied so the ONLY reason for exit 1 is the unknown flag,
		// not a missing <butane-source>.
		{"plan-badflag", func() int { return runPlan([]string{"--nope", "x.bu"}) }},
	}
	for _, c := range cases {
		if code := c.fn(); code != 1 {
			t.Errorf("%s: exit %d, want 1", c.name, code)
		}
	}
}

func TestRunStatusNeverApplied(t *testing.T) {
	// No manifest, no status file → status still succeeds (never-applied view).
	f := newFixture(t)
	out, code := captureStdout(t, func() int {
		return runStatus([]string{"--manifest", f.manifest, "--status", f.status})
	})
	if code != 0 {
		t.Fatalf("status never-applied: exit %d", code)
	}
	if !strings.Contains(out, "never") {
		t.Errorf("expected never-applied view: %s", out)
	}
}
