package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/lazypower/magus-cli/internal/apply"
	"github.com/lazypower/magus-cli/internal/diff"
	"github.com/lazypower/magus-cli/internal/ir"
	"github.com/lazypower/magus-cli/internal/manifest"
	"github.com/lazypower/magus-cli/internal/status"
)

func TestPlanCountsAndSummary(t *testing.T) {
	p := &diff.Plan{Actions: []diff.ResourceAction{
		{Action: diff.ActionCreate}, {Action: diff.ActionUpdate}, {Action: diff.ActionAdopt},
		{Action: diff.ActionDelete}, {Action: diff.ActionSkip}, {Action: diff.ActionConflict},
		{Action: diff.ActionOrphaned}, {Action: diff.ActionCleanup},
	}}
	changes, conflicts := planCounts(p)
	if changes != 5 { // create,update,adopt,delete,cleanup
		t.Errorf("changes = %d, want 5", changes)
	}
	if conflicts != 2 { // conflict + orphaned
		t.Errorf("conflicts = %d, want 2", conflicts)
	}
	s := summary(p)
	for _, want := range []string{"1 creates", "1 conflicts", "1 orphaned", "1 manifest cleanup"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary missing %q: %s", want, s)
		}
	}
}

func TestPlural(t *testing.T) {
	if plural(1) != "" || plural(0) != "s" || plural(2) != "s" {
		t.Errorf("plural wrong: %q %q %q", plural(1), plural(0), plural(2))
	}
}

func TestPrintPlanWithDetails(t *testing.T) {
	var b bytes.Buffer
	p := &diff.Plan{Actions: []diff.ResourceAction{
		{Action: diff.ActionUpdate, Path: "/etc/core/a", Reason: "content differs"},
	}}
	printPlan(&b, "x.bu", p, map[string]string{"/etc/core/a": "    --- on disk\n    +++ IR"})
	out := b.String()
	if !strings.Contains(out, "[update]") || !strings.Contains(out, "/etc/core/a") {
		t.Errorf("plan line missing: %s", out)
	}
	if !strings.Contains(out, "--- on disk") {
		t.Errorf("detail block not printed: %s", out)
	}
}

func TestConfirm(t *testing.T) {
	cases := []struct {
		in            string
		changes, conf int
		want          bool
	}{
		{"y\n", 1, 0, true},
		{"yes\n", 2, 1, true},
		{"n\n", 1, 0, false},
		{"\n", 1, 0, false},
		{"", 1, 0, false}, // EOF
	}
	for _, c := range cases {
		var out bytes.Buffer
		got := confirm(strings.NewReader(c.in), &out, c.changes, c.conf)
		if got != c.want {
			t.Errorf("confirm(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	// Conflicts-only never prompts (returns false).
	var out bytes.Buffer
	if confirm(strings.NewReader("y\n"), &out, 0, 3) {
		t.Errorf("conflicts-only confirm should not proceed")
	}
}

func TestPrintOutcome(t *testing.T) {
	var b bytes.Buffer
	printOutcome(&b, apply.Outcome{Path: "/x", Status: apply.StatusApplied, Reason: "created"})
	printOutcome(&b, apply.Outcome{Path: "/y", Status: apply.StatusSkipped, Reason: "conflict"})
	out := b.String()
	if !strings.Contains(out, "✓ /x") || !strings.Contains(out, "✗ /y") {
		t.Errorf("outcome marks wrong: %s", out)
	}
}

func TestStatusResultString(t *testing.T) {
	if statusResultString(0) != status.ResultOK ||
		statusResultString(2) != status.ResultWithSkips ||
		statusResultString(1) != status.ResultError {
		t.Errorf("statusResultString mapping wrong")
	}
}

func TestCombineResult(t *testing.T) {
	if combineResult(status.ResultError, true) != status.ResultError {
		t.Errorf("error must dominate")
	}
	if combineResult(status.ResultOK, true) != status.ResultWithSkips {
		t.Errorf("orphans should downgrade ok -> ok-with-skips")
	}
	if combineResult(status.ResultOK, false) != status.ResultOK {
		t.Errorf("clean should stay ok")
	}
}

func TestBuildStatusMergesManifestAndObservation(t *testing.T) {
	m := manifest.New()
	now := time.Unix(1000, 0).UTC()
	m.PutActive("/etc/core/a", manifest.KindFile, "h", manifest.OriginCreate, now)
	m.PutActive("/etc/core/secret", manifest.KindFile, "h", manifest.OriginCreate, now)
	m.Orphan("/etc/core/secret", "policy deny", now)

	obs := &status.Report{
		LastApply: time.Unix(2000, 0).UTC(),
		Result:    status.ResultOK,
		Units:     map[string]string{"x.service": "active"},
		Conflicts: []status.Conflict{{Path: "/etc/core/c", Reason: "differs", FirstSeen: now}},
		Errors:    []status.ErrEntry{},
	}
	r := buildStatus(m, obs)
	if r.ManagedResources != 1 || r.Files["/etc/core/a"] != "ok" {
		t.Errorf("managed/files wrong: %+v", r)
	}
	if len(r.Orphaned) != 1 || r.Orphaned[0].Path != "/etc/core/secret" {
		t.Errorf("orphaned wrong: %+v", r.Orphaned)
	}
	if r.Units["x.service"] != "active" || len(r.Conflicts) != 1 {
		t.Errorf("observation not merged: %+v", r)
	}
	// orphan present + obs ok -> ok-with-skips
	if r.Result != status.ResultWithSkips {
		t.Errorf("result = %q, want ok-with-skips", r.Result)
	}
	if r.LastApply == nil || !r.LastApply.Equal(time.Unix(2000, 0).UTC()) {
		t.Errorf("last_apply should come from observation")
	}
}

func TestBuildStatusNoObservation(t *testing.T) {
	m := manifest.New()
	m.PutActive("/etc/core/a", manifest.KindFile, "h", manifest.OriginCreate, time.Unix(500, 0).UTC())
	r := buildStatus(m, nil) // never applied with status binary
	if r.Result != status.ResultOK {
		t.Errorf("result = %q, want ok", r.Result)
	}
	// falls back to manifest applied_at
	if r.LastApply == nil || !r.LastApply.Equal(time.Unix(500, 0).UTC()) {
		t.Errorf("last_apply fallback wrong: %v", r.LastApply)
	}
}

func TestEmitStatusJSONAndHuman(t *testing.T) {
	r := statusReport{
		Result: status.ResultOK, ManagedResources: 1,
		Units: map[string]string{"x.service": "active"},
		Files: map[string]string{"/etc/core/a": "ok"},
	}
	var j bytes.Buffer
	if code := emitStatusJSON(&j, r); code != 0 {
		t.Fatalf("emitStatusJSON exit %d", code)
	}
	if !strings.Contains(j.String(), "\"managed_resources\": 1") {
		t.Errorf("json wrong: %s", j.String())
	}
	var h bytes.Buffer
	emitStatusHuman(&h, r)
	if !strings.Contains(h.String(), "x.service") || !strings.Contains(h.String(), "/etc/core/a") {
		t.Errorf("human output wrong: %s", h.String())
	}
}

func TestHashContent(t *testing.T) {
	if hashContent([]byte("x"))[:7] != "sha256:" {
		t.Errorf("hashContent prefix wrong")
	}
}

func TestFindDeclared(t *testing.T) {
	in := &ir.IR{
		Files:    []ir.File{{Path: "/etc/core/f", Contents: []byte("c"), Mode: 0o644}},
		Units:    []ir.Unit{{Name: "magus-x.service", Contents: "[Unit]\n", DropIns: []ir.DropIn{{Name: "10-magus.conf", Contents: "[Service]\n"}}}},
		Quadlets: []ir.Quadlet{{Path: "/etc/containers/systemd/a.container", Name: "a.container", Contents: []byte("[Container]\n")}},
	}
	cases := map[string]diff.Kind{
		"/etc/core/f":                                         diff.KindFile,
		"/etc/systemd/system/magus-x.service":                 diff.KindUnit,
		"/etc/systemd/system/magus-x.service.d/10-magus.conf": diff.KindUnit,
		"/etc/containers/systemd/a.container":                 diff.KindQuadlet,
	}
	for path, kind := range cases {
		d, ok := findDeclared(in, path)
		if !ok {
			t.Errorf("findDeclared(%q) not found", path)
			continue
		}
		if d.diffKind != kind {
			t.Errorf("findDeclared(%q) kind = %v, want %v", path, d.diffKind, kind)
		}
	}
	if _, ok := findDeclared(in, "/nope"); ok {
		t.Errorf("findDeclared should miss unknown path")
	}
}
