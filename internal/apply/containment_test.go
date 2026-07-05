package apply

import (
	"testing"
	"time"

	"github.com/lazypower/magus-cli/internal/diff"
	"github.com/lazypower/magus-cli/internal/ir"
	"github.com/lazypower/magus-cli/internal/manifest"
	"github.com/lazypower/magus-cli/internal/policy"
	"github.com/lazypower/magus-cli/internal/systemd"
)

// resolverWriter is a memWriter that also implements hostfs.Resolver, so the
// apply-time containment guard activates. `resolve` simulates a symlinked
// ancestor swapped in after planning.
type resolverWriter struct {
	*memWriter
	resolve map[string]string
}

func (r resolverWriter) ResolvePath(p string) (string, error) {
	if v, ok := r.resolve[p]; ok {
		return v, nil
	}
	return p, nil
}

func corePolicy() *policy.Policy {
	return &policy.Policy{Version: 1, FileRoots: []string{"/etc/core"}}
}

// TestApplyTimeContainmentSkipsEscapingWrite proves the apply-time guard: even
// when the plan says "create" (computed before a symlink swap), apply re-resolves
// and skips a write that would now escape authority — the file is never written.
func TestApplyTimeContainmentSkipsEscapingWrite(t *testing.T) {
	w := resolverWriter{memWriter: newMemWriter(), resolve: map[string]string{
		"/etc/core/evil/x": "/etc/x", // ancestor now a symlink to /etc
	}}
	in := &ir.IR{Files: []ir.File{{Path: "/etc/core/evil/x", Contents: []byte("hi")}}}
	plan := &diff.Plan{Actions: []diff.ResourceAction{
		{Path: "/etc/core/evil/x", Kind: diff.KindFile, Action: diff.ActionCreate},
	}}

	r := ApplyWithPolicy(corePolicy(), plan, in, w, manifest.New(), systemd.NewFake(), time.Unix(1, 0))

	if _, ok := w.files["/etc/core/evil/x"]; ok {
		t.Errorf("escaping write was executed despite containment")
	}
	if len(r.Outcomes) == 0 || r.Outcomes[0].Status != StatusSkipped {
		t.Errorf("expected a skipped outcome, got %+v", r.Outcomes)
	}
}

// TestApplyTimeContainmentAllowsInBounds confirms the guard does not block a
// write whose resolved path stays within authority.
func TestApplyTimeContainmentAllowsInBounds(t *testing.T) {
	w := resolverWriter{memWriter: newMemWriter(), resolve: map[string]string{
		"/etc/core/x": "/etc/core/x", // unchanged
	}}
	in := &ir.IR{Files: []ir.File{{Path: "/etc/core/x", Contents: []byte("hi")}}}
	plan := &diff.Plan{Actions: []diff.ResourceAction{
		{Path: "/etc/core/x", Kind: diff.KindFile, Action: diff.ActionCreate},
	}}
	ApplyWithPolicy(corePolicy(), plan, in, w, manifest.New(), systemd.NewFake(), time.Unix(1, 0))
	if _, ok := w.files["/etc/core/x"]; !ok {
		t.Errorf("in-bounds write was wrongly skipped")
	}
}

// TestApplyNilPolicySkipsGuard confirms the plain Apply (nil policy) path does
// not run containment — unit-test callers rely on this.
func TestApplyNilPolicySkipsGuard(t *testing.T) {
	w := resolverWriter{memWriter: newMemWriter(), resolve: map[string]string{
		"/etc/core/evil/x": "/etc/x",
	}}
	in := &ir.IR{Files: []ir.File{{Path: "/etc/core/evil/x", Contents: []byte("hi")}}}
	plan := &diff.Plan{Actions: []diff.ResourceAction{
		{Path: "/etc/core/evil/x", Kind: diff.KindFile, Action: diff.ActionCreate},
	}}
	Apply(plan, in, w, manifest.New(), systemd.NewFake(), time.Unix(1, 0))
	if _, ok := w.files["/etc/core/evil/x"]; !ok {
		t.Errorf("nil-policy Apply should not run containment guard")
	}
}

// TestQuadletManifestHashIsCanonical guards the diffKind quadlet mapping: a
// quadlet's recorded manifest hash must be the CANONICAL hash (comments/blank
// lines dropped), matching how diff and reclaim hash it — otherwise a clean
// orphaned quadlet falsely reads as drifted on reclaim.
func TestQuadletManifestHashIsCanonical(t *testing.T) {
	content := []byte("[Container]\n# a comment\n\nImage=x\n")
	q := ir.Quadlet{Path: "/etc/containers/systemd/a.container", Name: "a.container", Mode: 0o644, Contents: content}
	in := &ir.IR{Quadlets: []ir.Quadlet{q}}
	plan := &diff.Plan{Actions: []diff.ResourceAction{
		{Path: q.Path, Kind: diff.KindQuadlet, UnitName: q.Name, Action: diff.ActionCreate},
	}}

	m := manifest.New()
	Apply(plan, in, newMemWriter(), m, systemd.NewFake(), time.Unix(1, 0))

	entry, ok := m.Get(q.Path)
	if !ok {
		t.Fatal("quadlet not recorded in manifest")
	}
	want := diff.HashContent(content, diff.KindQuadlet)
	if entry.Hash != want {
		t.Errorf("stored hash %s, want canonical %s", entry.Hash, want)
	}
	// Sanity: this content actually distinguishes canonical from raw.
	if diff.HashContent(content, diff.KindQuadlet) == diff.HashContent(content, diff.KindFile) {
		t.Fatal("test content does not exercise canonicalization")
	}
}
