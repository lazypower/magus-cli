package apply

import (
	"testing"
	"time"

	"gitea.wabash.place/lab/magus-cli/internal/diff"
	"gitea.wabash.place/lab/magus-cli/internal/ir"
	"gitea.wabash.place/lab/magus-cli/internal/manifest"
	"gitea.wabash.place/lab/magus-cli/internal/policy"
	"gitea.wabash.place/lab/magus-cli/internal/systemd"
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
