package diff

import (
	"errors"
	"testing"
	"time"

	"github.com/lazypower/magus-cli/internal/ir"
	"github.com/lazypower/magus-cli/internal/manifest"
	"github.com/lazypower/magus-cli/internal/policy"
)

// resolverFS is a memFS that also implements hostfs.Resolver, simulating
// symlink resolution: paths in `resolve` map to a redirected real path; a path
// in `failPaths` returns a resolution error (to exercise fail-closed).
type resolverFS struct {
	memFS
	resolve   map[string]string
	failPaths map[string]bool
}

func (r resolverFS) ResolvePath(p string) (string, error) {
	if r.failPaths[p] {
		return "", errors.New("simulated resolution failure")
	}
	if v, ok := r.resolve[p]; ok {
		return v, nil
	}
	return p, nil
}

func corePolicy() *policy.Policy {
	return &policy.Policy{Version: 1, FileRoots: []string{"/etc/core"}}
}

func TestContainmentBlocksSymlinkEscape(t *testing.T) {
	in := &ir.IR{Files: []ir.File{{Path: "/etc/core/evil/x", Contents: []byte("hi")}}}
	// /etc/core/evil is a symlink to /etc/elsewhere → the write would escape.
	fs := resolverFS{memFS: memFS{}, resolve: map[string]string{
		"/etc/core/evil/x": "/etc/elsewhere/x",
	}}
	plan, err := ComputeWithPolicy(corePolicy(), in, manifest.New(), fs)
	if err != nil {
		t.Fatal(err)
	}
	a := findAction(t, plan, "/etc/core/evil/x")
	if a.Action != ActionConflict {
		t.Fatalf("symlink escape not blocked: action=%s reason=%q", a.Action, a.Reason)
	}
}

func TestContainmentAllowsInBoundsSymlink(t *testing.T) {
	in := &ir.IR{Files: []ir.File{{Path: "/etc/core/link/x", Contents: []byte("hi")}}}
	// Resolves to another in-bounds location → still allowed (create).
	fs := resolverFS{memFS: memFS{}, resolve: map[string]string{
		"/etc/core/link/x": "/etc/core/real/x",
	}}
	plan, err := ComputeWithPolicy(corePolicy(), in, manifest.New(), fs)
	if err != nil {
		t.Fatal(err)
	}
	if a := findAction(t, plan, "/etc/core/link/x"); a.Action != ActionCreate {
		t.Fatalf("in-bounds symlink wrongly blocked: action=%s reason=%q", a.Action, a.Reason)
	}
}

func TestContainmentFailsClosedOnResolveError(t *testing.T) {
	in := &ir.IR{Files: []ir.File{{Path: "/etc/core/x", Contents: []byte("hi")}}}
	fs := resolverFS{memFS: memFS{}, failPaths: map[string]bool{"/etc/core/x": true}}
	plan, err := ComputeWithPolicy(corePolicy(), in, manifest.New(), fs)
	if err != nil {
		t.Fatal(err)
	}
	if a := findAction(t, plan, "/etc/core/x"); a.Action != ActionConflict {
		t.Fatalf("resolution error did not fail closed: action=%s", a.Action)
	}
}

func TestContainmentNoOpWithoutResolver(t *testing.T) {
	// A plain memFS is not a Resolver; containment must be skipped (the path is
	// created normally) rather than erroring.
	in := &ir.IR{Files: []ir.File{{Path: "/etc/core/x", Contents: []byte("hi")}}}
	plan, err := ComputeWithPolicy(corePolicy(), in, manifest.New(), memFS{})
	if err != nil {
		t.Fatal(err)
	}
	if a := findAction(t, plan, "/etc/core/x"); a.Action != ActionCreate {
		t.Fatalf("containment ran without a Resolver: action=%s", a.Action)
	}
}

func TestContainmentBlocksEscapingDelete(t *testing.T) {
	// An owned file, omitted from IR, would normally be deleted — but its parent
	// is now a symlink redirecting outside authority, so the delete is skipped.
	m := manifest.New()
	m.PutActive("/etc/core/link/x", manifest.KindFile, "sha256:x", manifest.OriginCreate, time.Unix(1, 0))
	fs := resolverFS{
		memFS:   memFS{"/etc/core/link/x": memFile{contents: []byte("x"), mode: 0o644}},
		resolve: map[string]string{"/etc/core/link/x": "/etc/x"},
	}
	plan, err := ComputeWithPolicy(corePolicy(), &ir.IR{}, m, fs)
	if err != nil {
		t.Fatal(err)
	}
	if a := findAction(t, plan, "/etc/core/link/x"); a.Action != ActionConflict {
		t.Fatalf("escaping delete not blocked: action=%s reason=%q", a.Action, a.Reason)
	}
}

func TestOrphanCleanupWhenFileGone(t *testing.T) {
	m := manifest.New()
	m.PutActive("/etc/core/gone", manifest.KindFile, "sha256:x", manifest.OriginCreate, time.Unix(1, 0))
	m.Orphan("/etc/core/gone", "policy deny: x", time.Unix(2, 0))
	plan, err := Compute(&ir.IR{}, m, memFS{}) // file absent on disk
	if err != nil {
		t.Fatal(err)
	}
	if a := findAction(t, plan, "/etc/core/gone"); a.Action != ActionCleanup {
		t.Fatalf("absent orphan not aged out: action=%s", a.Action)
	}
}

func TestOrphanHeldWhenFilePresent(t *testing.T) {
	m := manifest.New()
	m.PutActive("/etc/core/keep", manifest.KindFile, "sha256:x", manifest.OriginCreate, time.Unix(1, 0))
	m.Orphan("/etc/core/keep", "policy deny: x", time.Unix(2, 0))
	plan, err := Compute(&ir.IR{}, m, memFS{"/etc/core/keep": memFile{contents: []byte("x"), mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	if a := findAction(t, plan, "/etc/core/keep"); a.Action != ActionOrphaned {
		t.Fatalf("present orphan not held: action=%s", a.Action)
	}
}

func TestContainmentBlocksSymlinkIntoDeniedSubtree(t *testing.T) {
	// A symlink that redirects an in-root path INTO a denied subtree must be
	// caught (regression for the reverted resolved-root deny bypass).
	p := &policy.Policy{
		Version:   1,
		FileRoots: []string{"/etc/core"},
		Deny:      policy.Deny{Paths: []string{"/etc/core/secret/*"}},
	}
	in := &ir.IR{Files: []ir.File{{Path: "/etc/core/link/x", Contents: []byte("hi")}}}
	fs := resolverFS{memFS: memFS{}, resolve: map[string]string{
		"/etc/core/link/x": "/etc/core/secret/x",
	}}
	plan, err := ComputeWithPolicy(p, in, manifest.New(), fs)
	if err != nil {
		t.Fatal(err)
	}
	if a := findAction(t, plan, "/etc/core/link/x"); a.Action != ActionConflict {
		t.Fatalf("symlink into denied subtree not blocked: action=%s reason=%q", a.Action, a.Reason)
	}
}
