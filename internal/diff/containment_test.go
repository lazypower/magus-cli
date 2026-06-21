package diff

import (
	"errors"
	"testing"

	"gitea.wabash.place/lab/magus-cli/internal/ir"
	"gitea.wabash.place/lab/magus-cli/internal/manifest"
	"gitea.wabash.place/lab/magus-cli/internal/policy"
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
