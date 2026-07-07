package diff

import (
	"errors"
	"io/fs"
	"testing"
	"time"

	"github.com/lazypower/magus-cli/internal/hostfs"
	"github.com/lazypower/magus-cli/internal/ir"
	"github.com/lazypower/magus-cli/internal/manifest"
)

// memFile is one entry in the in-memory test filesystem. isDir distinguishes
// directories from files since both share the path → metadata mapping but
// directories carry no contents.
type memFile struct {
	contents []byte
	mode     uint32
	uid, gid int
	isDir    bool
}

type memFS map[string]memFile

func (m memFS) Stat(path string) (hostfs.FileInfo, error) {
	f, ok := m[path]
	if !ok {
		return hostfs.FileInfo{Exists: false}, nil
	}
	return hostfs.FileInfo{Exists: true, Mode: f.mode, UID: f.uid, GID: f.gid}, nil
}

func (m memFS) ReadFile(path string) ([]byte, error) {
	f, ok := m[path]
	if !ok || f.isDir {
		return nil, &fs.PathError{Op: "open", Path: path, Err: errors.New("not found")}
	}
	return f.contents, nil
}

// erroringFS wraps a memFS and returns an I/O error for one designated path,
// modeling an EPERM/transient failure on a single declared resource.
type erroringFS struct {
	memFS
	failPath string
}

func (e erroringFS) Stat(path string) (hostfs.FileInfo, error) {
	if path == e.failPath {
		return hostfs.FileInfo{}, errors.New("permission denied")
	}
	return e.memFS.Stat(path)
}

func (e erroringFS) ReadFile(path string) ([]byte, error) {
	if path == e.failPath {
		return nil, errors.New("permission denied")
	}
	return e.memFS.ReadFile(path)
}

// D5: a stat/read failure on one declared path must degrade to a fail-closed
// ActionError row without aborting the diff of every other resource.
func TestDiffPerPathErrorIsolation(t *testing.T) {
	in := &ir.IR{Files: []ir.File{
		{Path: "/etc/magus.d/good", Mode: 0o644, Contents: []byte("hi")},
		{Path: "/etc/magus.d/bad", Mode: 0o644, Contents: []byte("nope")},
	}}
	fsys := erroringFS{memFS: memFS{}, failPath: "/etc/magus.d/bad"}

	plan, err := Compute(in, manifest.New(), fsys)
	if err != nil {
		t.Fatalf("Compute must not abort on a per-path error: %v", err)
	}
	good := findAction(t, plan, "/etc/magus.d/good")
	if good.Action != ActionCreate {
		t.Errorf("healthy resource action = %s, want create", good.Action)
	}
	bad := findAction(t, plan, "/etc/magus.d/bad")
	if bad.Action != ActionError {
		t.Errorf("failed resource action = %s, want error", bad.Action)
	}
	if bad.Reason == "" {
		t.Error("error row should carry a reason")
	}
}

// findAction returns the first action targeting path, or fails the test.
func findAction(t *testing.T, p *Plan, path string) ResourceAction {
	t.Helper()
	for _, a := range p.Actions {
		if a.Path == path {
			return a
		}
	}
	t.Fatalf("no action for %q in plan: %+v", path, p.Actions)
	return ResourceAction{}
}

func TestCreate(t *testing.T) {
	in := &ir.IR{
		Files: []ir.File{
			{Path: "/etc/magus.d/foo", Mode: 0o644, Contents: []byte("hi")},
		},
	}
	plan, err := Compute(in, manifest.New(), memFS{})
	if err != nil {
		t.Fatal(err)
	}
	a := findAction(t, plan, "/etc/magus.d/foo")
	if a.Action != ActionCreate {
		t.Errorf("Action = %s, want create", a.Action)
	}
}

func TestSkipWhenOwnedAndUnchanged(t *testing.T) {
	in := &ir.IR{
		Files: []ir.File{
			{Path: "/etc/magus.d/foo", Mode: 0o644, Contents: []byte("hi")},
		},
	}
	m := manifest.New()
	m.PutActive("/etc/magus.d/foo", manifest.KindFile, "sha256:abc", manifest.OriginCreate, time.Now())
	fs := memFS{
		"/etc/magus.d/foo": {contents: []byte("hi"), mode: 0o644, uid: 1000, gid: 1000},
	}
	plan, err := Compute(in, m, fs)
	if err != nil {
		t.Fatal(err)
	}
	a := findAction(t, plan, "/etc/magus.d/foo")
	if a.Action != ActionSkip {
		t.Errorf("Action = %s (%s), want skip", a.Action, a.Reason)
	}
}

func TestAdoptWhenContentMatchesAndNotOwned(t *testing.T) {
	in := &ir.IR{
		Files: []ir.File{
			{Path: "/etc/magus.d/foo", Mode: 0o644, Contents: []byte("hi")},
		},
	}
	fs := memFS{
		"/etc/magus.d/foo": {contents: []byte("hi"), mode: 0o644},
	}
	plan, err := Compute(in, manifest.New(), fs)
	if err != nil {
		t.Fatal(err)
	}
	a := findAction(t, plan, "/etc/magus.d/foo")
	if a.Action != ActionAdopt {
		t.Errorf("Action = %s (%s), want adopt", a.Action, a.Reason)
	}
}

func TestUpdateWhenOwnedAndContentDiffers(t *testing.T) {
	in := &ir.IR{
		Files: []ir.File{
			{Path: "/etc/magus.d/foo", Mode: 0o644, Contents: []byte("new")},
		},
	}
	m := manifest.New()
	m.PutActive("/etc/magus.d/foo", manifest.KindFile, "sha256:old", manifest.OriginCreate, time.Now())
	fs := memFS{
		"/etc/magus.d/foo": {contents: []byte("old"), mode: 0o644},
	}
	plan, err := Compute(in, m, fs)
	if err != nil {
		t.Fatal(err)
	}
	a := findAction(t, plan, "/etc/magus.d/foo")
	if a.Action != ActionUpdate {
		t.Errorf("Action = %s (%s), want update", a.Action, a.Reason)
	}
	if a.OnDiskHash == "" || a.IRHash == "" {
		t.Error("update should populate hashes for explain")
	}
}

func TestConflictWhenNotOwnedAndContentDiffers(t *testing.T) {
	in := &ir.IR{
		Files: []ir.File{
			{Path: "/etc/magus.d/foo", Mode: 0o644, Contents: []byte("new")},
		},
	}
	fs := memFS{
		"/etc/magus.d/foo": {contents: []byte("old"), mode: 0o644},
	}
	plan, err := Compute(in, manifest.New(), fs)
	if err != nil {
		t.Fatal(err)
	}
	a := findAction(t, plan, "/etc/magus.d/foo")
	if a.Action != ActionConflict {
		t.Errorf("Action = %s (%s), want conflict", a.Action, a.Reason)
	}
	if !plan.HasConflicts() {
		t.Error("plan.HasConflicts() = false, want true")
	}
}

func TestModeMismatchTreatedAsDiff(t *testing.T) {
	// Same content, different mode → not equivalent. Owned → update;
	// unowned → conflict. Tests both branches.
	mkIR := func() *ir.IR {
		return &ir.IR{Files: []ir.File{
			{Path: "/etc/magus.d/foo", Mode: 0o600, Contents: []byte("same")},
		}}
	}
	fs := memFS{
		"/etc/magus.d/foo": {contents: []byte("same"), mode: 0o644},
	}

	t.Run("owned/update", func(t *testing.T) {
		m := manifest.New()
		m.PutActive("/etc/magus.d/foo", manifest.KindFile, "sha256:x", manifest.OriginCreate, time.Now())
		plan, _ := Compute(mkIR(), m, fs)
		a := findAction(t, plan, "/etc/magus.d/foo")
		if a.Action != ActionUpdate {
			t.Errorf("Action = %s (%s)", a.Action, a.Reason)
		}
	})
	t.Run("unowned/conflict", func(t *testing.T) {
		plan, _ := Compute(mkIR(), manifest.New(), fs)
		a := findAction(t, plan, "/etc/magus.d/foo")
		if a.Action != ActionConflict {
			t.Errorf("Action = %s (%s)", a.Action, a.Reason)
		}
	})
}

func TestDelete(t *testing.T) {
	// Manifest owns a path, IR doesn't declare it, file exists → delete.
	in := &ir.IR{}
	m := manifest.New()
	m.PutActive("/etc/magus.d/gone", manifest.KindFile, "sha256:x", manifest.OriginCreate, time.Now())
	fs := memFS{
		"/etc/magus.d/gone": {contents: []byte("x"), mode: 0o644},
	}
	plan, _ := Compute(in, m, fs)
	a := findAction(t, plan, "/etc/magus.d/gone")
	if a.Action != ActionDelete {
		t.Errorf("Action = %s (%s), want delete", a.Action, a.Reason)
	}
}

func TestStaleClean(t *testing.T) {
	// Manifest owns a path, IR doesn't declare it, file is gone → stale-clean.
	in := &ir.IR{}
	m := manifest.New()
	m.PutActive("/etc/magus.d/gone", manifest.KindFile, "sha256:x", manifest.OriginCreate, time.Now())
	plan, _ := Compute(in, m, memFS{})
	a := findAction(t, plan, "/etc/magus.d/gone")
	if a.Action != ActionCleanup {
		t.Errorf("Action = %s (%s), want stale-clean", a.Action, a.Reason)
	}
}

func TestOrphanedDominates(t *testing.T) {
	// Orphaned manifest entry: regardless of IR/disk state, action is
	// orphaned (skip + warn). Tests both branches: declared and undeclared.
	now := time.Now()

	t.Run("declared", func(t *testing.T) {
		in := &ir.IR{Files: []ir.File{
			{Path: "/etc/secret", Mode: 0o600, Contents: []byte("x")},
		}}
		m := manifest.New()
		m.PutActive("/etc/secret", manifest.KindFile, "sha256:x", manifest.OriginCreate, now)
		m.Orphan("/etc/secret", "policy deny", now)
		plan, _ := Compute(in, m, memFS{
			"/etc/secret": {contents: []byte("x"), mode: 0o600},
		})
		a := findAction(t, plan, "/etc/secret")
		if a.Action != ActionOrphaned {
			t.Errorf("Action = %s (%s)", a.Action, a.Reason)
		}
	})

	t.Run("undeclared", func(t *testing.T) {
		m := manifest.New()
		m.PutActive("/etc/secret", manifest.KindFile, "sha256:x", manifest.OriginCreate, now)
		m.Orphan("/etc/secret", "policy deny", now)
		plan, _ := Compute(&ir.IR{}, m, memFS{
			"/etc/secret": {contents: []byte("x"), mode: 0o600},
		})
		a := findAction(t, plan, "/etc/secret")
		if a.Action != ActionOrphaned {
			t.Errorf("Action = %s (%s)", a.Action, a.Reason)
		}
	})
}

func TestHasChanges(t *testing.T) {
	skipOnly := &Plan{Actions: []ResourceAction{
		{Action: ActionSkip}, {Action: ActionCleanup},
	}}
	if skipOnly.HasChanges() {
		t.Error("HasChanges should be false for skip-only plan")
	}
	withCreate := &Plan{Actions: []ResourceAction{{Action: ActionCreate}}}
	if !withCreate.HasChanges() {
		t.Error("HasChanges should be true for plan with create")
	}
}
