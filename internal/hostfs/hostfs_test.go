package hostfs

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWriteFileAtomicAndMode(t *testing.T) {
	dir := t.TempDir()
	w := OS()
	p := filepath.Join(dir, "sub", "f.conf") // parent auto-created
	if err := w.WriteFile(p, []byte("hello\n"), 0o640, nil, nil); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := w.ReadFile(p)
	if err != nil || string(got) != "hello\n" {
		t.Fatalf("ReadFile = %q, %v", got, err)
	}
	st, _ := w.Stat(p)
	if st.Mode != 0o640 {
		t.Errorf("mode = %#o, want 0640", st.Mode)
	}
	// No leftover tmp file.
	if _, err := os.Lstat(p + ".magus.tmp"); !os.IsNotExist(err) {
		t.Errorf("tmp file lingered")
	}
}

// TestWriteReplacesSymlinkNotTarget proves the atomic write never writes THROUGH
// a symlink at the destination: rename replaces the link with our file, leaving
// the link's old target untouched.
func TestWriteReplacesSymlinkNotTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "outside.txt")
	if err := os.WriteFile(target, []byte("ORIGINAL\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.conf")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if err := OS().WriteFile(link, []byte("NEW\n"), 0o644, nil, nil); err != nil {
		t.Fatalf("WriteFile through symlink path: %v", err)
	}
	// The symlink's old target must be untouched...
	if b, _ := os.ReadFile(target); string(b) != "ORIGINAL\n" {
		t.Errorf("write leaked through symlink to target: %q", b)
	}
	// ...and the link path is now a regular file with the new content.
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Errorf("link is still a symlink; rename should have replaced it")
	}
	if b, _ := os.ReadFile(link); string(b) != "NEW\n" {
		t.Errorf("link content = %q, want NEW", b)
	}
}

func TestResolvePathSymlinkedParentEscapes(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(dir, "outside")
	roots := filepath.Join(dir, "roots")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(roots, 0o755); err != nil {
		t.Fatal(err)
	}
	// roots/evil -> ../outside : a symlinked "child" of an allowed root.
	if err := os.Symlink(outside, filepath.Join(roots, "evil")); err != nil {
		t.Fatal(err)
	}

	resolved, err := OS().(Resolver).ResolvePath(filepath.Join(roots, "evil", "newfile"))
	if err != nil {
		t.Fatalf("ResolvePath: %v", err)
	}
	want := filepath.Join(outside, "newfile")
	// EvalSymlinks may prepend /private on macOS; compare suffix semantics via
	// resolving the expected target too.
	wantResolved, _ := filepath.EvalSymlinks(outside)
	if resolved != want && resolved != filepath.Join(wantResolved, "newfile") {
		t.Errorf("ResolvePath = %q, want it to escape to %q", resolved, want)
	}
}

func TestResolvePathMissingLeafNoError(t *testing.T) {
	dir := t.TempDir()
	resolved, err := OS().(Resolver).ResolvePath(filepath.Join(dir, "does-not-exist"))
	if err != nil {
		t.Fatalf("missing leaf should not error: %v", err)
	}
	if filepath.Base(resolved) != "does-not-exist" {
		t.Errorf("resolved = %q, want leaf preserved", resolved)
	}
}

func TestRemoveMissingIsNoError(t *testing.T) {
	if err := OS().Remove(filepath.Join(t.TempDir(), "nope")); err != nil {
		t.Errorf("Remove of missing path: %v", err)
	}
}

// TestChownToSelf exercises the ownership code paths without root by chowning
// to the current uid/gid (always permitted). Covers WriteFile's chown branch,
// Mkdir's chown, and the standalone Chown, plus the nil no-op path.
func TestChownToSelf(t *testing.T) {
	dir := t.TempDir()
	w := OS()
	uid, gid := os.Getuid(), os.Getgid()

	f := filepath.Join(dir, "owned.conf")
	if err := w.WriteFile(f, []byte("x"), 0o644, &uid, &gid); err != nil {
		t.Fatalf("WriteFile with ownership: %v", err)
	}
	if st, _ := w.Stat(f); st.UID != uid || st.GID != gid {
		t.Errorf("owner = %d:%d, want %d:%d", st.UID, st.GID, uid, gid)
	}

	d := filepath.Join(dir, "owned-dir")
	if err := w.Mkdir(d, 0o755, &uid, &gid); err != nil {
		t.Fatalf("Mkdir with ownership: %v", err)
	}

	if err := w.Chown(f, &uid, &gid); err != nil {
		t.Errorf("Chown to self: %v", err)
	}
	// nil/nil is a no-op and must not error.
	if err := w.Chown(f, nil, nil); err != nil {
		t.Errorf("Chown(nil,nil): %v", err)
	}
}

// TestWriteFileOwnsCreatedParents proves the fix the live rootless run demanded:
// writing an owned file deep under an existing dir chowns the parent dirs magus
// CREATES to the file's owner, but never touches the pre-existing ancestor (the
// useradd-made home). Uses self uid so the chown is permitted unprivileged.
func TestWriteFileOwnsCreatedParents(t *testing.T) {
	base := t.TempDir() // stands in for the principal's home: pre-exists, must be left alone
	baseBefore, _ := os.Stat(base)
	uid, gid := os.Getuid(), os.Getgid()
	w := OS()

	p := filepath.Join(base, ".config", "containers", "systemd", "argusd.container")
	if err := w.WriteFile(p, []byte("[Container]\n"), 0o644, &uid, &gid); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Every created parent under base is owned by the file's owner.
	for _, d := range []string{".config", ".config/containers", ".config/containers/systemd"} {
		st, err := os.Stat(filepath.Join(base, d))
		if err != nil {
			t.Fatalf("stat created parent %s: %v", d, err)
		}
		sys := st.Sys().(*syscall.Stat_t)
		if int(sys.Uid) != uid {
			t.Errorf("created parent %s uid = %d, want %d", d, sys.Uid, uid)
		}
	}
	// The pre-existing base is untouched (same inode — not recreated/rechowned).
	baseAfter, _ := os.Stat(base)
	if baseBefore.Sys().(*syscall.Stat_t).Ino != baseAfter.Sys().(*syscall.Stat_t).Ino {
		t.Errorf("pre-existing ancestor was disturbed")
	}

	// Unowned write (nil uid) still works and creates parents, no chown.
	p2 := filepath.Join(base, "sys", "a", "b.conf")
	if err := w.WriteFile(p2, []byte("x"), 0o644, nil, nil); err != nil {
		t.Fatalf("unowned WriteFile: %v", err)
	}
	if _, err := os.Stat(p2); err != nil {
		t.Errorf("unowned nested write did not create parents: %v", err)
	}
}

func TestChmodChangesMode(t *testing.T) {
	dir := t.TempDir()
	w := OS()
	p := filepath.Join(dir, "f")
	if err := w.WriteFile(p, []byte("x"), 0o600, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Chmod(p, 0o640); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if st, _ := w.Stat(p); st.Mode != 0o640 {
		t.Errorf("mode = %#o, want 0640", st.Mode)
	}
}

func TestStatMissingNotError(t *testing.T) {
	st, err := OS().Stat(filepath.Join(t.TempDir(), "absent"))
	if err != nil {
		t.Fatalf("Stat of missing path errored: %v", err)
	}
	if st.Exists {
		t.Errorf("missing path reported as existing")
	}
}

func TestMkdirModeAndIdempotent(t *testing.T) {
	dir := t.TempDir()
	w := OS()
	p := filepath.Join(dir, "d")
	if err := w.Mkdir(p, 0o750, nil, nil); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if st, _ := w.Stat(p); st.Mode != 0o750 {
		t.Errorf("mode = %#o, want 0750", st.Mode)
	}
	// Idempotent: a second Mkdir of an existing dir is not an error.
	if err := w.Mkdir(p, 0o750, nil, nil); err != nil {
		t.Errorf("second Mkdir: %v", err)
	}
}
