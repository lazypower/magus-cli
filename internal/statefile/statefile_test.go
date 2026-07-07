package statefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAtomicRoundTrip(t *testing.T) {
	// A not-yet-existing parent dir is created.
	p := filepath.Join(t.TempDir(), "var", "manifest.json")
	data := []byte("{\"version\":1}\n")

	if err := WriteAtomic(p, data); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("content = %q, want %q", got, data)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
	// No temp file is left behind after a successful write.
	if _, err := os.Stat(p + ".magus.tmp"); !os.IsNotExist(err) {
		t.Errorf("tmp file left behind: %v", err)
	}
}

func TestWriteAtomicOverwrites(t *testing.T) {
	p := filepath.Join(t.TempDir(), "status.json")
	if err := WriteAtomic(p, []byte("first")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := WriteAtomic(p, []byte("second")); err != nil {
		t.Fatalf("second write: %v", err)
	}
	got, _ := os.ReadFile(p)
	if string(got) != "second" {
		t.Errorf("content = %q, want second", got)
	}
}

// A stale tmp left by a crashed prior write (or a planted symlink) is dropped
// and replaced rather than written through.
func TestWriteAtomicClearsStaleTmp(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(p+".magus.tmp", []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(p, []byte("fresh")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, _ := os.ReadFile(p)
	if string(got) != "fresh" {
		t.Errorf("content = %q, want fresh", got)
	}
}

// MkdirAll fails when an ancestor of the target is a regular file.
func TestWriteAtomicMkdirFails(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "afile")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// target's parent (blocker) is a file, so MkdirAll can't create the dir.
	if err := WriteAtomic(filepath.Join(blocker, "manifest.json"), []byte("y")); err == nil {
		t.Error("expected error when an ancestor is a file")
	}
}

// The tmp open fails when a non-removable entry (a non-empty directory) already
// sits at the ".magus.tmp" path.
func TestWriteAtomicTmpOpenFails(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "manifest.json")
	tmpDir := p + ".magus.tmp"
	if err := os.Mkdir(tmpDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A child makes the dir non-empty so the pre-write os.Remove can't clear it.
	if err := os.WriteFile(filepath.Join(tmpDir, "child"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(p, []byte("y")); err == nil {
		t.Error("expected error when tmp path is an unremovable directory")
	}
}

// The final rename fails when the destination is an existing directory.
func TestWriteAtomicRenameFails(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dest")
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(p, []byte("y")); err == nil {
		t.Error("expected error renaming onto an existing directory")
	}
	// The temp file must not be left behind on a failed rename.
	if _, err := os.Stat(p + ".magus.tmp"); !os.IsNotExist(err) {
		t.Errorf("tmp file left behind after failed rename: %v", err)
	}
}
