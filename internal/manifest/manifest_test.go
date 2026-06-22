package manifest

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadMissingReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	m, err := Load(filepath.Join(dir, "missing.json"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if m.Version != CurrentVersion {
		t.Errorf("Version = %d, want %d", m.Version, CurrentVersion)
	}
	if len(m.Resources) != 0 {
		t.Errorf("Resources should be empty, got %v", m.Resources)
	}
}

func TestLoadRejectsWrongVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, []byte(`{"version":99,"resources":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("Load: want error on version mismatch, got nil")
	}
}

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	m := New()
	now := time.Date(2026, 5, 1, 18, 30, 0, 0, time.UTC)
	m.PutActive("/etc/magus.d/foo.env", KindFile, "sha256:abc", OriginCreate, now)
	m.PutActive("/etc/magus.d/bar.env", KindFile, "sha256:def", OriginAdopt, now)
	m.Orphan("/etc/magus.d/bar.env", "policy deny", now)

	if err := m.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !loaded.Owns("/etc/magus.d/foo.env") {
		t.Error("foo.env should be owned (active)")
	}
	if loaded.Owns("/etc/magus.d/bar.env") {
		t.Error("bar.env should NOT be owned (orphaned)")
	}
	r, ok := loaded.Get("/etc/magus.d/bar.env")
	if !ok {
		t.Fatal("bar.env should still exist in manifest as orphaned")
	}
	if r.State != StateOrphaned {
		t.Errorf("bar.env state = %s, want orphaned", r.State)
	}
	if r.OrphanedReason != "policy deny" {
		t.Errorf("bar.env orphaned_reason = %q", r.OrphanedReason)
	}
}

func TestSaveAtomic(t *testing.T) {
	// After Save, the .magus.tmp file should not be left behind.
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	m := New()
	m.PutActive("/x", KindFile, "sha256:abc", OriginCreate, time.Now())
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".magus.tmp"); !os.IsNotExist(err) {
		t.Errorf("tmp file should be gone after Save, stat: %v", err)
	}
}

func TestDeleteRemovesEntry(t *testing.T) {
	m := New()
	m.PutActive("/etc/core/a", KindFile, "h", OriginCreate, time.Unix(1, 0))
	if !m.Owns("/etc/core/a") {
		t.Fatal("precondition: should own /etc/core/a")
	}
	m.Delete("/etc/core/a")
	if _, ok := m.Get("/etc/core/a"); ok {
		t.Errorf("Delete left the entry behind")
	}
	// Deleting a missing path is a no-op, not a panic.
	m.Delete("/nope")
}

func TestLoadRejectsCorruptJSON(t *testing.T) {
	p := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Errorf("Load should reject corrupt JSON")
	}
}

func TestLoadCoercesEmptyKind(t *testing.T) {
	p := filepath.Join(t.TempDir(), "manifest.json")
	// A pre-Kind manifest entry (no "kind") must coerce to KindFile.
	js := `{"version":1,"resources":{"/x":{"state":"active","hash":"h","applied_at":"2026-01-01T00:00:00Z","origin":"create"}}}`
	if err := os.WriteFile(p, []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := m.Get("/x"); e.Kind != KindFile {
		t.Errorf("empty kind coerced to %q, want file", e.Kind)
	}
}

func TestSaveCreatesDirAndReloads(t *testing.T) {
	// Save into a not-yet-existing directory; it must be created, and the
	// written file must reload to an equivalent manifest at mode 0600.
	p := filepath.Join(t.TempDir(), "sub", "deep", "manifest.json")
	m := New()
	m.PutActive("/etc/core/a", KindUnit, "h", OriginAdopt, time.Unix(5, 0).UTC())
	if err := m.Save(p); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("manifest mode = %v, want 0600", fi.Mode().Perm())
	}
	m2, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := m2.Get("/etc/core/a"); !ok || e.Kind != KindUnit || e.Origin != OriginAdopt {
		t.Errorf("reloaded entry wrong: %+v", e)
	}
}

func TestOrphanMissingPathNoop(t *testing.T) {
	m := New()
	m.Orphan("/absent", "reason", time.Unix(1, 0)) // must not panic or create
	if _, ok := m.Get("/absent"); ok {
		t.Errorf("Orphan created an entry for a missing path")
	}
}
