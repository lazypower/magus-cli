package policy

import (
	"testing"
	"time"

	"gitea.wabash.place/lab/magus-cli/internal/manifest"
)

func TestOrphanDeniedTransitionsNewlyDeniedOwnedPath(t *testing.T) {
	p := mustLoad(t, `
version: 1
file_roots: ["/etc/core"]
unit_patterns: ["magus-*"]
deny:
  paths: ["/etc/core/secret.env"]
`)
	m := manifest.New()
	now := time.Unix(1000, 0).UTC()
	m.PutActive("/etc/core/secret.env", manifest.KindFile, "sha256:x", manifest.OriginCreate, now)
	m.PutActive("/etc/core/ok.conf", manifest.KindFile, "sha256:y", manifest.OriginCreate, now)
	// Owned but now outside file_roots (root narrowed away).
	m.PutActive("/var/data/legacy", manifest.KindFile, "sha256:z", manifest.OriginCreate, now)

	got := OrphanDenied(p, m, time.Unix(2000, 0).UTC())

	if r, _ := m.Get("/etc/core/secret.env"); r.State != manifest.StateOrphaned {
		t.Errorf("explicitly-denied owned path not orphaned: %+v", r)
	}
	if r, _ := m.Get("/var/data/legacy"); r.State != manifest.StateOrphaned {
		t.Errorf("owned path outside file_roots not orphaned: %+v", r)
	}
	if r, _ := m.Get("/etc/core/ok.conf"); r.State != manifest.StateActive {
		t.Errorf("permitted owned path should stay active: %+v", r)
	}
	if len(got) != 2 {
		t.Errorf("returned %d orphaned paths, want 2: %v", len(got), got)
	}
}

func TestOrphanDeniedSkipsAlreadyOrphaned(t *testing.T) {
	p := mustLoad(t, `
version: 1
file_roots: ["/etc/core"]
unit_patterns: ["magus-*"]
deny:
  paths: ["/etc/core/secret.env"]
`)
	m := manifest.New()
	now := time.Unix(1000, 0).UTC()
	m.PutActive("/etc/core/secret.env", manifest.KindFile, "sha256:x", manifest.OriginCreate, now)
	m.Orphan("/etc/core/secret.env", "policy deny: prior", time.Unix(1500, 0).UTC())

	got := OrphanDenied(p, m, time.Unix(2000, 0).UTC())
	if len(got) != 0 {
		t.Errorf("already-orphaned entry re-transitioned: %v", got)
	}
	// orphaned_at must be preserved (sticky), not bumped.
	r, _ := m.Get("/etc/core/secret.env")
	if r.OrphanedAt == nil || !r.OrphanedAt.Equal(time.Unix(1500, 0).UTC()) {
		t.Errorf("orphaned_at was not preserved: %+v", r.OrphanedAt)
	}
}
