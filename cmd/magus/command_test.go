package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lazypower/magus-cli/internal/diff"
	"github.com/lazypower/magus-cli/internal/lock"
	"github.com/lazypower/magus-cli/internal/manifest"
)

// tempRoot returns a symlink-resolved temp dir, usable as a file_root without
// tripping symlink containment (macOS /var -> /private/var).
func tempRoot(t *testing.T) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func captureStdout(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	code := fn()
	_ = w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return string(out), code
}

// fixture sets up a temp file_root + policy and returns paths for a file-only
// scenario (no systemd needed).
type fixture struct {
	root, policy, butane, manifest, status string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	root := tempRoot(t)
	dir := tempRoot(t)
	f := fixture{
		root:     root,
		policy:   filepath.Join(dir, "policy.yaml"),
		butane:   filepath.Join(dir, "host.bu"),
		manifest: filepath.Join(dir, "manifest.json"),
		status:   filepath.Join(dir, "status.json"),
	}
	writeFile(t, f.policy, "version: 1\nfile_roots: [\""+root+"\"]\nunit_patterns: [\"magus-*\"]\n")
	return f
}

func (f fixture) butaneFile(t *testing.T, body string) {
	writeFile(t, f.butane, "variant: fcos\nversion: \"1.6.0\"\n"+body)
}

func TestRunValidate(t *testing.T) {
	f := newFixture(t)
	f.butaneFile(t, "storage:\n  files:\n    - path: "+f.root+"/ok.conf\n      contents: { inline: \"hi\\n\" }\n")
	if code := runValidate([]string{"--policy", f.policy, f.butane}); code != 0 {
		t.Errorf("valid: exit %d, want 0", code)
	}
	// denied path → exit 1
	f.butaneFile(t, "storage:\n  files:\n    - path: /etc/shadow\n      contents: { inline: \"x\\n\" }\n")
	if code := runValidate([]string{"--policy", f.policy, f.butane}); code != 1 {
		t.Errorf("denied: exit %d, want 1", code)
	}
	// missing butane → exit 1
	if code := runValidate([]string{"--policy", f.policy, "/no/such.bu"}); code != 1 {
		t.Errorf("missing butane: exit %d, want 1", code)
	}
}

func TestRunPlanApplyStatusLifecycle(t *testing.T) {
	f := newFixture(t)
	f.butaneFile(t, "storage:\n  files:\n    - path: "+f.root+"/app.conf\n      contents: { inline: \"hello\\n\" }\n")

	// plan: pending create → exit 2
	out, code := captureStdout(t, func() int {
		return runPlan([]string{"--policy", f.policy, "--manifest", f.manifest, f.butane})
	})
	if code != 2 || !strings.Contains(out, "[create]") {
		t.Fatalf("plan pending: exit %d\n%s", code, out)
	}

	// apply --yes → exit 0, file written, manifest + status created
	_, code = captureStdout(t, func() int {
		return runApply([]string{"--yes", "--policy", f.policy, "--manifest", f.manifest, "--status", f.status, f.butane})
	})
	if code != 0 {
		t.Fatalf("apply: exit %d", code)
	}
	if b, _ := os.ReadFile(f.root + "/app.conf"); string(b) != "hello\n" {
		t.Errorf("file not written: %q", b)
	}
	if _, err := os.Stat(f.manifest); err != nil {
		t.Errorf("manifest not written: %v", err)
	}
	if _, err := os.Stat(f.status); err != nil {
		t.Errorf("status not written: %v", err)
	}

	// plan again: clean → exit 0
	_, code = captureStdout(t, func() int {
		return runPlan([]string{"--policy", f.policy, "--manifest", f.manifest, f.butane})
	})
	if code != 0 {
		t.Errorf("clean plan: exit %d, want 0", code)
	}

	// status --json reports the managed file
	sout, scode := captureStdout(t, func() int {
		return runStatus([]string{"--json", "--manifest", f.manifest, "--status", f.status})
	})
	if scode != 0 {
		t.Fatalf("status: exit %d", scode)
	}
	var report struct {
		Managed int               `json:"managed_resources"`
		Files   map[string]string `json:"files"`
	}
	if err := json.Unmarshal([]byte(sout), &report); err != nil {
		t.Fatalf("status json: %v\n%s", err, sout)
	}
	if report.Managed != 1 || report.Files[f.root+"/app.conf"] != "ok" {
		t.Errorf("status wrong: %+v", report)
	}
}

func TestRunApplyConflict(t *testing.T) {
	f := newFixture(t)
	writeFile(t, f.root+"/c.env", "OLD=1\n") // unowned
	f.butaneFile(t, "storage:\n  files:\n    - path: "+f.root+"/c.env\n      contents: { inline: \"NEW=1\\n\" }\n")

	_, code := captureStdout(t, func() int {
		return runApply([]string{"--yes", "--policy", f.policy, "--manifest", f.manifest, "--status", f.status, f.butane})
	})
	if code != 2 {
		t.Errorf("conflict apply: exit %d, want 2", code)
	}
	if b, _ := os.ReadFile(f.root + "/c.env"); string(b) != "OLD=1\n" {
		t.Errorf("conflict file overwritten: %q", b)
	}
}

func TestRunApplyLockBusy(t *testing.T) {
	// D4: while another operation holds the manifest lock, apply fails fast
	// rather than racing into a concurrent read-modify-write.
	f := newFixture(t)
	f.butaneFile(t, "storage:\n  files:\n    - path: "+f.root+"/a.conf\n      contents: { inline: \"x\\n\" }\n")

	release, err := lock.Acquire(f.manifest)
	if err != nil {
		t.Fatalf("pre-acquire lock: %v", err)
	}
	defer func() { _ = release() }()

	_, code := captureStdout(t, func() int {
		return runApply([]string{"--yes", "--policy", f.policy, "--manifest", f.manifest, "--status", f.status, f.butane})
	})
	if code != 1 {
		t.Errorf("apply under contended lock: exit %d, want 1", code)
	}
	// Nothing should have been written — apply never got past the lock.
	if _, err := os.Stat(f.root + "/a.conf"); err == nil {
		t.Error("apply wrote a file despite the lock being held")
	}
}

func TestReservedStatusPathConsistentAcrossCommands(t *testing.T) {
	// UX8/D14: the reserved-path set is shared, so an IR declaring a relocated
	// --status file is rejected identically by validate, plan, and apply — plan
	// truthfully previews apply's gate instead of passing what apply refuses.
	f := newFixture(t)
	reloc := f.root + "/status.json" // inside file_roots, but reserved via --status
	f.butaneFile(t, "storage:\n  files:\n    - path: "+reloc+"\n      contents: { inline: \"x\\n\" }\n")
	common := []string{"--policy", f.policy, "--manifest", f.manifest, "--status", reloc}

	if code := runValidate(append(append([]string{}, common...), f.butane)); code != 1 {
		t.Errorf("validate should reject an IR declaring the reserved status path: exit %d", code)
	}
	_, code := captureStdout(t, func() int {
		return runPlan(append(append([]string{}, common...), f.butane))
	})
	if code != 1 {
		t.Errorf("plan should reject an IR declaring the reserved status path: exit %d", code)
	}
	_, code = captureStdout(t, func() int {
		return runApply(append(append([]string{"--yes"}, common...), f.butane))
	})
	if code != 1 {
		t.Errorf("apply should reject an IR declaring the reserved status path: exit %d", code)
	}
}

func TestRunApplyDeclinedExitsTwo(t *testing.T) {
	// UX5: declining the confirmation with a pending change exits 2 (changes
	// pending), not 0 — a wrapper must tell "aborted" from "converged". In the
	// test harness os.Stdin is at EOF, which the confirm reads as a decline.
	f := newFixture(t)
	f.butaneFile(t, "storage:\n  files:\n    - path: "+f.root+"/a.conf\n      contents: { inline: \"x\\n\" }\n")

	_, code := captureStdout(t, func() int {
		// No --yes, so it prompts; stdin EOF → declined.
		return runApply([]string{"--policy", f.policy, "--manifest", f.manifest, "--status", f.status, f.butane})
	})
	if code != 2 {
		t.Errorf("declined apply: exit %d, want 2", code)
	}
	if _, err := os.Stat(f.root + "/a.conf"); err == nil {
		t.Error("declined apply should not have written the file")
	}
}

func TestRunApplyNothingToApply(t *testing.T) {
	f := newFixture(t)
	f.butaneFile(t, "storage:\n  files:\n    - path: "+f.root+"/a.conf\n      contents: { inline: \"x\\n\" }\n")
	apply := func() int {
		return runApply([]string{"--yes", "--policy", f.policy, "--manifest", f.manifest, "--status", f.status, f.butane})
	}
	captureStdout(t, apply) // first apply creates
	out, code := captureStdout(t, apply)
	if code != 0 || !strings.Contains(out, "Nothing to apply") {
		t.Errorf("second apply: exit %d\n%s", code, out)
	}
}

func TestRunAdopt(t *testing.T) {
	f := newFixture(t)
	writeFile(t, f.root+"/take.env", "OLD=1\n") // exists, differs, unowned
	f.butaneFile(t, "storage:\n  files:\n    - path: "+f.root+"/take.env\n      contents: { inline: \"NEW=1\\n\" }\n")

	_, code := captureStdout(t, func() int {
		return runAdopt([]string{"--yes", "--policy", f.policy, "--manifest", f.manifest, f.butane, f.root + "/take.env"})
	})
	if code != 0 {
		t.Fatalf("adopt: exit %d", code)
	}
	if b, _ := os.ReadFile(f.root + "/take.env"); string(b) != "NEW=1\n" {
		t.Errorf("adopt did not overwrite: %q", b)
	}
	m, _ := manifest.Load(f.manifest)
	if e, ok := m.Get(f.root + "/take.env"); !ok || e.Origin != manifest.OriginForceAdopt {
		t.Errorf("adopt did not record force-adopt: %+v", e)
	}
}

func TestRunReclaim(t *testing.T) {
	f := newFixture(t)
	writeFile(t, f.root+"/orph.env", "K=V\n")
	// Pre-build a manifest with the path orphaned, on-disk hash matching.
	m := manifest.New()
	hash := diff.HashContent([]byte("K=V\n"), diff.KindFile)
	m.PutActive(f.root+"/orph.env", manifest.KindFile, hash, manifest.OriginCreate, time.Unix(1, 0).UTC())
	m.Orphan(f.root+"/orph.env", "policy deny: prior", time.Unix(1, 0).UTC())
	if err := m.Save(f.manifest); err != nil {
		t.Fatal(err)
	}
	f.butaneFile(t, "storage:\n  files:\n    - path: "+f.root+"/orph.env\n      contents: { inline: \"K=V\\n\" }\n")

	_, code := captureStdout(t, func() int {
		return runReclaim([]string{"--yes", "--policy", f.policy, "--manifest", f.manifest, f.butane, f.root + "/orph.env"})
	})
	if code != 0 {
		t.Fatalf("reclaim: exit %d", code)
	}
	m2, _ := manifest.Load(f.manifest)
	if e, _ := m2.Get(f.root + "/orph.env"); e.State != manifest.StateActive {
		t.Errorf("reclaim did not reactivate: %+v", e)
	}
}

func TestRunReclaimDirectory(t *testing.T) {
	// D6: an orphaned directory must be reclaimable. Directories have no
	// content, so reclaim can't hash/ReadFile them — it re-activates directly.
	f := newFixture(t)
	dir := f.root + "/data"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	m := manifest.New()
	// Seed a STALE kind (file) on the orphaned entry; reclaim must record the
	// currently-declared kind (directory), not carry the stale one forward
	// (finding 3).
	m.PutActive(dir, manifest.KindFile, "sha256:dir", manifest.OriginCreate, time.Unix(1, 0).UTC())
	m.Orphan(dir, "policy deny: prior", time.Unix(1, 0).UTC())
	if err := m.Save(f.manifest); err != nil {
		t.Fatal(err)
	}
	f.butaneFile(t, "storage:\n  directories:\n    - path: "+dir+"\n      mode: 0755\n")

	_, code := captureStdout(t, func() int {
		return runReclaim([]string{"--yes", "--policy", f.policy, "--manifest", f.manifest, f.butane, dir})
	})
	if code != 0 {
		t.Fatalf("reclaim directory: exit %d", code)
	}
	m2, _ := manifest.Load(f.manifest)
	e, _ := m2.Get(dir)
	if e.State != manifest.StateActive {
		t.Errorf("reclaim did not reactivate directory: %+v", e)
	}
	if e.Kind != manifest.KindDirectory {
		t.Errorf("reclaim recorded kind %s, want directory (corrected from stale file kind)", e.Kind)
	}
}

func TestRunReclaimDirectoryDeclaredButFileOnDisk(t *testing.T) {
	// Codex round-2 residual: the target is declared as a directory but a regular
	// file sits on disk. reclaim must refuse rather than report success and
	// record a directory entry for a non-directory.
	f := newFixture(t)
	writeFile(t, f.root+"/data", "x\n") // a FILE, not a directory
	m := manifest.New()
	m.PutActive(f.root+"/data", manifest.KindFile, "sha256:dir", manifest.OriginCreate, time.Unix(1, 0).UTC())
	m.Orphan(f.root+"/data", "policy deny: prior", time.Unix(1, 0).UTC())
	if err := m.Save(f.manifest); err != nil {
		t.Fatal(err)
	}
	f.butaneFile(t, "storage:\n  directories:\n    - path: "+f.root+"/data\n      mode: 0755\n")

	_, code := captureStdout(t, func() int {
		return runReclaim([]string{"--yes", "--policy", f.policy, "--manifest", f.manifest, f.butane, f.root + "/data"})
	})
	if code != 1 {
		t.Errorf("reclaim of a dir-declared path that is a file: exit %d, want 1", code)
	}
}
