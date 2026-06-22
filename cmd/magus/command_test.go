package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitea.wabash.place/lab/magus-cli/internal/manifest"
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
	hash := hashContent([]byte("K=V\n"))
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
