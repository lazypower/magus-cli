package apply

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lazypower/magus-cli/internal/diff"
	"github.com/lazypower/magus-cli/internal/ir"
	"github.com/lazypower/magus-cli/internal/manifest"
	"github.com/lazypower/magus-cli/internal/systemd"
)

// envConsumerBody is a unit that reads its environment from an EnvironmentFile=
// magus also manages — the notify relationship the graph walk propagates.
const envConsumerBody = "[Unit]\nDescription=env consumer\n[Service]\nEnvironmentFile=/etc/core/app.env\nExecStart=/bin/foo\n[Install]\nWantedBy=multi-user.target\n"

// TestNotifyRestartsConsumerOnEnvFileChange proves the gap B3 closes: when only
// an EnvironmentFile= changes (the consuming unit's own body is untouched), the
// active consumer is restarted so it re-reads the new environment. The pre-graph
// phase pipeline restarted only on a unit's OWN content change and would have
// left the consumer running with stale config.
func TestNotifyRestartsConsumerOnEnvFileChange(t *testing.T) {
	w := newMemWriter()
	sd := systemd.NewFake()
	sd.SetEnablement("magus-app.service", systemd.EnablementEnabled)
	sd.SetActive("magus-app.service", true)

	// The unit body is already on disk, owned, and byte-identical to the IR →
	// it plans as an unchanged skip (no daemon-reload, no own-content restart).
	unitPath := diff.UnitPath("magus-app.service")
	w.preload(unitPath, memFile{contents: []byte(envConsumerBody), mode: 0o644})
	// The EnvironmentFile is owned with the OLD content; the IR carries NEW.
	w.preload("/etc/core/app.env", memFile{contents: []byte("FOO=old\n"), mode: 0o644})

	m := manifest.New()
	m.PutActive(unitPath, manifest.KindUnit, diff.HashContent([]byte(envConsumerBody), diff.KindUnit), manifest.OriginCreate, time.Now())
	m.PutActive("/etc/core/app.env", manifest.KindFile, diff.HashContent([]byte("FOO=old\n"), diff.KindFile), manifest.OriginCreate, time.Now())

	in := &ir.IR{
		Files: []ir.File{{Path: "/etc/core/app.env", Mode: 0o644, Contents: []byte("FOO=new\n")}},
		Units: []ir.Unit{{Name: "magus-app.service", Contents: envConsumerBody}}, // Enabled nil: extend, don't touch enablement
	}

	plan, _ := diff.Compute(in, m, w)
	r := Apply(plan, in, w, m, sd, time.Now())

	if r.ExitCode() != 0 {
		t.Fatalf("exit = %d; outcomes: %+v", r.ExitCode(), r.Outcomes)
	}
	if !containsCall(sd.Calls(), "Restart(magus-app.service)") {
		t.Fatalf("env-file change did not restart the consumer (the notify gap): %v", sd.Calls())
	}
	// The restart outcome must attribute itself to the EnvironmentFile, so an
	// operator can see the config change was the cause, not a phantom body edit.
	var found bool
	for _, oc := range r.Outcomes {
		if oc.Path == "magus-app.service" && strings.Contains(oc.Reason, "EnvironmentFile") {
			found = true
		}
	}
	if !found {
		t.Errorf("restart not attributed to EnvironmentFile=: %+v", r.Outcomes)
	}
}

// TestNotifyQuietWhenEnvFileUnchanged is the control: identical topology, but the
// EnvironmentFile is already in its desired state (unchanged). No notify fires,
// so the consumer is NOT restarted — restart is driven by a real change, not by
// the mere presence of the notify edge.
func TestNotifyQuietWhenEnvFileUnchanged(t *testing.T) {
	w := newMemWriter()
	sd := systemd.NewFake()
	sd.SetEnablement("magus-app.service", systemd.EnablementEnabled)
	sd.SetActive("magus-app.service", true)

	unitPath := diff.UnitPath("magus-app.service")
	w.preload(unitPath, memFile{contents: []byte(envConsumerBody), mode: 0o644})
	w.preload("/etc/core/app.env", memFile{contents: []byte("FOO=same\n"), mode: 0o644})

	m := manifest.New()
	m.PutActive(unitPath, manifest.KindUnit, diff.HashContent([]byte(envConsumerBody), diff.KindUnit), manifest.OriginCreate, time.Now())
	m.PutActive("/etc/core/app.env", manifest.KindFile, diff.HashContent([]byte("FOO=same\n"), diff.KindFile), manifest.OriginCreate, time.Now())

	in := &ir.IR{
		Files: []ir.File{{Path: "/etc/core/app.env", Mode: 0o644, Contents: []byte("FOO=same\n")}},
		Units: []ir.Unit{{Name: "magus-app.service", Contents: envConsumerBody}},
	}

	plan, _ := diff.Compute(in, m, w)
	r := Apply(plan, in, w, m, sd, time.Now())

	if r.ExitCode() != 0 {
		t.Fatalf("exit = %d; outcomes: %+v", r.ExitCode(), r.Outcomes)
	}
	for _, c := range sd.Calls() {
		if c == "Restart(magus-app.service)" {
			t.Errorf("consumer restarted with no env change (notify must require a real change): %v", sd.Calls())
		}
	}
}

// TestRequireCascadeSkipsDependentOnFailedParent proves the honest fail-closed
// cascade: a directory whose creation fails must skip the file it contains
// (containment is a require edge) rather than attempt a write into a directory
// that isn't there — surfaced as "dependency <dir> failed", never a green lie.
func TestRequireCascadeSkipsDependentOnFailedParent(t *testing.T) {
	w := newMemWriter()
	in := &ir.IR{
		Directories: []ir.Directory{{Path: "/etc/core/sub", Mode: 0o750}},
		Files:       []ir.File{{Path: "/etc/core/sub/f", Mode: 0o644, Contents: []byte("data")}},
	}
	// The directory create fails; the contained file must not be attempted.
	w.injectError("/etc/core/sub", errors.New("mkdir: read-only file system"))

	plan, _ := diff.Compute(in, manifest.New(), w)
	m := manifest.New()
	r := Apply(plan, in, w, m, systemd.NewFake(), time.Now())

	if _, ok := w.files["/etc/core/sub/f"]; ok {
		t.Errorf("file was written into a directory whose create failed")
	}
	var dirErrored, fileSkipped bool
	for _, oc := range r.Outcomes {
		if oc.Path == "/etc/core/sub" && oc.Status == StatusErrored {
			dirErrored = true
		}
		if oc.Path == "/etc/core/sub/f" && oc.Status == StatusSkipped &&
			strings.Contains(oc.Reason, "dependency /etc/core/sub failed") {
			fileSkipped = true
		}
	}
	if !dirErrored {
		t.Errorf("directory create should have errored: %+v", r.Outcomes)
	}
	if !fileSkipped {
		t.Errorf("contained file should skip with a dependency-failed reason: %+v", r.Outcomes)
	}
	if m.Owns("/etc/core/sub/f") {
		t.Errorf("dependency-skipped file must not be recorded as owned")
	}
	if r.ExitCode() != 1 {
		t.Errorf("exit = %d, want 1 (error dominates the dependency skip)", r.ExitCode())
	}
}

// TestReloadFailureCascadesToServices proves the reload barrier's require edge:
// if the single daemon-reload fails, the services that depend on it are skipped
// honestly ("dependency daemon-reload failed") instead of being enabled/started
// against unit files systemd never loaded.
func TestReloadFailureCascadesToServices(t *testing.T) {
	w := newMemWriter()
	sd := systemd.NewFake()
	sd.FailNext("DaemonReload", errors.New("reload refused"))

	in := &ir.IR{Units: []ir.Unit{
		{Name: "magus-a.service", Enabled: boolPtr(true), Contents: sampleUnitBody},
		{Name: "magus-b.service", Enabled: boolPtr(true), Contents: sampleUnitBody},
	}}
	plan, _ := diff.Compute(in, manifest.New(), w)
	r := Apply(plan, in, w, manifest.New(), sd, time.Now())

	// The bodies wrote fine; the reload failed; both services must skip.
	for _, c := range sd.Calls() {
		if strings.HasPrefix(c, "EnableNow(") || strings.HasPrefix(c, "Enable(") {
			t.Errorf("service enabled despite a failed daemon-reload: %v", sd.Calls())
		}
	}
	var reloadErrored, aSkipped, bSkipped bool
	for _, oc := range r.Outcomes {
		if oc.Path == "daemon-reload" && oc.Status == StatusErrored {
			reloadErrored = true
		}
		if oc.Status == StatusSkipped && strings.Contains(oc.Reason, "dependency daemon-reload failed") {
			switch oc.Path {
			case "magus-a.service":
				aSkipped = true
			case "magus-b.service":
				bSkipped = true
			}
		}
	}
	if !reloadErrored {
		t.Errorf("daemon-reload should have errored: %+v", r.Outcomes)
	}
	if !aSkipped || !bSkipped {
		t.Errorf("both services should skip on the failed reload: %+v", r.Outcomes)
	}
	if r.ExitCode() != 1 {
		t.Errorf("exit = %d, want 1 (reload error dominates)", r.ExitCode())
	}
}

// TestCyclicGraphFailsClosed proves apply refuses a plan whose derived graph has
// a cycle (here two containers each declaring the other as their Network=): it
// applies nothing and surfaces the cycle rather than pick an arbitrary order.
func TestCyclicGraphFailsClosed(t *testing.T) {
	w := newMemWriter()
	aBody := []byte("[Container]\nImage=x\nNetwork=b.container\n")
	bBody := []byte("[Container]\nImage=x\nNetwork=a.container\n")
	in := &ir.IR{Quadlets: []ir.Quadlet{
		{Path: "/etc/containers/systemd/a.container", Name: "a.container", Mode: 0o644, Contents: aBody},
		{Path: "/etc/containers/systemd/b.container", Name: "b.container", Mode: 0o644, Contents: bBody},
	}}

	plan, _ := diff.Compute(in, manifest.New(), w)
	m := manifest.New()
	r := Apply(plan, in, w, m, systemd.NewFake(), time.Now())

	if r.ExitCode() != 1 {
		t.Fatalf("exit = %d, want 1 (cyclic graph is input-bad)", r.ExitCode())
	}
	// Nothing was written — fail closed, not half-applied.
	if _, ok := w.files["/etc/containers/systemd/a.container"]; ok {
		t.Errorf("cyclic plan wrote a.container; apply must be all-or-nothing on a cycle")
	}
	var cycleReported bool
	for _, oc := range r.Outcomes {
		if oc.Status == StatusErrored && oc.Err != nil && strings.Contains(oc.Err.Error(), "dependency cycle") {
			cycleReported = true
		}
	}
	if !cycleReported {
		t.Errorf("expected a dependency-cycle error outcome, got: %+v", r.Outcomes)
	}
}
