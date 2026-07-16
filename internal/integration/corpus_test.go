//go:build integration

package integration

import (
	"os"
	"strings"
	"testing"
	"time"
)

// The archetype corpus lives as real Butane files under corpus/ so it doubles as
// a capability corpus and as `magus graph` input. These tests drive each
// archetype through the graph-walk apply path (B3) against real systemd, proving
// plan / apply / status converge and — for archetype 4 — that an EnvironmentFile=
// change restarts its consumer (the gap the graph closes).

// corpusPolicy is the shared boundary for the corpus (corpus/policy.yaml).
func corpusPolicy(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("corpus/policy.yaml")
	if err != nil {
		t.Fatalf("read corpus policy: %v", err)
	}
	return string(b)
}

// corpusFile returns the contents of a corpus archetype by basename.
func corpusFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("corpus/" + name)
	if err != nil {
		t.Fatalf("read corpus/%s: %v", name, err)
	}
	return string(b)
}

// TestCorpusValidatesAndGraphs proves every archetype validates and derives an
// acyclic apply graph under the corpus policy, on real /etc (not the macOS
// symlinked layout). One container, all four archetypes.
func TestCorpusValidatesAndGraphs(t *testing.T) {
	c := setup(t, corpusPolicy(t))
	archetypes := []string{
		"01-files-tree.bu",
		"02-unit-dropin.bu",
		"03-quadlet-network.bu",
		"04-envfile-notify.bu",
	}
	for _, a := range archetypes {
		c.put("/host.bu", corpusFile(t, a))

		if out, code := c.magus("validate", "--policy", "/policy.yaml", "/host.bu"); code != 0 {
			t.Errorf("%s: validate exit %d\n%s", a, code, out)
		}
		// graph exits 0 only when the derived graph is acyclic.
		gout, gcode := c.magus("graph", "--policy", "/policy.yaml", "/host.bu")
		if gcode != 0 {
			t.Errorf("%s: graph exit %d (cyclic or input-bad)\n%s", a, gcode, gout)
		}
		if !strings.Contains(gout, "nodes") {
			t.Errorf("%s: graph produced no node summary:\n%s", a, gout)
		}
	}
}

// TestCorpusFilesTree drives archetype 1: a directory containment tree. It
// proves the `require` containment edges apply parent-before-child, every mode
// lands, and the whole tree is idempotent on a second apply.
func TestCorpusFilesTree(t *testing.T) {
	c := setup(t, corpusPolicy(t))
	bu := corpusFile(t, "01-files-tree.bu")

	// plan before apply: creates pending → exit 2.
	if out, code := c.plan(bu); code != 2 {
		t.Fatalf("plan (pending) exit %d, want 2\n%s", code, out)
	}

	if out, code := c.apply(bu); code != 0 {
		t.Fatalf("apply exit %d\n%s", code, out)
	}
	if m := c.mode("/etc/core/app"); m != "750" {
		t.Errorf("dir /etc/core/app mode = %s, want 750", m)
	}
	if m := c.mode("/etc/core/app/sub"); m != "755" {
		t.Errorf("dir /etc/core/app/sub mode = %s, want 755", m)
	}
	if got := c.readFile("/etc/core/app/config.conf"); !strings.Contains(got, "key=value") {
		t.Errorf("config.conf = %q", got)
	}
	if m := c.mode("/etc/core/app/sub/nested.conf"); m != "640" {
		t.Errorf("nested.conf mode = %s, want 640", m)
	}

	// Idempotence: a second apply is a clean no-op.
	if out, code := c.apply(bu); code != 0 || !strings.Contains(out, "Nothing to apply") {
		t.Errorf("second apply not a no-op: exit %d\n%s", code, out)
	}
	// plan after apply: clean → exit 0.
	if out, code := c.plan(bu); code != 0 {
		t.Errorf("plan (clean) exit %d, want 0\n%s", code, out)
	}

	// status reflects the managed tree (4 resources: 2 dirs + 2 files).
	r := c.statusJSON(t)
	if r.Managed < 4 {
		t.Errorf("status managed_resources = %d, want >= 4", r.Managed)
	}
}

// TestCorpusUnitDropin drives archetype 2: a standalone unit + drop-in +
// enablement. It proves the daemon-reload barrier runs, the unit is enabled and
// active, and systemd merged the precedence-named drop-in.
func TestCorpusUnitDropin(t *testing.T) {
	c := setup(t, corpusPolicy(t))
	bu := corpusFile(t, "02-unit-dropin.bu")

	if out, code := c.apply(bu); code != 0 {
		t.Fatalf("apply exit %d\n%s", code, out)
	}
	if e := c.isEnabled("magus-corpus.service"); e != "enabled" {
		t.Errorf("is-enabled = %q, want enabled", e)
	}
	if a := c.isActive("magus-corpus.service"); a != "active" {
		t.Errorf("is-active = %q, want active (oneshot RemainAfterExit)", a)
	}
	props, _ := c.exec("systemctl", "show", "magus-corpus.service", "-p", "Environment")
	if !strings.Contains(props, "CORPUS=present") {
		t.Errorf("systemd did not merge the drop-in: %q", props)
	}

	// Idempotence.
	if out, code := c.apply(bu); code != 0 || !strings.Contains(out, "Nothing to apply") {
		t.Errorf("second apply not a no-op: exit %d\n%s", code, out)
	}
}

// TestCorpusQuadletNetwork drives archetype 3: a container quadlet that
// references a declared network quadlet. It proves both sources are written,
// both generated services materialize, and the network's generated service
// (which needs no image egress) comes up. The container's runtime start is
// egress-dependent under nested podman, so it is logged, not asserted.
func TestCorpusQuadletNetwork(t *testing.T) {
	c := setup(t, corpusPolicy(t))
	bu := corpusFile(t, "03-quadlet-network.bu")

	// The graph must carry the reference edge (network service before container).
	c.put("/host.bu", bu)
	gout, gcode := c.magus("graph", "--policy", "/policy.yaml", "/host.bu")
	if gcode != 0 {
		t.Fatalf("graph exit %d\n%s", gcode, gout)
	}
	if !strings.Contains(gout, "corpus-network.service → corpus.service") {
		t.Errorf("graph missing the Network= reference edge:\n%s", gout)
	}

	out, code := c.apply(bu)
	// Both quadlet sources must be on disk as declared.
	if !c.exists("/etc/containers/systemd/corpus.network") {
		t.Fatalf("network source not written (apply exit %d)\n%s", code, out)
	}
	if !c.exists("/etc/containers/systemd/corpus.container") {
		t.Fatalf("container source not written (apply exit %d)\n%s", code, out)
	}
	// After magus' daemon-reload, the generator must materialize both services.
	if _, cc := c.exec("systemctl", "cat", "corpus-network.service"); cc != 0 {
		t.Errorf("network generated service did not materialize")
	}
	if _, cc := c.exec("systemctl", "cat", "corpus.service"); cc != 0 {
		t.Errorf("container generated service did not materialize")
	}
	// The network comes up without egress; the container may not (no image pull
	// in the nested runner) — log its state rather than assert it.
	t.Logf("corpus-network.service is-active=%s, corpus.service is-active=%s (apply exit %d)",
		c.isActive("corpus-network.service"), c.isActive("corpus.service"), code)
}

// TestEnvFileNotifyRestartsConsumer is the B3 centerpiece: it proves the graph's
// notify edge restarts an EnvironmentFile= consumer when ONLY the env file
// changes. The witness service appends its $WITNESS value to a log on every
// (re)start; after an env-only change the log must gain a second line — meaning
// magus restarted the service to pick up the new environment.
//
// Under the pre-graph phase pipeline this second apply would have been a no-op
// for the service (its body was unchanged), leaving the log with a single line.
// See TestEnvFileNotifyBaselineIsStale for the RED counterpart against the
// pre-B3 binary.
func TestEnvFileNotifyRestartsConsumer(t *testing.T) {
	c := setup(t, corpusPolicy(t))
	buOne := corpusFile(t, "04-envfile-notify.bu")

	if out, code := c.apply(buOne); code != 0 {
		t.Fatalf("initial apply exit %d\n%s", code, out)
	}
	if !c.waitActive("magus-witness.service", 60*time.Second) {
		t.Fatalf("witness service never became active\n%s", c.journal("magus-witness.service"))
	}
	if got := strings.Fields(c.readFile("/var/tmp/witness.log")); len(got) != 1 || got[0] != "one" {
		t.Fatalf("witness.log after first apply = %v, want [one]", got)
	}

	// Change ONLY the env file (WITNESS one→two); the unit body is byte-identical
	// so it plans as an unchanged skip. The env-file update must notify the
	// service and restart it.
	buTwo := strings.Replace(buOne, "WITNESS=one", "WITNESS=two", 1)
	if buTwo == buOne {
		t.Fatal("test setup: env value substitution did not change the butane")
	}
	out, code := c.apply(buTwo)
	if code != 0 {
		t.Fatalf("env-change apply exit %d\n%s", code, out)
	}
	// The apply must attribute a restart to the EnvironmentFile change.
	if !strings.Contains(out, "magus-witness.service") || !strings.Contains(out, "EnvironmentFile") {
		t.Errorf("apply did not report an EnvironmentFile-driven restart:\n%s", out)
	}

	// Give the restarted service a moment to re-run ExecStart and append.
	deadline := time.Now().Add(30 * time.Second)
	var fields []string
	for time.Now().Before(deadline) {
		fields = strings.Fields(c.readFile("/var/tmp/witness.log"))
		if len(fields) >= 2 {
			break
		}
		time.Sleep(time.Second)
	}
	if len(fields) < 2 {
		t.Fatalf("witness.log = %v, want two lines (a restart appended the new value)\n%s",
			fields, c.journal("magus-witness.service"))
	}
	if fields[0] != "one" || fields[1] != "two" {
		t.Errorf("witness.log = %v, want [one two] (old value then new after restart)", fields)
	}
	if a := c.isActive("magus-witness.service"); a != "active" {
		t.Errorf("witness service not active after env-change restart: %q", a)
	}
}
