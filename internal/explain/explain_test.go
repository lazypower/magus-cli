package explain

import (
	"strings"
	"testing"
)

func iptr(i int) *int { return &i }

func TestOwnedUpdateShowsUnifiedDiff(t *testing.T) {
	out := Render(Input{
		OnDisk: []byte("OLLAMA_HOST=127.0.0.1:11434\nOLLAMA_KEEP_ALIVE=24h\n"),
		IR:     []byte("OLLAMA_HOST=0.0.0.0:11434\nOLLAMA_KEEP_ALIVE=24h\n"),
		Owned:  true,
	})
	if !strings.Contains(out, "-OLLAMA_HOST=127.0.0.1:11434") ||
		!strings.Contains(out, "+OLLAMA_HOST=0.0.0.0:11434") {
		t.Errorf("expected a unified diff of the changed line:\n%s", out)
	}
	if !strings.Contains(out, "@@") {
		t.Errorf("expected hunk header:\n%s", out)
	}
	// Unchanged line is context, not a change marker.
	if strings.Contains(out, "+OLLAMA_KEEP_ALIVE") || strings.Contains(out, "-OLLAMA_KEEP_ALIVE") {
		t.Errorf("unchanged line marked as a change:\n%s", out)
	}
}

func TestConflictHidesContentByDefault(t *testing.T) {
	in := Input{
		OnDisk: []byte("secret-old\n"),
		IR:     []byte("secret-new\n"),
		Owned:  false, // conflict
	}
	out := Render(in)
	if strings.Contains(out, "secret-old") || strings.Contains(out, "secret-new") {
		t.Errorf("conflict leaked unowned content without -v:\n%s", out)
	}
	if !strings.Contains(out, "hashes only") || !strings.Contains(out, "sha256:") {
		t.Errorf("expected hashes-only conflict output:\n%s", out)
	}
}

func TestConflictRevealedWithVerbose(t *testing.T) {
	out := Render(Input{
		OnDisk:  []byte("secret-old\n"),
		IR:      []byte("secret-new\n"),
		Owned:   false,
		Verbose: true,
	})
	if !strings.Contains(out, "-secret-old") || !strings.Contains(out, "+secret-new") {
		t.Errorf("-v did not reveal the conflict diff:\n%s", out)
	}
}

func TestBinaryFallsBackToHashes(t *testing.T) {
	out := Render(Input{
		OnDisk: []byte{0x00, 0x01, 0x02},
		IR:     []byte{0x00, 0x03},
		Owned:  true,
	})
	if !strings.Contains(out, "binary content differs") || !strings.Contains(out, "sha256:") {
		t.Errorf("expected binary hash fallback:\n%s", out)
	}
	if strings.Contains(out, "@@") {
		t.Errorf("should not attempt a textual diff on binary:\n%s", out)
	}
}

func TestModeDeltaLine(t *testing.T) {
	out := Render(Input{
		OnDisk:     []byte("x\n"),
		IR:         []byte("x\n"), // content equal — only mode differs
		OnDiskMode: 0o644,
		IRMode:     0o600,
		Owned:      true,
	})
	if !strings.Contains(out, "mode 0644 → 0600") {
		t.Errorf("expected mode delta line:\n%s", out)
	}
	if strings.Contains(out, "@@") {
		t.Errorf("no content diff expected when content matches:\n%s", out)
	}
}

func TestOwnerDeltaLine(t *testing.T) {
	out := Render(Input{
		OnDisk:    []byte("x\n"),
		IR:        []byte("x\n"),
		OnDiskUID: 0, OnDiskGID: 0,
		IRUID: iptr(1000), IRGID: iptr(1000),
		Owned: true,
	})
	if !strings.Contains(out, "owner 0:0 → 1000:1000") {
		t.Errorf("expected owner delta line:\n%s", out)
	}
}

func TestNoOwnerLineWhenUndeclared(t *testing.T) {
	out := Render(Input{
		OnDisk: []byte("x\n"), IR: []byte("y\n"),
		OnDiskUID: 0, OnDiskGID: 0,
		IRUID: nil, IRGID: nil, // ownership not declared
		Owned: true,
	})
	if strings.Contains(out, "owner") {
		t.Errorf("owner line shown though ownership undeclared:\n%s", out)
	}
}

func TestNothingToExplain(t *testing.T) {
	if out := Render(Input{OnDisk: []byte("x"), IR: []byte("x"), Owned: true}); out != "" {
		t.Errorf("expected empty detail when everything matches, got:\n%s", out)
	}
}
