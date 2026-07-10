package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// boolPtr returns a pointer to b — for ir.Unit.Enabled tri-state in tests.
func boolPtr(b bool) *bool { return &b }

func writeTemp(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, []byte(contents), 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return p
}
