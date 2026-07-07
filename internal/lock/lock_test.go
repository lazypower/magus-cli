package lock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAcquireIsExclusive(t *testing.T) {
	target := filepath.Join(t.TempDir(), "manifest.json")

	release, err := Acquire(target)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	// A second acquire while the first is held must report busy, not block.
	if _, err := Acquire(target); !errors.Is(err, ErrBusy) {
		t.Errorf("second acquire err = %v, want ErrBusy", err)
	}

	if err := release(); err != nil {
		t.Fatalf("release: %v", err)
	}

	// After release the lock is re-acquirable.
	release2, err := Acquire(target)
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	if err := release2(); err != nil {
		t.Fatalf("release2: %v", err)
	}
}

func TestAcquireCreatesLockDir(t *testing.T) {
	// The manifest dir need not exist yet (first run) — Acquire creates it.
	target := filepath.Join(t.TempDir(), "var", "lib", "magus", "manifest.json")
	release, err := Acquire(target)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer func() { _ = release() }()
	if _, err := os.Stat(target + ".lock"); err != nil {
		t.Errorf("lock file not created: %v", err)
	}
}
