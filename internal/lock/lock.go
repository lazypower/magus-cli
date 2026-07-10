// Package lock provides a filesystem advisory lock that serializes the
// mutating magus operations — a timer-driven `apply --yes` and a human
// `apply`/`adopt`/`reclaim` — so they can't interleave and corrupt the
// manifest. The manifest is the consent ledger the whole ownership model hangs
// on; two concurrent read-modify-write cycles can silently drop one side's
// records, and two applies sharing the fixed `.magus.tmp` names can rename a
// half-written state file into place. One writer at a time removes the race.
package lock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// ErrBusy is returned by Acquire when another process already holds the lock.
// Callers surface it as "another apply is in progress" and exit fast rather
// than block behind the running operation.
var ErrBusy = errors.New("another magus operation is in progress")

// Acquire takes an exclusive, non-blocking advisory lock (flock) keyed to
// target — the manifest path. The lock file is target+".lock" in the same
// directory, so the lock is scoped to the manifest being mutated: applies
// against different manifests don't block each other, and tests using temp
// manifests stay isolated. It returns a release function; call it (deferred)
// to unlock. ErrBusy means another holder has it.
func Acquire(target string) (func() error, error) {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return nil, fmt.Errorf("lock dir: %w", err)
	}
	lockPath := target + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock %s: %w", lockPath, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, fmt.Errorf("flock %s: %w", lockPath, err)
	}
	return func() error {
		// The lock is released implicitly on close; unlock explicitly first so
		// the intent is clear and the fd's lifetime doesn't matter.
		unlockErr := syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		closeErr := f.Close()
		if unlockErr != nil {
			return unlockErr
		}
		return closeErr
	}, nil
}
