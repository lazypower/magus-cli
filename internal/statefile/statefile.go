// Package statefile writes magus's own JSON state files — the manifest (the
// ownership ledger) and the status observation — atomically and durably.
//
// The write is tmp + fsync + rename: the temp file is created with
// O_EXCL|O_NOFOLLOW so a symlink planted at the ".magus.tmp" sibling can't
// redirect the write, its contents are fsync'd before the rename so a power
// loss can't leave the renamed file present-but-empty (ext4/xfs will otherwise
// flush the rename before the data), and the rename is atomic on the same
// filesystem. The ".magus.tmp" suffix is reserved from IR declaration by
// policy.ReservedReason, so an operator can't pre-create it.
package statefile

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// WriteAtomic writes data to path atomically and durably at mode 0600 (state
// files are magus-private). The parent directory is created if missing.
func WriteAtomic(path string, data []byte) (err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("state dir: %w", err)
	}
	tmp := path + ".magus.tmp"
	// Drop any leftover tmp (unlink follows no symlink — it removes a planted
	// symlink itself, not its target), then create fresh with O_EXCL|O_NOFOLLOW.
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("open tmp %s: %w", tmp, err)
	}
	// Any failure after the temp file exists leaves nothing behind.
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write tmp %s: %w", tmp, err)
	}
	// fsync before rename — the durability guarantee that keeps the ledger from
	// vanishing on power loss.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("fsync tmp %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close tmp %s: %w", tmp, err)
	}
	// Chmod after close — OpenFile honors umask, which can clip the mode.
	if err := os.Chmod(tmp, 0o600); err != nil {
		return fmt.Errorf("chmod tmp %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %s: %w", tmp, err)
	}
	return nil
}
