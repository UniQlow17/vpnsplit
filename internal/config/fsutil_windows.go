//go:build windows

package config

import (
	"os"
	"path/filepath"
)

// openReadFlags: Windows has no O_NOFOLLOW; readRegular's Lstat and
// SameFile checks refuse symlinks and junctions.
const openReadFlags = 0

// writeFileAtomic replaces dir/name with data: the data goes to a fresh
// temporary file in the same directory (created exclusively), and is renamed
// into place. dir must be a plain directory, not a symlink or a junction
// (checked before the file is created and again before it is renamed, which
// leaves only a very short window). Windows has no directory-relative rename;
// callers that run elevated avoid user-writable directories where they can
// (see SaveCache), and the journal lives in a directory only administrators
// can write.
func writeFileAtomic(dir, name string, data []byte, perm os.FileMode, o *owner) (err error) {
	if err := checkDir(dir); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, name+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Chmod(perm); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = checkDir(dir); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, name))
}
