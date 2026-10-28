//go:build unix

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// secureDirUnix returns path after making sure it is a real directory (not a
// symlink) owned by wantUID with no access for anybody else. A directory that
// is owned by root but too open is tightened to 0700.
func secureDirUnix(path string, create bool, wantUID int) (string, error) {
	fi, err := os.Lstat(path)
	if os.IsNotExist(err) && create {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return "", err
		}
		if err := os.Mkdir(path, 0o700); err != nil && !os.IsExist(err) {
			return "", err
		}
		fi, err = os.Lstat(path)
	}
	if err != nil {
		return "", err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return "", fmt.Errorf("%s is not a plain directory (symbolic link?), refusing to use it", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != wantUID {
		return "", fmt.Errorf("%s is owned by another user, refusing to use it", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o700); err != nil {
			return "", err
		}
	}
	return path, nil
}
