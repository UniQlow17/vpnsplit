package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// maxFileSize bounds what is read from files that other users can influence.
const maxFileSize = 16 << 20

// owner is the user whose files a process running as root (sudo, pkexec)
// writes; they must stay theirs.
type owner struct {
	uid, gid int
	home     string
}

// readRegular reads a regular file; symlinks, devices and huge files are
// refused. The check is repeated on the opened descriptor (and, where the OS
// has it, the open itself refuses a symlink and never blocks on a pipe), so
// swapping the file between the check and the open does not help.
func readRegular(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Size() > maxFileSize {
		return nil, fmt.Errorf("%s is too large", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|openReadFlags, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi2, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi2.Mode().IsRegular() || !os.SameFile(fi, fi2) {
		return nil, fmt.Errorf("%s changed while it was opened", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFileSize {
		return nil, fmt.Errorf("%s is too large", path)
	}
	return b, nil
}

// checkDir fails unless path is a real directory (not a symlink or junction).
func checkDir(path string) error {
	_, err := lstatDir(path)
	return err
}

func lstatDir(path string) (fs.FileInfo, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a plain directory (symbolic link?)", path)
	}
	return fi, nil
}

// relInside returns dir relative to home, failing if dir is not inside it.
// Both are compared as written (no symlink resolution): the caller builds
// dir from home, and the kernel-enforced check is done by os.Root.
func relInside(home, dir string) (string, error) {
	rel, err := filepath.Rel(filepath.Clean(home), filepath.Clean(dir))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("%s is outside the home directory %s, refusing to use it as root", dir, home)
	}
	return rel, nil
}

// removeRegular deletes dir/name if it is a regular file; a missing file is
// not an error. Nothing is followed: a symlink (or junction) at name or as
// dir is refused, and the deletion goes through a handle of dir (os.Root),
// so replacing dir by a link meanwhile does not redirect it.
func removeRegular(dir, name string) error {
	if err := checkDir(dir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	fi, err := root.Lstat(name)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file, not deleting it", filepath.Join(dir, name))
	}
	return root.Remove(name)
}

// ensureUserDir creates the user's config directory. For a process running
// as root on behalf of a user, created directories are handed to the user,
// and every step stays inside the user's home: the walk goes through os.Root,
// which refuses any component (symlink) leading out of home and cannot be
// redirected between check and use.
func ensureUserDir(p string, o *owner) error {
	if o == nil {
		if err := os.MkdirAll(p, 0o755); err != nil {
			return err
		}
		return checkDir(p)
	}
	rel, err := relInside(o.home, p)
	if err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	root, err := os.OpenRoot(o.home)
	if err != nil {
		return err
	}
	defer root.Close()
	parts := strings.Split(rel, string(filepath.Separator))
	cur := ""
	for i, part := range parts {
		cur = filepath.Join(cur, part)
		last := i == len(parts)-1
		var fi fs.FileInfo
		if last {
			fi, err = root.Lstat(cur)
		} else {
			fi, err = root.Stat(cur) // an inner link is fine while it stays inside home
		}
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if err := root.Mkdir(cur, 0o755); err != nil {
				return err
			}
			d, err := root.Open(cur)
			if err != nil {
				return err
			}
			err = d.Chown(o.uid, o.gid)
			d.Close()
			if err != nil {
				return err
			}
		case err != nil:
			return fmt.Errorf("%s: %w (it must stay inside the home directory %s)", p, err, o.home)
		case !fi.IsDir() || fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0:
			return fmt.Errorf("%s is not a plain directory (symbolic link?)", filepath.Join(o.home, cur))
		}
	}
	return nil
}
