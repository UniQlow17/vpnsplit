//go:build unix

package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// openReadFlags: never follow a symlink at the file, never block on a pipe.
const openReadFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK

// writeFileAtomic replaces dir/name with data: the data goes to a fresh
// temporary file in the same directory (created exclusively, so no planted
// link is followed), is handed to o by descriptor, and is renamed into place.
//
// Every step goes through a handle of the directory (os.Root and renameat on
// its descriptor), so replacing dir or one of its parents by a symlink while
// this runs cannot redirect the write. For o != nil (root writing for a
// user) dir must lie inside o's home and the handle is taken from the home,
// so no link can lead out of it.
func writeFileAtomic(dir, name string, data []byte, perm os.FileMode, o *owner) (err error) {
	want, err := lstatDir(dir)
	if err != nil {
		return err
	}
	var root *os.Root
	if o != nil {
		rel, err := relInside(o.home, dir)
		if err != nil {
			return err
		}
		home, err := os.OpenRoot(o.home)
		if err != nil {
			return err
		}
		defer home.Close()
		if root, err = home.OpenRoot(rel); err != nil {
			return err
		}
	} else if root, err = os.OpenRoot(dir); err != nil {
		return err
	}
	defer root.Close()
	dirf, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dirf.Close()
	if got, err := dirf.Stat(); err != nil || !os.SameFile(want, got) {
		return fmt.Errorf("%s changed while it was opened, refusing to write", dir)
	}

	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := name + "." + hex.EncodeToString(rnd[:]) + ".tmp"
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = root.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Chmod(perm); err != nil {
		return err
	}
	if o != nil {
		if err = f.Chown(o.uid, o.gid); err != nil {
			return err
		}
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	fd := int(dirf.Fd())
	if err = unix.Renameat(fd, tmp, fd, name); err != nil {
		return &os.LinkError{Op: "rename", Old: filepath.Join(dir, tmp), New: filepath.Join(dir, name), Err: err}
	}
	return nil
}
