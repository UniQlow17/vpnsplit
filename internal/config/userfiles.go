package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ReadRegularMax reads a regular file of at most max bytes: a symlink, a
// device, a directory or a bigger file is refused (see readRegular). It is for
// files of other programs in the profile of the user, which are not trusted.
func ReadRegularMax(path string, max int64) ([]byte, error) {
	if max <= 0 || max > maxFileSize {
		return nil, fmt.Errorf("bad size limit %d", max)
	}
	return readRegularMax(path, max)
}

// RealUserHome returns the home directory of the user on whose behalf the
// process runs: the one that started sudo or pkexec, otherwise the user of the
// process. ok is false when it cannot be told.
func RealUserHome() (home string, ok bool) {
	if o := sudoOwner(); o != nil {
		return o.home, true
	}
	h, err := os.UserHomeDir()
	if err != nil || h == "" {
		return "", false
	}
	return h, true
}

// RealUserConfigDir is the per-user configuration base of RealUserHome
// (~/.config, ~/Library/Application Support, %AppData%).
func RealUserConfigDir() (dir string, ok bool) {
	if o := sudoOwner(); o != nil {
		return userConfigDir(o.home), true
	}
	d, err := os.UserConfigDir()
	if err != nil || d == "" {
		return "", false
	}
	return d, true
}

// RealUser is the account behind a root process started by sudo or pkexec:
// the name and numeric id come from the user database, not from the
// environment variables that only pointed to them. ok is false for any other process.
func RealUser() (name string, uid int, ok bool) {
	o := sudoOwner()
	if o == nil {
		return "", 0, false
	}
	return o.name, o.uid, true
}

// UserEntry is one entry of a directory listed by ListUserDir or ListMachineDir.
type UserEntry struct {
	Name    string
	Dir     bool // a plain directory
	Regular bool // a plain file
}

// plainPath checks that every component of rel below root is a plain directory
// (the last one may be a plain file when wantFile): a symlink, a junction or
// another reparse point on the way means the path leads somewhere else than
// its name says, and what is behind it is not read.
func plainPath(root *os.Root, rel string, wantFile bool) error {
	if rel == "." {
		return nil
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for i := range parts {
		p := strings.Join(parts[:i+1], "/")
		fi, err := root.Lstat(p)
		if err != nil {
			return err
		}
		if fi.Mode()&(os.ModeSymlink|os.ModeIrregular|os.ModeDevice|os.ModeNamedPipe|os.ModeSocket) != 0 {
			return fmt.Errorf("%s is a link or not a plain file", p)
		}
		last := i == len(parts)-1
		switch {
		case !last && !fi.IsDir():
			return fmt.Errorf("%s is not a directory", p)
		case last && wantFile && !fi.Mode().IsRegular():
			return fmt.Errorf("%s is not a regular file", p)
		case last && !wantFile && !fi.IsDir():
			return fmt.Errorf("%s is not a directory", p)
		}
	}
	return nil
}

// ReadUserFile reads a regular file of at most max bytes that lies below base
// (the profile of the user, or the folder of its settings). base is opened as
// a root (os.Root), so the path cannot lead out of it, and no component below
// it may be a symlink or a reparse point. Where the OS has owners (Unix) the
// file must belong to the real user or to root: whoever else can write in the
// profile cannot feed it a file. The file is for a program that runs
// elevated and reads what the user (and anything running as the user) can write.
func ReadUserFile(base, path string, max int64) ([]byte, error) {
	if max <= 0 || max > maxFileSize {
		return nil, fmt.Errorf("bad size limit %d", max)
	}
	rel, err := relInside(base, path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err := plainPath(root, rel, true); err != nil {
		return nil, err
	}
	f, err := root.OpenFile(rel, os.O_RDONLY|openReadFlags, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > max || !userOwned(fi) {
		return nil, fmt.Errorf("%s: not a regular file of the user, or too large", path)
	}
	return readLimited(f, max, path)
}

func readLimited(f *os.File, max int64, path string) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s is too large", path)
	}
	return b, nil
}

// ListUserDir lists at most limit entries of the directory path below base,
// with the same care as ReadUserFile. The order is the one of the names.
func ListUserDir(base, path string, limit int) ([]UserEntry, error) {
	rel, err := relInside(base, path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err := plainPath(root, rel, false); err != nil {
		return nil, err
	}
	d, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	return listEntries(d, limit)
}

func listEntries(d *os.File, limit int) ([]UserEntry, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("bad limit %d", limit)
	}
	ents, err := d.ReadDir(limit)
	if err != nil && err != io.EOF {
		return nil, err
	}
	out := make([]UserEntry, 0, len(ents))
	for _, e := range ents {
		out = append(out, UserEntry{Name: e.Name(), Dir: e.Type().IsDir(), Regular: e.Type().IsRegular()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// machineDirOK says whether a directory of the machine (Program Files,
// ProgramData\..., /etc, /opt) is one that only the system can change: a plain
// directory owned by root (SYSTEM, Administrators, TrustedInstaller) and, on
// Unix, not writable by group or others. What lies in a directory a user made
// is not a setting of the machine.
//
// On Windows the access list of the directory is checked as well: nobody but
// SYSTEM, Administrators and TrustedInstaller may write to it or change it.
func machineDirOK(dir string) bool {
	fi, err := os.Lstat(dir)
	return err == nil && fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 && trustedOwner(fi, dir) && strictDir(dir)
}

// machineChainOK says whether every directory from dir up to the root belongs
// to the system (owner, and on Unix no write for group or others): a directory
// on the way that a user owns would let the user swap the one below it. dir has
// no symbolic links in it (see ReadMachineFile).
func machineChainOK(dir string) bool {
	for d := dir; ; {
		fi, err := os.Lstat(d)
		if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || !trustedOwner(fi, d) {
			return false
		}
		parent := filepath.Dir(d)
		if parent == d {
			return true
		}
		d = parent
	}
}

// ReadMachineFile is ReadRegularMax for the files of the machine-wide places.
// The file is opened first (a link is not followed) and its owner and rights are
// judged on the open descriptor, so it cannot be swapped afterwards; its
// directory must belong to the system (see machineDirOK) and so must every
// directory above it, else the file is refused as if it were not there.
func ReadMachineFile(path string, max int64) ([]byte, error) {
	if max <= 0 || max > maxFileSize {
		return nil, fmt.Errorf("bad size limit %d", max)
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%s: not an absolute path", path)
	}
	// links in the directories above (macOS: /etc -> private/etc) are resolved
	// once; the checks below then walk a path without links
	dir, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	full := filepath.Join(dir, filepath.Base(path))
	fi, err := os.Lstat(full)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > max {
		return nil, fmt.Errorf("%s: not a regular file, or too large", path)
	}
	f, err := os.OpenFile(full, os.O_RDONLY|openReadFlags, 0)
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
	if !machineFileOK(f, fi2) {
		return nil, fmt.Errorf("%s: the file is not the system's", path)
	}
	if !machineDirOK(dir) || !machineChainOK(dir) {
		return nil, fmt.Errorf("%s: the directory is not the system's", path)
	}
	return readLimited(f, max, path)
}

// ListMachineDir lists at most limit entries of a directory that only the
// system owns (see machineDirOK).
func ListMachineDir(dir string, limit int) ([]UserEntry, error) {
	if !machineDirOK(dir) {
		return nil, fmt.Errorf("%s: not the system's directory", dir)
	}
	d, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	return listEntries(d, limit)
}
