package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// ProtectedExe checks that the program at path can be started by SYSTEM or root
// at boot without handing those rights to an ordinary user: the file belongs to
// the system and nobody else may write it, and every directory from its own up to
// the root belongs to the system and cannot be changed or replaced by anybody
// else either. A user who can write the file or swap one of its directories
// decides what runs with full rights.
//
// The path must be absolute. It is returned with symbolic links resolved, and
// that is the path to hand on: what the checks judged is what will be started.
// The error says what failed and what to do.
func ProtectedExe(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s: not an absolute path", path)
	}
	full, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	fi, err := os.Lstat(full)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s: not a regular file", full)
	}
	f, err := os.Open(full)
	if err != nil {
		return "", err
	}
	defer f.Close()
	fi2, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !os.SameFile(fi, fi2) {
		return "", fmt.Errorf("%s changed while it was checked", full)
	}
	if !exeFileOK(f, fi2) {
		return "", fmt.Errorf("%s: the file is not the system's or somebody else can write it", full)
	}
	dir := filepath.Dir(full)
	if !exeDirOK(dir) {
		return "", fmt.Errorf("%s: the directory is not the system's or somebody else can write it", dir)
	}
	for d := filepath.Dir(dir); ; d = filepath.Dir(d) {
		if !ancestorDirOK(d) {
			return "", fmt.Errorf("%s: a directory above the program is not the system's or can be replaced by a user", d)
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	return full, nil
}

// ProtectedDir checks that a directory can be trusted to hold files that SYSTEM
// or root acts on (a systemd unit, a LaunchDaemon): it and every directory above
// it belong to the system and cannot be changed by anybody else.
func ProtectedDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%s: not an absolute path", dir)
	}
	full, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	if !exeDirOK(full) {
		return fmt.Errorf("%s: the directory is not the system's or somebody else can write it", full)
	}
	for d := filepath.Dir(full); ; d = filepath.Dir(d) {
		if !ancestorDirOK(d) {
			return fmt.Errorf("%s: a directory above is not the system's or can be replaced by a user", d)
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	return nil
}
