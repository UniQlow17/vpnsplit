//go:build unix

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func machineProgramDir() (string, error) {
	if runtime.GOOS == "darwin" {
		return "/Library/PrivilegedHelperTools/vpnsplit", nil
	}
	return "/usr/local/libexec/vpnsplit", nil
}

func pathsEqual(a, b string) bool { return a == b }

func ensureProgramDir(dir string) (string, error) {
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("%s: not an absolute path", dir)
	}
	dir = filepath.Clean(dir)
	// create what is missing, from the top: root's, 0755
	cur := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(dir, cur), cur) {
		cur = filepath.Join(cur, part)
		if _, err := os.Lstat(cur); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			return "", err
		}
		if err := os.Mkdir(cur, 0o755); err != nil && !os.IsExist(err) {
			return "", fmt.Errorf("create %s: %w", cur, err)
		}
		if err := os.Chown(cur, 0, 0); err != nil {
			return "", fmt.Errorf("chown %s: %w", cur, err)
		}
		if err := os.Chmod(cur, 0o755); err != nil {
			return "", fmt.Errorf("chmod %s: %w", cur, err)
		}
	}
	return checkProgramDir(dir)
}

func checkProgramDir(dir string) (string, error) {
	fi, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s is not a plain directory", dir)
	}
	if err := ProtectedDir(dir); err != nil {
		return "", err
	}
	full, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}
	if underUserMount(full) {
		return "", fmt.Errorf("%s: a user can mount something here, refusing to keep a program of root in it", full)
	}
	return full, nil
}

func verifyFinalPath(full string) error {
	if underUserMount(full) {
		return fmt.Errorf("%s: a user can mount something here, refusing to run it as root", full)
	}
	return nil
}
