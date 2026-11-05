//go:build unix

package sysexec

import (
	"errors"
	"os"
	"path/filepath"
)

// dirs are the places system tools live, in search order. They are owned by
// root; nothing from PATH or the user's home is ever consulted.
var dirs = []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin", "/run/current-system/sw/bin"}

const trustedPath = "/usr/sbin:/sbin:/usr/bin:/bin"

func lookPath(name string) (string, error) {
	if name == "" || name != filepath.Base(name) {
		return "", errors.New("not a bare tool name")
	}
	for _, d := range dirs {
		p := filepath.Join(d, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return p, nil
		}
	}
	return "", errors.New("not found in the system directories")
}

// baseEnv: a fixed PATH, and the C locale so that the messages of the tools
// are the English ones this program recognizes.
func baseEnv() []string {
	return []string{"PATH=" + trustedPath, "LC_ALL=C", "LANG=C"}
}
