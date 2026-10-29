package config

import (
	"fmt"
	"path/filepath"
	"strings"
)

// The program that the boot-time job starts is a copy of vpnsplit made by
// `vpnsplit install-recover` into a fixed directory of the system: whoever owns
// the place the user started vpnsplit from (a junction, a directory a user can
// rename) cannot change what SYSTEM or root runs later. The functions here only
// name and judge that place; the copying is in package autorecover.

// ProgramMarkName is the file next to the copy that says the directory is ours.
const ProgramMarkName = "vpnsplit.managed"

// MachineProgramDir is the fixed directory of the copy: %ProgramFiles%\vpnsplit
// (the folder is asked from the system, not from the environment),
// /Library/PrivilegedHelperTools/vpnsplit on macOS, /usr/local/libexec/vpnsplit
// on other Unix systems.
func MachineProgramDir() (string, error) { return machineProgramDir() }

// EnsureProgramDir creates the directory (owned by the system, closed to
// everybody else) and judges it. It returns the path to use, with symbolic
// links resolved.
func EnsureProgramDir(dir string) (string, error) { return ensureProgramDir(dir) }

// CheckProgramDir judges an existing directory of the copy the same way,
// without creating anything.
func CheckProgramDir(dir string) (string, error) { return checkProgramDir(dir) }

// VerifyInstalledProgram checks the copy once it is in place: ProtectedExe on
// the path, no link and no reparse point anywhere on the way, and (Unix) not on
// removable or user-mounted media. It returns the path to put in the job, which
// is exactly path.
func VerifyInstalledProgram(path string) (string, error) {
	full, err := ProtectedExe(path)
	if err != nil {
		return "", err
	}
	if !samePath(full, filepath.Clean(path)) {
		return "", fmt.Errorf("%s: the path leads through a link (it is %s)", path, full)
	}
	if err := verifyFinalPath(full); err != nil {
		return "", err
	}
	return full, nil
}

func samePath(a, b string) bool { return pathsEqual(a, b) }

// userMountPrefixes: places where a user can mount a file system of their own.
var userMountPrefixes = []string{"/media", "/run/media", "/mnt"}

func underUserMount(p string) bool {
	for _, m := range userMountPrefixes {
		if p == m || strings.HasPrefix(p, m+"/") {
			return true
		}
	}
	return false
}
