// Package sysexec starts the operating system's own tools (PowerShell,
// route, ip, scutil...) the way a process with administrator rights must:
// by absolute path from the system directories, never through PATH, and with
// a minimal environment instead of the caller's.
//
// The caller's PATH, PATHEXT and PSModulePath can be edited by the ordinary
// user (HKCU\Environment on Windows, shell profiles elsewhere), so letting
// them decide which "powershell" or "ip" is run would hand administrator
// rights to whoever planted a file in one of those directories.
package sysexec

import (
	"fmt"
	"os/exec"
)

// Command returns the command for the system tool name (a bare name such as
// "route" or "ip"). If the tool is not found in the system directories the
// command is returned with its error already set, so Run, Output and the
// like fail instead of searching elsewhere.
func Command(name string, args ...string) *exec.Cmd {
	path, err := LookPath(name)
	if err != nil {
		return &exec.Cmd{Path: name, Args: append([]string{name}, args...), Err: err}
	}
	cmd := exec.Command(path, args...)
	cmd.Env = baseEnv()
	return cmd
}

// LookPath finds the system tool name in the trusted directories only.
func LookPath(name string) (string, error) {
	path, err := lookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return path, nil
}
