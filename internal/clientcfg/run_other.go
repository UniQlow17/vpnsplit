//go:build !unix

package clientcfg

import "os/exec"

// setGroup: no process groups here; toolWaitDelay keeps a child that holds the
// pipe from holding the caller.
func setGroup(*exec.Cmd) {}

// killGroup kills the tool itself.
func killGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill() // best effort: the process may be gone already
	}
}
