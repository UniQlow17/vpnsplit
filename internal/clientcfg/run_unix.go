//go:build unix

package clientcfg

import (
	"os/exec"
	"syscall"
)

// setGroup puts the tool into a process group of its own, so that on a timeout
// the whole group (runuser -> env -> gsettings) can be killed, not only the first.
func setGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// killGroup kills the process group of the tool (and, as a fallback, the process).
func killGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		_ = cmd.Process.Kill() // best effort: the group is gone or was not made
	}
}
