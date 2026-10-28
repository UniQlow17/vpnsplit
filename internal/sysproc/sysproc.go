// Package sysproc identifies processes and boots: enough to tell whether the
// process that wrote the journal is still the same live process, and whether
// the machine was rebooted since.
package sysproc

import "os"

// Self returns the identity of the current process.
func Self() (pid int, start int64) {
	pid = os.Getpid()
	start, _ = Start(pid) // 0 when unknown: Alive then trusts the pid alone
	return pid, start
}

// Alive reports whether the process pid exists and is the one that started
// at start (a reused pid has another start time). A start of 0 means "not
// recorded": only the existence of the pid is checked.
func Alive(pid int, start int64) bool {
	if pid <= 0 {
		return false
	}
	cur, exists, err := startOf(pid)
	if !exists {
		return false
	}
	if err != nil || start == 0 || cur == 0 {
		return true // exists, but the start time cannot be compared
	}
	return cur == start
}

// Start returns the start time of the process in an OS-specific unit; it is
// only meant to be compared for equality with a value from the same OS.
func Start(pid int) (int64, error) {
	s, exists, err := startOf(pid)
	if err == nil && !exists {
		return 0, os.ErrProcessDone
	}
	return s, err
}

// AliveExact reports whether pid is the very process that started at start.
// Unlike Alive it says yes only when both start times are known and equal:
// an unreadable process (access denied) or an unrecorded start is not a
// proof. Used where a wrong "alive" would only produce a warning.
func AliveExact(pid int, start int64) bool {
	if pid <= 0 || start == 0 {
		return false
	}
	cur, exists, err := startOf(pid)
	return exists && err == nil && cur != 0 && cur == start
}
