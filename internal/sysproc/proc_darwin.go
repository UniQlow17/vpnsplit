//go:build darwin

package sysproc

import (
	"errors"
	"strconv"

	"golang.org/x/sys/unix"
)

func startOf(pid int) (start int64, exists bool, err error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
			return 0, false, nil
		}
		if kerr := unix.Kill(pid, 0); kerr == unix.ESRCH {
			return 0, false, nil
		}
		return 0, true, err
	}
	if int(kp.Proc.P_pid) != pid {
		return 0, false, nil // sysctl returns an empty record for a missing pid
	}
	tv := kp.Proc.P_starttime
	return int64(tv.Sec)*1_000_000 + int64(tv.Usec), true, nil
}

// BootID is the boot time (unix seconds) reported by kern.boottime.
func BootID() string {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return ""
	}
	return strconv.FormatInt(int64(tv.Sec), 10)
}

// SameBoot reports whether two BootID values are of the same boot. An
// unknown (empty) id never proves a reboot.
func SameBoot(a, b string) bool { return sameBootTime(a, b) }
