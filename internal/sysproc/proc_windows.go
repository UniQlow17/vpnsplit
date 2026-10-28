//go:build windows

package sysproc

import (
	"errors"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

const stillActive = 259

func startOf(pid int) (start int64, exists bool, err error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return 0, false, nil // no such pid
		}
		return 0, true, err // e.g. access denied: it exists
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err == nil && code != stillActive {
		return 0, false, nil // exited, a handle to it is still open somewhere
	}
	var created, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exit, &kernel, &user); err != nil {
		return 0, true, err
	}
	return int64(created.HighDateTime)<<32 | int64(created.LowDateTime), true, nil
}

// BootID is the boot time (unix seconds) from the kernel.
func BootID() string {
	// SYSTEM_TIMEOFDAY_INFORMATION: BootTime is the first field (100ns since 1601)
	var buf [48]byte
	var n uint32
	if err := windows.NtQuerySystemInformation(int32(windows.SystemTimeOfDayInformation), unsafe.Pointer(&buf[0]), uint32(len(buf)), &n); err != nil {
		return ""
	}
	ft := *(*int64)(unsafe.Pointer(&buf[0]))
	if ft <= 0 {
		return ""
	}
	return strconv.FormatInt(ft/10_000_000-11644473600, 10)
}

// SameBoot reports whether two BootID values are of the same boot (the
// boot time moves a little when the clock is corrected).
func SameBoot(a, b string) bool { return sameBootTime(a, b) }
