//go:build linux

package sysproc

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
)

// startOf reads the start time (clock ticks since boot) from /proc/<pid>/stat.
func startOf(pid int) (start int64, exists bool, err error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, false, nil
		}
		if _, serr := os.Stat("/proc/self/stat"); serr != nil {
			return 0, true, err // no /proc: existence is unknown
		}
		return 0, false, nil // the process vanished while it was read
	}
	start, err = parseStatStart(string(b))
	return start, true, err
}

// parseStatStart extracts field 22 of /proc/<pid>/stat. The command name
// (field 2) may contain spaces and parentheses, so fields are counted after
// the last ")".
func parseStatStart(s string) (int64, error) {
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, fmt.Errorf("unexpected /proc stat format")
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 { // fields 3..22
		return 0, fmt.Errorf("unexpected /proc stat format")
	}
	return strconv.ParseInt(f[19], 10, 64)
}

// BootID is the kernel's random id of this boot.
func BootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// SameBoot reports whether two BootID values are of the same boot. An
// unknown (empty) id never proves a reboot.
func SameBoot(a, b string) bool { return a == "" || b == "" || a == b }
