//go:build unix

package config

import "strings"

// lsHasACL reads the output of `ls -lde`: macOS prints the entries of an
// extended access list on the lines below the one of the file ("0: user:x allow
// write"). The flag character after the mode cannot be trusted: '@' (extended
// attributes) hides '+'.
func lsHasACL(out string) bool {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for _, l := range lines[min(1, len(lines)):] {
		l = strings.TrimSpace(l)
		i := strings.IndexByte(l, ':')
		if i <= 0 {
			continue
		}
		digits := true
		for _, r := range l[:i] {
			if r < '0' || r > '9' {
				digits = false
			}
		}
		if digits {
			return true
		}
	}
	return false
}
