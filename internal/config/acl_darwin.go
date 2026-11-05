//go:build darwin

package config

import "github.com/UniQlow17/vpnsplit/internal/sysexec"

// noExtendedACL: the object has no extended access list. A rule such as
// "everyone allow write" would let a user change what root runs, and the mode
// bits do not show it. There is no cgo here, so the system's own ls is asked
// (acl_get_link_np is not reachable). Fails closed: if ls cannot say, the
// answer is no.
func noExtendedACL(path string) bool {
	if path == "" {
		return false
	}
	out, err := sysexec.Command("ls", "-lde", "--", path).Output()
	return err == nil && !lsHasACL(string(out))
}
