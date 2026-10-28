//go:build windows

package router

import (
	"strings"

	"github.com/UniQlow17/vpnsplit/internal/sysexec"
)

// routeListed asks the route table, through `route print`, whether the prefix
// is there with that next hop. It is the confirmation of `route add`, whose
// exit code alone is not reliable. `route print` is much cheaper than a
// PowerShell start, which matters when a rule list adds hundreds of routes.
// known is false when the table could not be read.
func routeListed(ip, mask, gw string) (listed, known bool) {
	out, err := sysexec.Command("route", "print", "-4", ip, "mask", mask).Output()
	if err != nil {
		return false, false
	}
	return tableHasRoute(string(out), ip, mask, gw), true
}

// tableHasRoute looks for a row "dest mask next-hop interface metric" in the
// active routes of `route print`. The columns are numbers and addresses, so
// the (localized) headings do not matter; an on-link route has the word
// "On-link" in its own language as the next hop, which is accepted when gw
// is 0.0.0.0. Rows of the persistent table have four columns and are skipped.
func tableHasRoute(out, ip, mask, gw string) bool {
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) != 5 || f[0] != ip || f[1] != mask {
			continue
		}
		if gw == "0.0.0.0" || f[2] == gw {
			return true
		}
	}
	return false
}
