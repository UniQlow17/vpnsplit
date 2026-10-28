package sysproc

import "strconv"

// bootTolerance: the boot time is derived from the clock, which is
// corrected (NTP, RTC fixes) after boot, so two reads of the same boot differ.
const bootTolerance = 600 // seconds

// sameBootTime compares boot times given in unix seconds.
func sameBootTime(a, b string) bool {
	if a == "" || b == "" {
		return true
	}
	x, e1 := strconv.ParseInt(a, 10, 64)
	y, e2 := strconv.ParseInt(b, 10, 64)
	if e1 != nil || e2 != nil {
		return a == b
	}
	d := x - y
	if d < 0 {
		d = -d
	}
	return d <= bootTolerance
}
