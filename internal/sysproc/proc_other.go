//go:build !linux && !darwin && !windows

package sysproc

func startOf(pid int) (int64, bool, error) { return 0, true, nil }

// BootID is unknown on this OS.
func BootID() string { return "" }

// SameBoot reports whether two BootID values are of the same boot.
func SameBoot(a, b string) bool { return a == "" || b == "" || a == b }
