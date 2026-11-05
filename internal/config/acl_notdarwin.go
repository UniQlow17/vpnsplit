//go:build unix && !darwin

package config

// noExtendedACL: only macOS is checked (see acl_darwin.go).
func noExtendedACL(string) bool { return true }
