//go:build !windows

package netif

// descriptions: adapter names are descriptive enough on Linux and macOS.
func descriptions() map[string]string { return map[string]string{} }
