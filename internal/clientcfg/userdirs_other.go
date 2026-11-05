//go:build !windows

package clientcfg

import "github.com/UniQlow17/vpnsplit/internal/config"

// userDirs returns the configuration directory and the profile of the user
// (under sudo or pkexec the user who started it, not root).
func userDirs() (cfgDir, home string) {
	cfgDir, _ = config.RealUserConfigDir()
	home, _ = config.RealUserHome()
	return cfgDir, home
}
