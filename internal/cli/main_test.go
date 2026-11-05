package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

// TestMain keeps the tests away from the real configuration of the user: the
// commands save the config and the last session, and those live in the profile.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "vpnsplit-cli-test")
	if err != nil {
		panic(err)
	}
	for _, k := range []string{"APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "HOME", "USERPROFILE"} {
		os.Setenv(k, dir)
	}
	os.Unsetenv("SUDO_USER")
	os.Unsetenv("PKEXEC_UID")
	cd, err := config.Dir()
	if err != nil {
		panic(err)
	}
	if rel, err := filepath.Rel(dir, cd); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		panic("tests would write outside the temporary directory: " + cd)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
