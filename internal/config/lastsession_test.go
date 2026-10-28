package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLastSessionRoundTripAndOverwrite(t *testing.T) {
	dir := t.TempDir()
	if got := readLastSession(dir); got != "" {
		t.Fatalf("no file yet: %q", got)
	}
	if err := writeLastSession(dir, "first"); err != nil {
		t.Fatal(err)
	}
	if err := writeLastSession(dir, "2026-01-01 SIGTERM: снято: маршрутов 3\n"); err != nil {
		t.Fatal(err)
	}
	if got := readLastSession(dir); got != "2026-01-01 SIGTERM: снято: маршрутов 3" {
		t.Errorf("%q", got)
	}
}

func TestLastSessionIsBoundedAndPlain(t *testing.T) {
	dir := t.TempDir()
	if err := writeLastSession(dir, strings.Repeat("я", 5000)); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, lastSessionFile))
	if err != nil || fi.Size() > maxLastSession+8 {
		t.Errorf("%v %v", fi, err)
	}
	if err := os.WriteFile(filepath.Join(dir, lastSessionFile), []byte("ok\x1b[31m red\x07\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readLastSession(dir); strings.ContainsAny(got, "\x1b\x07") {
		t.Errorf("control characters reach the terminal: %q", got)
	}
}

// reset --purge deletes the user's config.json and nothing else: not the
// journal, the lock or the last-session note, which live elsewhere.
func TestRemoveDeletesOnlyConfigJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir) // Windows: os.UserConfigDir
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("SUDO_USER", "")
	d, err := Dir()
	if err != nil {
		t.Skipf("user config dir not usable here: %v", err)
	}
	if !strings.HasPrefix(d, dir) {
		t.Skipf("config dir %s is outside the test directory", d)
	}
	for _, n := range []string{"config.json", stateFile, lockFile, lastSessionFile} {
		if err := os.WriteFile(filepath.Join(d, n), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(d, "config.json")); !os.IsNotExist(err) {
		t.Error("config.json must be gone")
	}
	for _, n := range []string{stateFile, lockFile, lastSessionFile} {
		if _, err := os.Stat(filepath.Join(d, n)); err != nil {
			t.Errorf("%s must stay: %v", n, err)
		}
	}
	if _, err := os.Stat(d); err != nil {
		t.Errorf("the directory must stay: %v", err)
	}
}
