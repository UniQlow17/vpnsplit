//go:build windows

package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A junction in place of the directory (what an ordinary user can create) is
// refused, and nothing behind it is deleted.
func TestRemoveRegularRefusesJunction(t *testing.T) {
	target := t.TempDir()
	victim := filepath.Join(target, "state.json")
	if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "vpnsplit")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("cannot create a junction: %v %s", err, out)
	}
	if err := removeRegular(link, "state.json"); err == nil {
		t.Error("a junction as the directory was accepted")
	}
	if _, err := os.Lstat(victim); err != nil {
		t.Errorf("the file behind the junction was deleted: %v", err)
	}
}
