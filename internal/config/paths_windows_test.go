//go:build windows

package config

import "testing"

// A directory in the user's own temp folder is owned by the user and lists
// them in its DACL: it must never pass for the protected journal directory.
func TestCheckProtectedDirRejectsUserDir(t *testing.T) {
	if err := checkProtectedDir(t.TempDir()); err == nil {
		t.Error("a user-controlled directory was accepted as the protected journal directory")
	}
}

func TestCheckProtectedDirRejectsMissing(t *testing.T) {
	if err := checkProtectedDir(t.TempDir() + `\nope`); err == nil {
		t.Error("expected error")
	}
}
