package autorecover

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/UniQlow17/vpnsplit/internal/sysexec"
)

// sysRun starts a system tool by its absolute path (see package sysexec) and
// returns what it printed.
func sysRun(tool string, args ...string) ([]byte, error) {
	return sysexec.Command(tool, args...).CombinedOutput()
}

// installUnit writes the systemd unit into dir and enables it. exe must be
// checked by the caller (see Install); the text of the path is checked here.
func installUnit(dir, exe string, run Runner, out io.Writer) error {
	text, err := UnitText(exe)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, UnitName)
	if err := writeManaged(path, []byte(text), unitMark, 0o644); err != nil {
		return err
	}
	say(out, "wrote %s", path)
	if o, err := run("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w: %s", err, trim(o))
	}
	if o, err := run("systemctl", "enable", UnitName); err != nil {
		return fmt.Errorf("systemctl enable %s: %w: %s", UnitName, err, trim(o))
	}
	say(out, "enabled: `%s recover` runs as root at every boot (not started now)", exe)
	return nil
}

// removeUnit disables and deletes the unit if it is ours.
func removeUnit(dir string, run Runner, out io.Writer) error {
	path := filepath.Join(dir, UnitName)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		say(out, "not installed: %s does not exist", path)
		return nil
	}
	if err := checkManaged(path, unitMark); err != nil {
		return err
	}
	if o, err := run("systemctl", "disable", UnitName); err != nil {
		// without a running systemd there is nothing to disable; the file goes anyway
		say(out, "warning: systemctl disable %s: %v: %s", UnitName, err, trim(o))
	}
	if _, err := removeManaged(path, unitMark); err != nil {
		return err
	}
	say(out, "removed %s", path)
	if o, err := run("systemctl", "daemon-reload"); err != nil {
		say(out, "warning: systemctl daemon-reload: %v: %s", err, trim(o))
	}
	return nil
}

// installPlist writes the LaunchDaemon into dir and loads it. launchd refuses a
// plist that is not owned by root or that others can write.
func installPlist(dir, exe string, run Runner, out io.Writer, chownRoot bool) error {
	text, err := PlistText(exe)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, Label+".plist")
	if err := writeManaged(path, []byte(text), plistMarkStart, 0o644); err != nil {
		return err
	}
	if chownRoot {
		if err := os.Chown(path, 0, 0); err != nil {
			return fmt.Errorf("chown %s: %w", path, err)
		}
	}
	say(out, "wrote %s", path)
	_, _ = run("launchctl", "bootout", "system/"+Label) // a copy that is loaded already is replaced
	if o, err := run("launchctl", "bootstrap", "system", path); err != nil {
		return fmt.Errorf("launchctl bootstrap: %w: %s", err, trim(o))
	}
	say(out, "loaded: `%s recover` runs as root at every boot", exe)
	return nil
}

// removePlist unloads and deletes the LaunchDaemon if it is ours.
func removePlist(dir string, run Runner, out io.Writer) error {
	path := filepath.Join(dir, Label+".plist")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		say(out, "not installed: %s does not exist", path)
		return nil
	}
	if err := checkManaged(path, plistMarkStart); err != nil {
		return err
	}
	if o, err := run("launchctl", "bootout", "system/"+Label); err != nil {
		say(out, "warning: launchctl bootout: %v: %s", err, trim(o)) // it may not be loaded
	}
	if _, err := removeManaged(path, plistMarkStart); err != nil {
		return err
	}
	say(out, "removed %s", path)
	return nil
}

func trim(b []byte) string {
	s := string(b)
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}
