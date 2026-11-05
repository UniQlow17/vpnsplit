//go:build unix

package autorecover

import (
	"fmt"
	"io"
	"path/filepath"
	"runtime"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/sysexec"
)

// Install makes `vpnsplit recover` run at every boot, as root: a systemd unit
// (Linux) or a LaunchDaemon (macOS). The job starts a copy of exe made in a
// directory of root (see program.go); exe may be anywhere. The caller must be root.
func Install(exe string, out io.Writer) error {
	switch runtime.GOOS {
	case "linux":
		if err := config.ProtectedDir(unitDir); err != nil {
			return err
		}
		if _, err := sysexec.LookPath("systemctl"); err != nil {
			return fmt.Errorf("systemd was not found (%w): install-recover supports systemd only", err)
		}
		// somebody else's unit: refuse before a copy of the program is made
		if err := checkManaged(filepath.Join(unitDir, UnitName), unitMark); err != nil {
			return err
		}
	case "darwin":
		if err := config.ProtectedDir(plistDir); err != nil {
			return err
		}
		if err := checkManaged(filepath.Join(plistDir, Label+".plist"), plistMarkStart); err != nil {
			return err
		}
	default:
		return fmt.Errorf("install-recover is not supported on %s", runtime.GOOS)
	}
	full, err := installProgram(exe, out)
	if err != nil {
		return err
	}
	if runtime.GOOS == "linux" {
		return installUnit(unitDir, full, sysRun, out)
	}
	return installPlist(plistDir, full, sysRun, out, true)
}

// Remove deletes the job made by Install, if it is ours; somebody else's job of
// the same name is left alone.
func Remove(out io.Writer) error {
	switch runtime.GOOS {
	case "linux":
		if err := config.ProtectedDir(unitDir); err != nil {
			return err
		}
		if err := removeUnit(unitDir, sysRun, out); err != nil {
			return err
		}
		return removeProgram(out)
	case "darwin":
		if err := config.ProtectedDir(plistDir); err != nil {
			return err
		}
		if err := removePlist(plistDir, sysRun, out); err != nil {
			return err
		}
		return removeProgram(out)
	}
	return fmt.Errorf("install-recover is not supported on %s", runtime.GOOS)
}
