package autorecover

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

// The job does not start the program the user ran: a directory that user owns
// (or can rename, or turn into a junction) would decide what runs as SYSTEM or
// root. install-recover copies the program into a fixed directory of the system
// (config.MachineProgramDir) and the job starts the copy. The directory carries
// a marker file; only a directory and a copy with the marker are ever replaced
// or removed. After vpnsplit is updated, run install-recover again to update
// the copy.

func programFileName() string {
	if runtime.GOOS == "windows" {
		return "vpnsplit.exe"
	}
	return "vpnsplit"
}

const markerText = Mark + ": the copy of vpnsplit that `vpnsplit install-recover` made for the job that runs `vpnsplit recover`; removed by `vpnsplit install-recover --remove`\n"

// installProgram puts the copy of the program src into the fixed directory and
// returns the path of the copy, checked: that is what the job gets.
func installProgram(src string, out io.Writer) (string, error) {
	dir, err := config.MachineProgramDir()
	if err != nil {
		return "", err
	}
	dir, err = config.EnsureProgramDir(dir)
	if err != nil {
		return "", fmt.Errorf("the directory for the program of the job: %w", err)
	}
	dest := filepath.Join(dir, programFileName())
	if err := copyProgram(src, dir, dest); err != nil {
		return "", err
	}
	full, err := config.VerifyInstalledProgram(dest)
	if err != nil {
		return "", fmt.Errorf("the copy %s cannot be trusted: %w", dest, err)
	}
	if err := ValidExePath(runtime.GOOS, full); err != nil {
		return "", err
	}
	say(out, "copied the program to %s (run install-recover again after updating vpnsplit)", full)
	return full, nil
}

// copyProgram copies the regular file src to dest in dir, atomically: written
// next to its place (a new file, never through a link) and moved there.
func copyProgram(src, dir, dest string) error {
	real, err := filepath.EvalSymlinks(src)
	if err != nil {
		return err
	}
	fi, err := os.Lstat(real)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file", real)
	}
	in, err := os.Open(real)
	if err != nil {
		return err
	}
	defer in.Close()
	fi2, err := in.Stat()
	if err != nil {
		return err
	}
	if !fi2.Mode().IsRegular() || !os.SameFile(fi, fi2) {
		return fmt.Errorf("%s changed while it was read", real)
	}

	marker := filepath.Join(dir, config.ProgramMarkName)
	if _, err := os.Lstat(dest); err == nil {
		if _, err := os.Lstat(marker); err != nil {
			return fmt.Errorf("%s exists and has no mark of vpnsplit: %w", dest, ErrNotOurs)
		}
		if err := checkManaged(marker, Mark); err != nil {
			return fmt.Errorf("%s exists and has no mark of vpnsplit: %w", dest, ErrNotOurs)
		}
		if di, err := os.Lstat(dest); err != nil || !di.Mode().IsRegular() {
			return fmt.Errorf("%s: %w", dest, ErrNotOurs)
		} else if os.SameFile(di, fi2) {
			return nil // started from the copy itself
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writeManaged(marker, []byte(markerText), Mark, 0o644); err != nil {
		return err
	}

	tmp := dest + ".tmp"
	_ = os.Remove(tmp) // a leftover of a failed run, in a directory only the system can write
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if _, err := io.Copy(f, in); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replace %s (is it running?): %w", dest, err)
	}
	return nil
}

// removeProgram deletes the copy and the marker, and the directory if nothing
// else is in it. Nothing is touched without the marker.
func removeProgram(out io.Writer) error {
	dir, err := config.MachineProgramDir()
	if err != nil {
		return err
	}
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	dir, err = config.CheckProgramDir(dir)
	if err != nil {
		return fmt.Errorf("the directory of the copy: %w", err)
	}
	return removeCopy(dir, out)
}

// removeCopy is removeProgram for a directory that has been judged.
func removeCopy(dir string, out io.Writer) error {
	marker := filepath.Join(dir, config.ProgramMarkName)
	if _, err := os.Lstat(marker); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := checkManaged(marker, Mark); err != nil {
		return err
	}
	dest := filepath.Join(dir, programFileName())
	if fi, err := os.Lstat(dest); err == nil {
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%s: %w", dest, ErrNotOurs)
		}
		if err := os.Remove(dest); err != nil {
			return fmt.Errorf("remove %s (is it running?): %w", dest, err)
		}
		say(out, "removed %s", dest)
	}
	if err := os.Remove(marker); err != nil {
		return err
	}
	_ = os.Remove(dir) // only if empty; else somebody else's files stay
	return nil
}
