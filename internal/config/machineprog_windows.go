//go:build windows

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func machineProgramDir() (string, error) {
	pf, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return "", fmt.Errorf("find Program Files: %w", err)
	}
	return filepath.Join(pf, "vpnsplit"), nil
}

func pathsEqual(a, b string) bool { return strings.EqualFold(a, b) }

func ensureProgramDir(dir string) (string, error) {
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		if err := createProtectedDir(dir); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return "", fmt.Errorf("create %s: %w", dir, err)
		}
	} else if err != nil {
		return "", err
	}
	return checkProgramDir(dir)
}

func checkProgramDir(dir string) (string, error) {
	if err := noReparseOnWay(dir); err != nil {
		return "", err
	}
	if err := checkProtectedDir(dir); err != nil {
		return "", err
	}
	if err := ProtectedDir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

// noReparseOnWay fails if the path or any part of it is a reparse point
// (junction, symbolic link, mount point).
func noReparseOnWay(p string) error {
	vol := filepath.VolumeName(p)
	rest := strings.TrimPrefix(p, vol)
	cur := vol + `\`
	for _, part := range strings.Split(strings.Trim(rest, `\`), `\`) {
		if part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		u, err := windows.UTF16PtrFromString(cur)
		if err != nil {
			return err
		}
		a, err := windows.GetFileAttributes(u)
		if err != nil {
			return fmt.Errorf("%s: %w", cur, err)
		}
		if a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("%s is a reparse point (junction or link): refusing to use it", cur)
		}
	}
	return nil
}

// verifyFinalPath opens the file and asks the system for its final DOS path:
// it must be the path asked, so no junction or link led somewhere else.
func verifyFinalPath(full string) error {
	if err := noReparseOnWay(full); err != nil {
		return err
	}
	u, err := windows.UTF16PtrFromString(full)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(u, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", full, err)
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 1024)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), volumeNameDOS)
	if err != nil || int(n) > len(buf) {
		return fmt.Errorf("final path of %s: %v", full, err)
	}
	final, err := dosFinalPath(windows.UTF16ToString(buf[:n]))
	if err != nil {
		return fmt.Errorf("final path of %s: %w", full, err)
	}
	if !strings.EqualFold(final, full) {
		return fmt.Errorf("%s leads to %s: refusing a path through a link", full, final)
	}
	return nil
}

// dosFinalPath turns what GetFinalPathNameByHandle returns (`\\?\C:\dir`) into
// the plain path (`C:\dir`). A network share (`\\?\UNC\...`) is refused.
func dosFinalPath(p string) (string, error) {
	const prefix = `\\?\`
	if !strings.HasPrefix(p, prefix) {
		return p, nil
	}
	rest := p[len(prefix):]
	if len(rest) >= 4 && strings.EqualFold(rest[:4], `UNC\`) {
		return "", errors.New("the file is on a network share")
	}
	return rest, nil
}

// VOLUME_NAME_DOS of GetFinalPathNameByHandle.
const volumeNameDOS = 0
