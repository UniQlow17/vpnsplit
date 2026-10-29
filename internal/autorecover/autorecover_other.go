//go:build !unix && !windows

package autorecover

import (
	"fmt"
	"io"
	"runtime"
)

// Install is not supported on this system.
func Install(string, io.Writer) error {
	return fmt.Errorf("install-recover is not supported on %s", runtime.GOOS)
}

// Remove is not supported on this system.
func Remove(io.Writer) error {
	return fmt.Errorf("install-recover is not supported on %s", runtime.GOOS)
}
