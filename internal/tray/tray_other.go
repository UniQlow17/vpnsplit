//go:build !windows

package tray

// Start: there is no tray outside Windows (see the package comment).
func Start(Commands) (Tray, error) { return nil, ErrUnsupported }

// ConsoleCanHide: the console window is not hidden outside Windows.
func ConsoleCanHide() bool { return false }

// ConsoleHide does nothing.
func ConsoleHide() bool { return false }

// ConsoleShow does nothing.
func ConsoleShow() {}

// ConsoleHidden is always false.
func ConsoleHidden() bool { return false }
