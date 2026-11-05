package main

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/UniQlow17/vpnsplit/internal/cli"
	"github.com/UniQlow17/vpnsplit/internal/lifecycle"
)

// version is set at release time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run())
}

// run is the last line of defence: whatever escapes the commands (they end
// their sessions by themselves, see tui.Run and cli) still gets a message and
// a non-zero exit code instead of a bare stack trace and an unknown state.
func run() (code int) {
	// the last: the icon of the tray and the console window are put right even when nothing else did
	defer lifecycle.RunAtExit()
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "\nvpnsplit: internal error: %v\n%s\nThe journal of routes is kept: `vpnsplit reset` or the next start removes what is left.\n", r, debug.Stack())
			code = 2
		}
	}()
	return cli.Run(os.Args[1:], version)
}
