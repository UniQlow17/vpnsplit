package main

import (
	"os"

	"github.com/UniQlow17/vpnsplit/internal/cli"
)

// version is set at release time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(cli.Run(os.Args[1:], version))
}
