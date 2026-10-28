//go:build linux && vpnsplit_stand

package router

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// standSlowFile holds a number of seconds. Only the binary of the test stand
// (go build -tags vpnsplit_stand) looks at it: it makes removals slow, as a
// loaded system would, to test the time limits of the cleanup.
const standSlowFile = "/tmp/stand/slow-del"

func standDelay() {
	b, err := os.ReadFile(standSlowFile)
	if err != nil {
		return
	}
	if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n > 0 {
		time.Sleep(time.Duration(n) * time.Second)
	}
}
