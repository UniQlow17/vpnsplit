package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
)

const lastSessionFile = "last-session.log"

// maxLastSession bounds the file: it is a short note, rewritten each time.
const maxLastSession = 1024

// WriteLastSession records how the last session ended, in the protected
// journal directory (replacing the previous text). A closed console window
// leaves nobody to read the message, so the next start shows it.
func WriteLastSession(text string) error {
	dir, err := StateDir(true)
	if err != nil {
		return fmt.Errorf("last session: %w", err)
	}
	return writeLastSession(dir, text)
}

func writeLastSession(dir, text string) error {
	text = strings.TrimSpace(text)
	if len(text) > maxLastSession {
		text = strings.ToValidUTF8(text[:maxLastSession], "")
	}
	return writeFileAtomic(dir, lastSessionFile, []byte(text+"\n"), 0o600, nil)
}

// ReadLastSession returns the text left by WriteLastSession; "" if there is
// none or the directory is not readable (no administrator rights).
func ReadLastSession() string {
	dir, err := StateDir(false)
	if err != nil {
		return ""
	}
	return readLastSession(dir)
}

// readLastSession drops control characters: the file is shown on a terminal.
func readLastSession(dir string) string {
	b, err := readRegular(filepath.Join(dir, lastSessionFile))
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if len(s) > maxLastSession {
		s = strings.ToValidUTF8(s[:maxLastSession], "")
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}
