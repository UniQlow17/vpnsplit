package tui

import (
	"os"
	"sync"

	"github.com/UniQlow17/vpnsplit/internal/termsize"
)

// windowRestore keeps the way to put the window back as it was before the
// first enlargement. The window is fitted twice (at the start, for the empty
// menu, and once the first status is in, when the menu is longer); the second
// call must not replace the first one's restore, which knows the real original
// size: it would put back the already enlarged window.
type windowRestore struct {
	mu   sync.Mutex
	f    func()
	done bool
}

// set remembers f unless there is a restore already. After do has run it calls
// f at once, so a resize that finishes late is not left in place.
func (w *windowRestore) set(f func()) {
	if f == nil {
		return
	}
	w.mu.Lock()
	switch {
	case w.done:
		w.mu.Unlock()
		f()
		return
	case w.f == nil:
		w.f = f
	}
	w.mu.Unlock()
}

// do puts the window back; safe to call more than once.
func (w *windowRestore) do() {
	w.mu.Lock()
	f := w.f
	w.f, w.done = nil, true
	w.mu.Unlock()
	if f != nil {
		f()
	}
}

// fit enlarges the window to want and remembers how to undo it.
func (w *windowRestore) fit(want termsize.Size) {
	if res := termsize.Fit(want, os.Stdout); res.Resized {
		w.set(res.Restore)
	}
}
