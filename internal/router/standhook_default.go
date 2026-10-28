//go:build !(linux && vpnsplit_stand)

package router

// standDelay is a hook of the Linux test stand (see standhook_stand.go); the
// real program has none.
func standDelay() {}
