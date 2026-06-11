package sysinfo

import "context"

// WatchClipboard polls the system clipboard and calls onData when content
// changes. The label is "clipboard". Blocks until ctx is cancelled.
func WatchClipboard(ctx context.Context, onData func(data []byte, label string)) error {
	return watchClipboard(ctx, onData)
}
