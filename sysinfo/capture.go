package sysinfo

// CaptureHandle abstracts a platform-specific packet capture source.
type CaptureHandle interface {
	Read(buf []byte) (int, error)
	Close() error
	HasEthernetHeader() bool
}
