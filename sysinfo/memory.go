package sysinfo

// MemoryRegion describes a contiguous memory mapping in a process's address space.
type MemoryRegion struct {
	BaseAddr   uint64
	Size       uint64
	Perms      string
	MappedFile string
}

// MemoryReader provides access to a process's memory regions and contents.
type MemoryReader interface {
	Regions() ([]MemoryRegion, error)
	ReadAt(buf []byte, addr uint64) (int, error)
	Close() error
}
