//go:build linux
// +build linux

package file

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseMapsLine(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		ok     bool
		base   uint64
		size   uint64
		perms  string
		mapped string
	}{
		{
			"heap", "7f1234560000-7f1234570000 rw-p 00000000 00:00 0                          [heap]",
			true, 0x7f1234560000, 0x10000, "rw-p", "[heap]",
		},
		{
			"library", "7f0000100000-7f0000200000 r-xp 00001000 08:01 1234 /usr/lib/libc.so.6",
			true, 0x7f0000100000, 0x100000, "r-xp", "/usr/lib/libc.so.6",
		},
		{
			"anonymous", "55a000000000-55a000001000 rw-p 00000000 00:00 0",
			true, 0x55a000000000, 0x1000, "rw-p", "",
		},
		{"empty", "", false, 0, 0, "", ""},
		{"bad format", "not-a-valid-line", false, 0, 0, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			region, ok := parseMapsLine(tt.line)
			assert.Equal(t, tt.ok, ok)
			if ok {
				assert.Equal(t, tt.base, region.BaseAddr)
				assert.Equal(t, tt.size, region.Size)
				assert.Equal(t, tt.perms, region.Perms)
				assert.Equal(t, tt.mapped, region.MappedFile)
			}
		})
	}
}
