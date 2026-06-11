//go:build !emptytemplates
// +build !emptytemplates

package pkg

import (
	_ "embed"

	"github.com/chainreactors/utils/encode"
)

//go:embed data/found_keys.bin
var foundKeysData []byte

//go:embed data/found_spray.bin
var foundSprayData []byte

//go:embed data/found_auto.bin
var foundAutoData []byte

//go:embed data/found_filter_ext.bin
var foundFilterExtData []byte

//go:embed data/found_filter_dir.bin
var foundFilterDirData []byte


func loadEmbeddedConfig(typ string) []byte {
	if typ == "found_keys" {
		return encode.MustDeflateDeCompress(foundKeysData)
	}else if typ == "found_spray" {
		return encode.MustDeflateDeCompress(foundSprayData)
	}else if typ == "found_auto" {
		return encode.MustDeflateDeCompress(foundAutoData)
	}else if typ == "found_filter_ext" {
		return encode.MustDeflateDeCompress(foundFilterExtData)
	}else if typ == "found_filter_dir" {
		return encode.MustDeflateDeCompress(foundFilterDirData)
	}
	return nil
}
