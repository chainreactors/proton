//go:build !emptytemplates
// +build !emptytemplates

package pkg

var RandomDir = "/g8kZMwp4oeKsL2in"

func LoadConfig(typ string) []byte {
	return loadEmbeddedConfig(typ)
}
