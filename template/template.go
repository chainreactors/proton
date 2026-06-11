package template

import (
	"github.com/chainreactors/proton/proton/file"
	"github.com/chainreactors/proton/proton/sys"
)

type Template struct {
	Id      string   `json:"id" yaml:"id"`
	Fingers []string `json:"finger" yaml:"finger"`
	Chains  []string `json:"chain" yaml:"chain"`
	Opsec   bool     `json:"opsec" yaml:"opsec"`
	Info    struct {
		Name        string `json:"name" yaml:"name"`
		Severity    string `json:"severity" yaml:"severity"`
		Description string `json:"description" yaml:"description"`
		Tags        string `json:"tags" yaml:"tags"`
	} `json:"info" yaml:"info"`

	RequestsFile []*file.Request `json:"file" yaml:"file"`
	RequestsSys  []*sys.Request  `json:"sys" yaml:"sys"`

	TotalRequests int `yaml:"-" json:"-"`

	scanner *file.Scanner `yaml:"-" json:"-"`
}
