package templates

import (
	"github.com/chainreactors/proton/protocols/executer"
	"github.com/chainreactors/proton/protocols/file"
)

type Template struct {
	Id      string   `json:"id" yaml:"id"`
	Fingers []string `json:"finger" yaml:"finger"`
	Chains  []string `json:"chain" yaml:"chain"`
	Opsec   bool     `json:"opsec" yaml:"opsec"`
	Info    struct {
		Name string `json:"name" yaml:"name"`
		//Author    string `json:"author"`
		Severity    string `json:"severity" yaml:"severity"`
		Description string `json:"description" yaml:"description"`
		//Reference string `json:"reference"`
		//Vendor    string `json:"vendor"`
		Tags string `json:"tags" yaml:"tags"`
	} `json:"info" yaml:"info"`
	//RequestsHTTP    []*http.Request    `json:"http" yaml:"http"`
	//RequestsNetwork []*network.Request `json:"network" yaml:"network"`
	RequestsFile []*file.Request `json:"file" yaml:"file"`

	// TotalRequests is the total number of requests for the template.
	TotalRequests int `yaml:"-" json:"-"`
	// Executor is the actual template executor for running template requests
	Executor *executer.Executer `yaml:"-" json:"-"`
}
