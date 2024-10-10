package templates

import (
	"github.com/chainreactors/proton/common"
	"github.com/chainreactors/proton/operators"
	"github.com/chainreactors/proton/protocols"
	"github.com/chainreactors/proton/protocols/executer"
	"strings"
)

func (t *Template) GetTags() []string {
	if t.Info.Tags != "" {
		return strings.Split(t.Info.Tags, ",")
	}
	return []string{}

}

func (t *Template) Compile(options *protocols.ExecuterOptions) error {
	var requests []protocols.Request
	var err error
	if len(t.RequestsFile) > 0 {
		for _, req := range t.RequestsFile {
			requests = append(requests, req)
		}
		t.Executor = executer.NewExecuter(requests, options)
	}
	if t.Executor != nil {
		err = t.Executor.Compile()
		if err != nil {
			return err
		}
		t.TotalRequests += t.Executor.Requests()
	}
	return nil
}

func (t *Template) Execute(input string, payload map[string]interface{}) (*operators.Result, error) {
	if t.Executor.Options().Options.Opsec && t.Opsec {
		common.NeutronLog.Debugf("(opsec!!!) skip template %s", t.Id)
		return nil, protocols.OpsecError
	}
	return t.Executor.Execute(protocols.NewScanContext(input, payload))
}
