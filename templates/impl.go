package templates

import (
	"errors"
	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/protocols/executer"
	"strings"
)

func (t *Template) GetTags() []string {
	if t.Info.Tags != "" {
		return strings.Split(t.Info.Tags, ",")
	}
	return []string{}
}

func (t *Template) Compile(options *protocols.ExecuterOptions) error {
	if options == nil {
		options = &protocols.ExecuterOptions{Options: &protocols.Options{}}
	}

	var requests []protocols.Request
	if len(t.RequestsFile) > 0 {
		for _, req := range t.RequestsFile {
			requests = append(requests, req)
		}
		t.Executor = executer.NewExecuter(requests, options)
	}
	if t.Executor != nil {
		if err := t.Executor.Compile(); err != nil {
			return err
		}
		t.TotalRequests += t.Executor.Requests()
		return nil
	}
	return errors.New("no requests defined in template")
}

func (t *Template) Execute(input string, payload map[string]interface{}) (*operators.Result, error) {
	if t.Executor.Options().Options.Opsec && t.Opsec {
		common.Logger().Debugf("(opsec!!!) skip template %s", t.Id)
		return nil, protocols.OpsecError
	}
	return t.Executor.Execute(protocols.NewScanContext(input, payload))
}
