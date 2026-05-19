package file

import (
	"os"
	"testing"
	"time"

	"github.com/chainreactors/neutron/protocols"
	"gopkg.in/yaml.v3"
)

const credentialExposureYAML = "/tmp/nuclei-templates/file/keys/credential-exposure-file.yaml"
const privateKeyYAML = "/tmp/nuclei-templates/file/keys/private-key.yaml"

func loadFileRequest(tb testing.TB, yamlPath string, textOnly bool) *Request {
	tb.Helper()
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		tb.Skipf("template not found: %s", yamlPath)
		return nil
	}
	type tmpl struct {
		File []*Request `yaml:"file"`
	}
	var t tmpl
	if err := yaml.Unmarshal(data, &t); err != nil {
		tb.Fatalf("parse: %v", err)
		return nil
	}
	if len(t.File) == 0 {
		tb.Skipf("no file requests")
		return nil
	}
	opts := &protocols.ExecuterOptions{Options: &protocols.Options{TextOnly: textOnly}}
	if err := t.File[0].Compile(opts); err != nil {
		tb.Fatalf("compile: %v", err)
		return nil
	}
	return t.File[0]
}

func TestACFilter_RealScan(t *testing.T) {
	target := "/mnt/chainreactors/proton"
	if _, err := os.Stat(credentialExposureYAML); os.IsNotExist(err) {
		t.Skipf("template not found")
	}

	req := loadFileRequest(t, credentialExposureYAML, true)

	t.Log("Scanning /mnt/chainreactors/proton with credential-exposure (690 regex, AC pre-filter)...")
	start := time.Now()
	var findings int
	ctx := protocols.NewScanContext(target, nil)
	req.ExecuteWithResults(ctx, nil, nil, func(event *protocols.InternalWrappedEvent) {
		if event != nil && event.OperatorsResult != nil {
			findings += len(event.OperatorsResult.OutputExtracts)
		}
	})
	elapsed := time.Since(start)
	t.Logf("Result: %d findings in %s", findings, elapsed.Round(time.Millisecond))
}

func BenchmarkACFilter_CredentialExposure(b *testing.B) {
	if _, err := os.Stat(credentialExposureYAML); os.IsNotExist(err) {
		b.Skipf("template not found")
	}

	target := "/mnt/chainreactors/proton"
	req := loadFileRequest(b, credentialExposureYAML, true)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := protocols.NewScanContext(target, nil)
		req.ExecuteWithResults(ctx, nil, nil, func(event *protocols.InternalWrappedEvent) {})
	}
}

func BenchmarkACFilter_PrivateKey(b *testing.B) {
	if _, err := os.Stat(privateKeyYAML); os.IsNotExist(err) {
		b.Skipf("template not found")
	}

	target := "/mnt/chainreactors/proton"
	req := loadFileRequest(b, privateKeyYAML, true)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := protocols.NewScanContext(target, nil)
		req.ExecuteWithResults(ctx, nil, nil, func(event *protocols.InternalWrappedEvent) {})
	}
}
