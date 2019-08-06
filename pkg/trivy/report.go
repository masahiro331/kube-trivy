package trivy

import (
	"os"

	"github.com/knqyf263/trivy/pkg/report"
	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"
	v1 "github.com/masahiro331/kube-trivy/pkg/apis/kubetrivy/v1"
	"golang.org/x/xerrors"
)

type Results []Result
type Result report.Result

func Write(res *v1.Vulnerability) error {
	output := os.Stdout
	var results report.Results
	for _, target := range res.Spec.Targets {
		vulns := make([]vulnerability.DetectedVulnerability, len(target.Vulnerabilities))
		for i, vuln := range target.Vulnerabilities {
			vulns[i] = vulnerability.DetectedVulnerability(vuln)
		}
		result := report.Result{
			FileName:        target.Name,
			Vulnerabilities: vulnerability.FillAndFilter(vulns, severities, config.IgnoreUnfixed),
		}

		results = append(results, result)
	}

	var writer report.Writer
	switch config.Format {
	case "table":
		writer = &report.TableWriter{Output: output}
	case "json":
		writer = &report.JsonWriter{Output: output}
	default:
		return xerrors.Errorf("unknown format: %v", config.Format)
	}
	if err := writer.Write(results); err != nil {
		return xerrors.Errorf("failed to write results: %v", err)
	}
	return nil
}
