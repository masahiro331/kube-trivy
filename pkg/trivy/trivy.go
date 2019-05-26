package trivy

import (
	l "log"
	"os"
	"strings"

	"github.com/knqyf263/trivy/pkg/db"
	"github.com/knqyf263/trivy/pkg/log"
	"github.com/knqyf263/trivy/pkg/report"
	"github.com/knqyf263/trivy/pkg/scanner"
	"github.com/knqyf263/trivy/pkg/utils"
	"github.com/knqyf263/trivy/pkg/vulnsrc"
	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"
	"golang.org/x/xerrors"
)

func Init() error {
	cacheDir := "cache-dir"
	if cacheDir != "" {
		utils.SetCacheDir(cacheDir)
	}
	log.Logger.Debugf("cache dir:  %s", utils.CacheDir())

	if err := db.Init(); err != nil {
		l.Fatalf("error in vulnerability DB initialize: %w", err)
	}
	return nil
}

func Update() error {
	if err := vulnsrc.Update(); err != nil {
		l.Fatalf("error in vulnerability DB update: %w", err)
	}
	return nil
}

func ScanImage(imageName string) error {
	vulns, err := scanner.ScanImage(imageName, "")

	var results report.Results
	var severities []vulnerability.Severity
	for _, s := range strings.Split(strings.Join(vulnerability.SeverityNames, ","), ",") {
		severity, err := vulnerability.NewSeverity(s)
		if err != nil {
			log.Logger.Infof("error in severity option: %s", err)
		}
		severities = append(severities, severity)
	}
	ignoreUnfixed := false
	for path, vuln := range vulns {
		results = append(results, report.Result{
			FileName:        path,
			Vulnerabilities: vulnerability.FillAndFilter(vuln, severities, ignoreUnfixed),
		})
	}

	var writer report.Writer
	output := os.Stdout
	writer = &report.TableWriter{Output: output}

	if err = writer.Write(results); err != nil {
		return xerrors.Errorf("failed to write results: %w", err)
	}

	exitCode := 0
	if exitCode != 0 {
		for _, result := range results {
			if len(result.Vulnerabilities) > 0 {
				os.Exit(exitCode)
			}
		}
	}
	return nil
}
