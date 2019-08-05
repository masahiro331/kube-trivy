package trivy

import (
	"fmt"
	"strings"

	"github.com/genuinetools/reg/registry"

	"github.com/knqyf263/trivy/pkg/log"
	"github.com/knqyf263/trivy/pkg/report"
	"github.com/knqyf263/trivy/pkg/scanner"
	"github.com/knqyf263/trivy/pkg/types"
	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"
	"golang.org/x/xerrors"
)

// type Scanner struct {
// 	ScanImage func(imageName, filePath string, scanOptions types.ScanOptions) (map[string][]vulnerability.DetectedVulnerability, error)
// }
//
// func NewScanner() *Scanner {
// 	return &Scanner{
// 		ScanImage: scanner.ScanImage,
// 	}
// }

func Scan(imageMap map[string]map[string][]string) map[string]report.Results {
	var resultsMap map[string]report.Results = map[string]report.Results{}
	// resourcesName: e.g. deployment
	for resourcesName, resources := range imageMap {
		// name: metadata.name
		for name, resource := range resources {
			for _, imageName := range resource {
				results, err := scan(imageName)
				if err != nil {
					log.Logger.Warn(err)
				}
				resultsMap[fmt.Sprintf("%s-%s-%s", resourcesName, name, imageName)] = results
			}
		}
	}
	return resultsMap
}

func scan(imageName string) (results report.Results, err error) {
	// Check whether 'latest' tag is used
	if imageName != "" {
		image, err := registry.ParseImage(imageName)
		if err != nil {
			return nil, xerrors.Errorf("invalid image: %w", err)
		}
		if image.Tag == "latest" && !config.ClearCache {
			log.Logger.Warn("You should avoid using the :latest tag as it is cached. You need to specify '--clear-cache' option when :latest image is changed")
		}
	}

	scanOptions := types.ScanOptions{VulnType: strings.Split(config.VulnType, ",")}

	log.Logger.Debugf("Vulnerability type:  %s", scanOptions.VulnType)

	vulns, err := scanner.ScanImage(imageName, "", scanOptions)
	if err != nil {
		return nil, xerrors.Errorf("error in image scan: %w", err)
	}

	for path, vuln := range vulns {
		results = append(results, report.Result{
			FileName:        path,
			Vulnerabilities: vulnerability.FillAndFilter(vuln, severities, config.IgnoreUnfixed),
		})
	}

	return results, nil
}
