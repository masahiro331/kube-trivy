package trivy

import (
	"github.com/knqyf263/trivy/pkg/types"
	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"
)

type ScanImage interface {
	ScanImage(imageName, filePath string, scanOptions types.ScanOptions) (map[string][]vulnerability.DetectedVulnerability, error)
}
