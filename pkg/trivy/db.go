package trivy

import (
	"encoding/json"
	"reflect"

	bolt "github.com/etcd-io/bbolt"
	"github.com/knqyf263/trivy/pkg/db"
	"github.com/knqyf263/trivy/pkg/report"
	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"
	"golang.org/x/xerrors"
)

const (
	rootBucket = "results"
	source     = "localhost"
)

func Put(tx *bolt.Tx, target string, result []vulnerability.DetectedVulnerability) error {
	root, err := tx.CreateBucketIfNotExists([]byte(rootBucket))
	if err != nil {
		return xerrors.Errorf("failed to create bucket: %w", err)
	}
	return db.Put(root, target, source, result)
}

func DBUpdate(target string, result []vulnerability.DetectedVulnerability) error {
	return db.Update(rootBucket, target, source, result)
}

func Get(target string) ([]byte, error) {
	values, err := db.ForEach(rootBucket, target)
	if err != nil {
		return nil, xerrors.Errorf("error in NVD get: %w", err)
	}
	if len(values) == 0 {
		return nil, nil
	}

	for _, result := range values {
		return result, nil
	}
	return nil, nil
}

func SaveScanResult(prefix string, rs report.Results) error {
	err := db.BatchUpdate(func(tx *bolt.Tx) error {
		for _, r := range rs {
			err := Put(tx, prefix+r.FileName, r.Vulnerabilities)
			if err != nil {
				return xerrors.Errorf("failed to put result: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func CompareResults(prefix string, rs report.Results) (report.Results, error) {
	var results report.Results
	for _, r := range rs {
		jsonBytes, err := Get(prefix + r.FileName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get DetectedVulnerability: %w", err)
		}
		if len(jsonBytes) == 0 {
			return rs, nil
		}

		dvMap := map[string]vulnerability.DetectedVulnerability{}
		for _, dv := range r.Vulnerabilities {
			dvMap[dv.VulnerabilityID+dv.PkgName+dv.InstalledVersion] = dv
		}

		var dvStructs []vulnerability.DetectedVulnerability
		if err := json.Unmarshal(jsonBytes, &dvStructs); err != nil {
			return nil, xerrors.Errorf("failed to unmarshal json: %w", err)
		}

		var resultVulns []vulnerability.DetectedVulnerability
		for _, dv := range dvStructs {
			if !reflect.DeepEqual(dv, dvMap[dv.VulnerabilityID+dv.PkgName+dv.InstalledVersion]) {
				resultVulns = append(resultVulns, dvMap[dv.VulnerabilityID+dv.PkgName+dv.InstalledVersion])
			}
		}
		results = append(results, report.Result{FileName: r.FileName, Vulnerabilities: resultVulns})
	}
	return results, nil
}
