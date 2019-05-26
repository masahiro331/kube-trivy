package trivy

import (
	l "log"
	"os"
	"strings"

	"github.com/knqyf263/fanal/cache"
	"github.com/knqyf263/kube-trivy/pkg/config"
	"github.com/knqyf263/trivy/pkg/db"
	"github.com/knqyf263/trivy/pkg/log"
	"github.com/knqyf263/trivy/pkg/report"
	"github.com/knqyf263/trivy/pkg/scanner"
	"github.com/knqyf263/trivy/pkg/utils"
	"github.com/knqyf263/trivy/pkg/vulnsrc"
	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"
	"golang.org/x/xerrors"
)

var Conf config.TrivyConf

func Init(conf config.TrivyConf) error {
	Conf = conf

	utils.Quiet = Conf.Quiet
	if Conf.CacheDir != "" {
		utils.SetCacheDir(Conf.CacheDir)
	}
	if err := log.InitLogger(Conf.Debug); err != nil {
		l.Fatal(err)
	}
	log.Logger.Debugf("cache dir:  %s", utils.CacheDir())

	if Conf.Reset {
		log.Logger.Info("Resetting...")
		if err := cache.Clear(); err != nil {
			return xerrors.New("failed to remove image layer cache")
		}
		if err := os.RemoveAll(utils.CacheDir()); err != nil {
			return xerrors.New("failed to remove cache")
		}
		return nil
	}

	if Conf.ClearCache {
		log.Logger.Info("Removing image caches...")
		if err := cache.Clear(); err != nil {
			return xerrors.New("failed to remove image layer cache")
		}
	}

	if (Conf.Refresh || Conf.AutoRefresh) && Conf.SkipUpdate {
		return xerrors.New("The --skip-update option can not be specified with the --refresh or --auto-refresh option")
	}

	if err := db.Init(); err != nil {
		l.Fatalf("error in vulnerability DB initialize: %w", err)
	}
	return nil
}

func Update() error {
	if Conf.SkipUpdate {
		return nil
	}
	if err := vulnsrc.Update(); err != nil {
		l.Fatalf("error in vulnerability DB update: %w", err)
	}
	return nil
}

func ScanImage(imageName string) error {
	vulns, err := scanner.ScanImage(imageName, "")

	var results report.Results
	var severities []vulnerability.Severity
	for _, s := range strings.Split(Conf.Severity, ",") {
		severity, err := vulnerability.NewSeverity(s)
		if err != nil {
			log.Logger.Infof("error in severity option: %s", err)
		}
		severities = append(severities, severity)
	}
	for path, vuln := range vulns {
		results = append(results, report.Result{
			FileName:        path,
			Vulnerabilities: vulnerability.FillAndFilter(vuln, severities, Conf.IgnoreUnfixed),
		})
	}

	var writer report.Writer
	switch Conf.Format {
	case "table":
		writer = &report.TableWriter{Output: os.Stdout}
	case "json":
		writer = &report.JsonWriter{Output: os.Stdout}
	default:
		return xerrors.Errorf("unknown format: %v", Conf.Format)
	}

	if err = writer.Write(results); err != nil {
		return xerrors.Errorf("failed to write results: %w", err)
	}

	return nil
}
