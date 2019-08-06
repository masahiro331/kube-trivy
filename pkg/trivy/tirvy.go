package trivy

import (
	"os"
	"strings"

	"github.com/knqyf263/fanal/cache"
	"github.com/knqyf263/trivy/pkg/log"
	"github.com/knqyf263/trivy/pkg/utils"
	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"
	"golang.org/x/xerrors"
)

var severities []vulnerability.Severity
var config TrivyConf

type TrivyConf struct {
	ClearCache     bool
	SeverityFilter string
	Debug          bool
	Quiet          bool
	CacheDir       string
	Reset          bool
	NoTarget       bool
	IgnoreUnfixed  bool
	VulnType       string
	Format         string
	Refresh        bool
	AutoRefresh    bool
	SkipUpdate     bool
	OnlyUpdate     string
}

func Init(conf *TrivyConf) error {
	config = *conf
	if err := log.InitLogger(config.Debug); err != nil {
		return xerrors.Errorf("error in init logger", err)
	}
	log.Logger.Debugf("cache dir:  %s", utils.CacheDir())

	if config.CacheDir != "" {
		utils.SetCacheDir(config.CacheDir)
	}

	reset := config.Reset
	if reset {
		log.Logger.Info("Resetting...")
		if err := cache.Clear(); err != nil {
			return xerrors.New("failed to remove image layer cache")
		}
		if err := os.RemoveAll(utils.CacheDir()); err != nil {
			return xerrors.New("failed to remove cache")
		}
		return nil
	}

	if config.ClearCache {
		log.Logger.Info("Removing image caches...")
		if err := cache.Clear(); err != nil {
			return xerrors.New("failed to remove image layer cache")
		}
	}

	if config.NoTarget {
		if !config.Reset && !config.ClearCache {
			// cli.ShowAppHelpAndExit(c, 1)
			return xerrors.New("please -h")
		}
		return nil
	}

	for _, s := range strings.Split(config.SeverityFilter, ",") {
		severity, err := vulnerability.NewSeverity(s)
		if err != nil {
			return xerrors.Errorf("error in severity option: %v", err)
		}
		severities = append(severities, severity)
	}
	return nil
}

/*
c.String("severity")
c.Bool("debug")
c.Bool("quiet")
c.String("cache-dir")
c.Bool("reset")
conf.Bool("clear-cache")
*/
