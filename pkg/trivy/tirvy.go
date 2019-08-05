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

var (
	clearCache     bool
	severityFilter string
	ignoreUnfixed  bool
	output         string
	vulnType       string
	format         string
	refresh        bool
	autoRefresh    bool
	skipUpdate     bool
	onlyUpdate     string
)

var severities []vulnerability.Severity

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
	if err := log.InitLogger(conf.Debug); err != nil {
		return xerrors.Errorf("error in init logger", err)
	}
	severityFilter = conf.SeverityFilter
	utils.Quiet = conf.Quiet
	vulnType = conf.VulnType
	cacheDir := conf.CacheDir
	ignoreUnfixed = conf.IgnoreUnfixed
	format = conf.Format
	log.Logger.Debugf("cache dir:  %s", utils.CacheDir())

	if conf.CacheDir != "" {
		utils.SetCacheDir(cacheDir)
	}

	reset := conf.Reset
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

	clearCache = conf.ClearCache
	if clearCache {
		log.Logger.Info("Removing image caches...")
		if err := cache.Clear(); err != nil {
			return xerrors.New("failed to remove image layer cache")
		}
	}

	if conf.NoTarget {
		if !reset && !clearCache {
			// cli.ShowAppHelpAndExit(c, 1)
			return xerrors.New("please -h")
		}
		return nil
	}

	for _, s := range strings.Split(severityFilter, ",") {
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
