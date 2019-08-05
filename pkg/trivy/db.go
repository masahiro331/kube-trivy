package trivy

import (
	"strings"

	"github.com/knqyf263/trivy/pkg/db"
	"github.com/knqyf263/trivy/pkg/log"
	"github.com/knqyf263/trivy/pkg/vulnsrc"
	"golang.org/x/xerrors"
)

func InitDB() error {
	if config.Refresh || config.AutoRefresh {
		if config.SkipUpdate {
			return xerrors.New("The --skip-update option can not be specified with the --refresh or --auto-refresh option")
		}
		if config.OnlyUpdate != "" {
			return xerrors.New("The --only-update option can not be specified with the --refresh or --auto-refresh option")
		}
	}
	if config.SkipUpdate && config.OnlyUpdate != "" {
		return xerrors.New("The --skip-update and --only-update option can not be specified both")
	}

	if err := db.Init(); err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}
	return nil
}

func UpdateDB(cliVersion string) error {
	needRefresh := false
	dbVersion := db.GetVersion()
	if dbVersion != "" && dbVersion != cliVersion {
		if !config.Refresh && !config.AutoRefresh {
			return xerrors.New("Detected version update of kubetrivy. Please try again with --refresh or --auto-refresh option")
		}
		needRefresh = true
	}

	if config.Refresh || needRefresh {
		log.Logger.Info("Refreshing DB...")
		if err := db.Reset(); err != nil {
			return xerrors.Errorf("error in refresh DB: %w", err)
		}
	}

	updateTargets := vulnsrc.UpdateList
	if config.OnlyUpdate != "" {
		log.Logger.Warn("The --only-update option may cause the vulnerability details such as severity and title not to be displayed")
		updateTargets = strings.Split(config.OnlyUpdate, ",")
	}

	if !config.SkipUpdate {
		if err := vulnsrc.Update(updateTargets); err != nil {
			return xerrors.Errorf("error in vulnerability DB update: %w", err)
		}
	}

	if err := db.SetVersion(cliVersion); err != nil {
		return xerrors.Errorf("unexpected error: %w", err)
	}

	return nil
}
