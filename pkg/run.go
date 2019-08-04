package pkg

import (
	"fmt"
	l "log"
	"os"
	"strings"

	"github.com/genuinetools/reg/registry"
	"github.com/knqyf263/fanal/cache"
	"github.com/knqyf263/trivy/pkg/log"
	"github.com/knqyf263/trivy/pkg/report"
	"github.com/knqyf263/trivy/pkg/scanner"
	"github.com/knqyf263/trivy/pkg/types"
	"github.com/knqyf263/trivy/pkg/utils"
	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"
	"github.com/urfave/cli"

	"github.com/knqyf263/kube-trivy/pkg/kubetrivy"
	"github.com/knqyf263/trivy/pkg/db"
	"github.com/knqyf263/trivy/pkg/vulnsrc"
	"golang.org/x/xerrors"
)

var (
	noTarget       = false
	clearCache     = false
	o              = ""
	severityfilter = ""
	vulnType       = ""
	ignoreUnfixed  = false
	format         = "table"
	exitCode       = 0
)

func Run(c *cli.Context) error {
	if err := log.InitLogger(c.Bool("debug")); err != nil {
		return xerrors.Errorf("error in init logger", err)
	}

	if err := dbUpdate(c); err != nil {
		return xerrors.Errorf("error in dbUpdate: %w", err)
	}

	if noTarget {
		return nil
	}

	client := kubetrivy.NewKubeTrivy(c.String("namespace"))
	imageMap, err := client.GetImages()
	if err != nil {
		return xerrors.Errorf("error in get images in kubernetes: %w", err)
	}

	o = c.String("output")
	severityfilter = c.String("severity")
	vulnType = c.String("vuln-type")
	ignoreUnfixed = c.Bool("ignore-unfixed")
	format = c.String("format")
	exitCode = c.Int("exit-code")
	// resourcesName: e.g. deployment
	for resourcesName, resources := range imageMap {
		// name: metadata.name
		for name, resource := range resources {
			for _, imageName := range resource {
				results, err := scan(imageName)
				if err != nil {
					log.Logger.Warn(err)
				}
				if err := client.CreateVulnerability(fmt.Sprintf("%s-%s-%s", resourcesName, name, imageName), results); err != nil {
					log.Logger.Warn(err)
				}

			}
		}
	}

	if err := client.GetVulnerability(); err != nil {
		return xerrors.Errorf("failed to get vulnerability", err)
	}

	return nil
}

func scan(imageName string) (reports report.Results, err error) {
	output := os.Stdout
	if o != "" {
		if output, err = os.Create(o); err != nil {
			return nil, xerrors.Errorf("failed to create an output file: %w", err)
		}
	}

	var severities []vulnerability.Severity
	for _, s := range strings.Split(severityfilter, ",") {
		severity, err := vulnerability.NewSeverity(s)
		if err != nil {
			return nil, xerrors.Errorf("error in severity option: %w", err)
		}
		severities = append(severities, severity)
	}

	// Check whether 'latest' tag is used
	if imageName != "" {
		image, err := registry.ParseImage(imageName)
		if err != nil {
			return nil, xerrors.Errorf("invalid image: %w", err)
		}
		if image.Tag == "latest" && !clearCache {
			log.Logger.Warn("You should avoid using the :latest tag as it is cached. You need to specify '--clear-cache' option when :latest image is changed")
		}
	}

	scanOptions := types.ScanOptions{VulnType: strings.Split(vulnType, ",")}

	log.Logger.Debugf("Vulnerability type:  %s", scanOptions.VulnType)

	vulns, err := scanner.ScanImage(imageName, "", scanOptions)
	if err != nil {
		return nil, xerrors.Errorf("error in image scan: %w", err)
	}

	for path, vuln := range vulns {
		reports = append(reports, report.Result{
			FileName:        path,
			Vulnerabilities: vulnerability.FillAndFilter(vuln, severities, ignoreUnfixed),
		})
	}

	var writer report.Writer
	switch format {
	case "table":
		writer = &report.TableWriter{Output: output}
	case "json":
		writer = &report.JsonWriter{Output: output}
	default:
		return nil, xerrors.Errorf("unknown format: %v", format)
	}

	if err = writer.Write(reports); err != nil {
		return nil, xerrors.Errorf("failed to write reports: %w", err)
	}

	if exitCode != 0 {
		for _, report := range reports {
			if len(report.Vulnerabilities) > 0 {
				os.Exit(exitCode)
			}
		}
	}
	return reports, nil

}

func dbUpdate(c *cli.Context) error {
	cliVersion := c.App.Version

	utils.Quiet = c.Bool("quiet")
	debug := c.Bool("debug")
	if err := log.InitLogger(debug); err != nil {
		l.Fatal(err)
	}

	cacheDir := c.String("cache-dir")
	if cacheDir != "" {
		utils.SetCacheDir(cacheDir)
	}

	log.Logger.Debugf("cache dir:  %s", utils.CacheDir())

	reset := c.Bool("reset")
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

	clearCache = c.Bool("clear-cache")
	if clearCache {
		log.Logger.Info("Removing image caches...")
		if err := cache.Clear(); err != nil {
			return xerrors.New("failed to remove image layer cache")
		}
	}

	refresh := c.Bool("refresh")
	autoRefresh := c.Bool("auto-refresh")
	skipUpdate := c.Bool("skip-update")
	onlyUpdate := c.String("only-update")
	if refresh || autoRefresh {
		if skipUpdate {
			return xerrors.New("The --skip-update option can not be specified with the --refresh or --auto-refresh option")
		}
		if onlyUpdate != "" {
			return xerrors.New("The --only-update option can not be specified with the --refresh or --auto-refresh option")
		}
	}
	if skipUpdate && onlyUpdate != "" {
		return xerrors.New("The --skip-update and --only-update option can not be specified both")
	}

	if err := db.Init(); err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}

	needRefresh := false
	dbVersion := db.GetVersion()
	if dbVersion != "" && dbVersion != cliVersion {
		if !refresh && !autoRefresh {
			return xerrors.New("Detected version update of kubetrivy. Please try again with --refresh or --auto-refresh option")
		}
		needRefresh = true
	}

	if refresh || needRefresh {
		log.Logger.Info("Refreshing DB...")
		if err := db.Reset(); err != nil {
			return xerrors.Errorf("error in refresh DB: %w", err)
		}
	}

	updateTargets := vulnsrc.UpdateList
	if onlyUpdate != "" {
		log.Logger.Warn("The --only-update option may cause the vulnerability details such as severity and title not to be displayed")
		updateTargets = strings.Split(onlyUpdate, ",")
	}

	if !skipUpdate {
		if err := vulnsrc.Update(updateTargets); err != nil {
			return xerrors.Errorf("error in vulnerability DB update: %w", err)
		}
	}

	if err := db.SetVersion(cliVersion); err != nil {
		return xerrors.Errorf("unexpected error: %w", err)
	}

	return nil
}
