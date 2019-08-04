package pkg

import (
	"fmt"
	l "log"
	"os"
	"strings"

	"github.com/knqyf263/trivy/pkg/db"
	"github.com/knqyf263/trivy/pkg/log"
	"github.com/knqyf263/trivy/pkg/report"
	"github.com/knqyf263/trivy/pkg/scanner"
	"github.com/knqyf263/trivy/pkg/types"
	"github.com/knqyf263/trivy/pkg/utils"
	"github.com/knqyf263/trivy/pkg/vulnsrc"
	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"

	"github.com/genuinetools/reg/registry"
	"github.com/knqyf263/fanal/cache"
	"github.com/urfave/cli"
	"golang.org/x/xerrors"

	"github.com/knqyf263/kube-trivy/pkg/kubetrivy"
)

var severities []vulnerability.Severity
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

	ignoreUnfixed = c.Bool("ignore-unfixed")
	severityfilter = c.String("severity")
	for _, s := range strings.Split(severityfilter, ",") {
		severity, err := vulnerability.NewSeverity(s)
		if err != nil {
			return xerrors.Errorf("error in severity option: %w", err)
		}
		severities = append(severities, severity)
	}

	o = c.String("output")
	output := os.Stdout
	if o != "" {
		if output, err = os.Create(o); err != nil {
			return xerrors.Errorf("failed to create an output file: %w", err)
		}
	}
	args := c.Args()
	if len(args) == 0 {
		return xerrors.Errorf("need some arguments", err)
	}
	switch args[0] {
	case "scan":
		vulnType = c.String("vuln-type")
		var resultsMap map[string]report.Results = map[string]report.Results{}
		// resourcesName: e.g. deployment
		for resourcesName, resources := range imageMap {
			// name: metadata.name
			for name, resource := range resources {
				for _, imageName := range resource {
					results, err := Scan(imageName)
					if err != nil {
						log.Logger.Warn(err)
					}
					resultsMap[fmt.Sprintf("%s-%s-%s", resourcesName, name, imageName)] = results
				}
			}
		}
		if err := client.SyncVulnerability(resultsMap); err != nil {
			log.Logger.Warn(err)
		}

		return nil
	case "get":
		if len(args) < 2 {
			return xerrors.Errorf("failed to get commad need target", err)
		}
		res, err := client.GetVulnerability(args[1])
		if err != nil {
			return xerrors.Errorf("failed to get vulnerability", err)
		}

		var results report.Results
		for _, target := range res.Spec.Targets {
			vulns := make([]vulnerability.DetectedVulnerability, len(target.Vulnerabilities))
			for i, vuln := range target.Vulnerabilities {
				vulns[i] = vulnerability.DetectedVulnerability(vuln)
			}
			result := report.Result{
				FileName:        target.Name,
				Vulnerabilities: vulnerability.FillAndFilter(vulns, severities, ignoreUnfixed),
			}

			results = append(results, result)
		}

		var writer report.Writer
		switch format := c.String("format"); format {
		case "table":
			writer = &report.TableWriter{Output: output}
		case "json":
			writer = &report.JsonWriter{Output: output}
		default:
			return xerrors.Errorf("unknown format: %v", format)
		}

		if err = writer.Write(results); err != nil {
			return xerrors.Errorf("failed to write results: %w", err)
		}

	}

	return nil
}

func Scan(imageName string) (results report.Results, err error) {
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
		results = append(results, report.Result{
			FileName:        path,
			Vulnerabilities: vulnerability.FillAndFilter(vuln, severities, ignoreUnfixed),
		})
	}

	return results, nil

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
