package pkg

import (
	"fmt"

	"github.com/knqyf263/trivy/pkg/log"

	"github.com/urfave/cli"
	"golang.org/x/xerrors"

	"github.com/masahiro331/kube-trivy/pkg/kubetrivy"
	"github.com/masahiro331/kube-trivy/pkg/trivy"
)

var (
	clearCache     = false
	o              = ""
	severityfilter = ""
	vulnType       = ""
	format         = "table"
	exitCode       = 0
	noTarget       = false
)

func Run(c *cli.Context) error {
	args := c.Args()
	if len(args) == 0 {
		noTarget = true
	}

	trivyConf := &trivy.TrivyConf{
		ClearCache:     c.Bool("clear-cache"),
		SeverityFilter: c.String("severity"),
		Debug:          c.Bool("debug"),
		Quiet:          c.Bool("quiet"),
		CacheDir:       c.String("cache-dir"),
		Reset:          c.Bool("reset"),
		NoTarget:       noTarget,
		IgnoreUnfixed:  c.Bool("ignore-unfixed"),
		VulnType:       c.String("vuln-type"),
		Format:         c.String("format"),
		Refresh:        c.Bool("refresh"),
		AutoRefresh:    c.Bool("auto-refresh"),
		SkipUpdate:     c.Bool("skip-update"),
		OnlyUpdate:     c.String("only-update"),
	}

	if err := trivy.Init(trivyConf); err != nil {
		return xerrors.Errorf("error in Init Trivy: %v", err)
	}
	if err := trivy.InitDB(); err != nil {
		return xerrors.Errorf("error in Init Trivy: %v", err)
	}

	client := kubetrivy.NewKubeTrivy(c.String("namespace"))

	var isInstalledCrd = true
	if err := CheckCrd(client); err != nil {
		log.Logger.Warn(err)
		isInstalledCrd = false
		if !c.Bool("no-crd") {
			log.Logger.Info(isInstalledCrd)
			return xerrors.New("kubetrivy requires CustomResourceDefinition or --no-crd option.")
		}
	}

	switch args[0] {
	case "scan":
		imageMap, err := client.GetImages()
		if err != nil {
			return xerrors.Errorf("error in get images in kubernetes: %v", err)
		}
		if err := trivy.UpdateDB(c.App.Version); err != nil {
			return xerrors.Errorf("error in dbUpdate: %w", err)
		}
		resultsMap := trivy.Scan(imageMap)

		if err := client.SyncVulnerability(resultsMap); err != nil {
			log.Logger.Warn(err)
		}

		return nil

	case "list":
		res, err := client.ListVulnerability()
		if err != nil {
			return xerrors.Errorf("failed to get vulnerability: %v", err)
		}
		body := ""
		for _, vuln := range res.Items {
			body += fmt.Sprintf("%-64s %-7d %-7d %-7d %-7d %-7d\n", vuln.Name,
				vuln.Spec.Statistics["CRITICAL"],
				vuln.Spec.Statistics["HIGH"],
				vuln.Spec.Statistics["MIDIUM"],
				vuln.Spec.Statistics["LOW"],
				vuln.Spec.Statistics["UNKNOWN"],
			)
		}
		header := fmt.Sprintf("%-64.64s %-7.7s %-7.7s %-7.7s %-7.7s %-7.7s\n", "NAME", "CRITICAL", "HIGH", "MIDIUM", "LOW", "UNKNOWN")
		if len(body) == 0 {
			header = "No vulnerability found.\n"
		}
		fmt.Print(header + body)
		return nil

	case "get":
		if len(args) < 2 {
			return xerrors.New("failed to get commad need target")
		}
		res, err := client.GetVulnerability(args[1])
		if err != nil {
			return xerrors.Errorf("failed to get vulnerability: %v", err)
		}

		if err = trivy.Write(res); err != nil {
			return xerrors.Errorf("failed to write results: %v", err)
		}
	}

	return nil
}

func CheckCrd(client *kubetrivy.KubeTrivy) error {
	_, err := client.ListVulnerability()
	if err != nil {
		return err
	}
	return nil
}
