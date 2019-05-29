package slack

import (
	"fmt"
	"strings"

	"github.com/knqyf263/kube-trivy/pkg/config"
	"github.com/knqyf263/trivy/pkg/report"
	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"
	"github.com/nlopes/slack"
	appsv1 "k8s.io/api/apps/v1"
)

const (
	colorCyan   = "#00a1e9f"
	colorYellow = "#e8e800"
	colorBlue   = "#2700e8"
	colorHiRed  = "#e80000"
	colorRed    = "#e84d00"
)

type field struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

type message struct {
	Text        string             `json:"text"`
	Username    string             `json:"username"`
	IconEmoji   string             `json:"icon_emoji"`
	Channel     string             `json:"channel"`
	Attachments []slack.Attachment `json:"attachments"`
}

type SlackWriter struct {
}

var Conf config.SlackConf

func Init(conf config.SlackConf) {
	Conf = conf
}

func (w SlackWriter) NotificationDeployment(deployment *appsv1.Deployment) (err error) {
	api := slack.New(Conf.Token)
	str := fmt.Sprintf(`*Deployment: %s (%s)*`, deployment.ObjectMeta.Name, deployment.ObjectMeta.Namespace)

	_, _, err = api.PostMessage(
		Conf.Channel,
		slack.MsgOptionText(str, true),
	)
	if err != nil {
		fmt.Printf("%s\n", err)
		return err
	}
	return nil
}

func (w SlackWriter) NotificationAddOrModifyContainer(rs report.Results) (err error) {
	api := slack.New(Conf.Token)

	for _, r := range rs {
		severityCount := map[string]int{}
		for _, v := range r.Vulnerabilities {
			severityCount[v.Severity]++
		}

		var results []string
		for _, severity := range vulnerability.SeverityNames {
			results = append(results, fmt.Sprintf("%s: %d", severity, severityCount[severity]))
		}
		str := fmt.Sprintf("> %s\n> Total: %d (%s)\n\n", r.FileName, len(r.Vulnerabilities), strings.Join(results, ", "))

		_, _, err := api.PostMessage(
			Conf.Channel,
			slack.MsgOptionText(str, true),
			slack.MsgOptionAttachments(toSlackAttachments(r.Vulnerabilities)...),
		)
		if err != nil {
			fmt.Printf("%s\n", err)
			return err
		}
	}
	return nil
}

func toSlackAttachments(vs []vulnerability.DetectedVulnerability) (attaches []slack.Attachment) {
	for _, v := range vs {
		a := slack.Attachment{
			Title:      v.PkgName,
			Text:       v.Title,
			MarkdownIn: []string{"text", "pretext"},
			Fields: []slack.AttachmentField{
				{
					Title: "Vulnerability ID",
					Value: v.VulnerabilityID,
					Short: true,
				},
				{
					Title: "Severity",
					Value: v.Severity,
					Short: true,
				},
				{
					Title: "Installed Version",
					Value: v.InstalledVersion,
					Short: true,
				},
				{
					Title: "Fixed Version",
					Value: v.FixedVersion,
					Short: true,
				},
				{
					Title: "Description",
					Value: "```" + v.Description + "```",
					Short: false,
				},
			},
			Color: severityToColor(v.Severity),
		}

		attaches = append(attaches, a)
	}
	return attaches
}

func severityToColor(severity string) string {
	switch severity {
	case "UNKNOWN":
		return colorCyan
	case "LOW":
		return colorBlue
	case "MEDIUM":
		return colorYellow
	case "HIGH":
		return colorHiRed
	case "CRITICAL":
		return colorRed
	default:
		return colorBlue
	}
	return colorBlue
}
