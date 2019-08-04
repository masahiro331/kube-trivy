package kubetrivy

import (
	"log"
	"strings"

	"github.com/knqyf263/kube-trivy/pkg/config"
	"github.com/knqyf263/trivy/pkg/report"
	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	kubetrivyv1 "github.com/knqyf263/kube-trivy/pkg/apis/kubetrivy/v1"
	v1 "github.com/knqyf263/kube-trivy/pkg/apis/kubetrivy/v1"
	kubetrivy "github.com/knqyf263/kube-trivy/pkg/client/clientset/versioned"
)

// K8s resources
const (
	Deployment  = "deployment"
	DaemonSet   = "daemonset"
	StatefulSet = "statefulset"
)

var (
	namespace = "default"
)

type KubeTrivy struct {
	*kubernetes.Clientset
	KubeTrivy *kubetrivy.Clientset
	Namespace string
}

func NewKubeTrivy(namespace string) *KubeTrivy {
	const CONFIGPATH = ""
	config, err := config.GetConfig(CONFIGPATH)
	if err != nil {
		log.Fatal(err.Error())
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(err.Error())
	}

	kubetrivyClientset, err := kubetrivy.NewForConfig(config)
	if err != nil {
		log.Fatal(err.Error())
	}

	// metav1.NamespaceAll

	return &KubeTrivy{
		Clientset: clientset,
		Namespace: namespace,
		KubeTrivy: kubetrivyClientset,
	}
}

func (kt KubeTrivy) GetVulnerability(target string) (*v1.Vulnerability, error) {
	vulnerabilities, err := kt.KubeTrivy.KubetrivyV1().Vulnerabilities(kt.Namespace).Get(
		target,
		metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to get  vulnerability")
	}

	return vulnerabilities, nil

}

func (kt KubeTrivy) CreateVulnerability(name string, results report.Results) error {
	var targets []kubetrivyv1.Target
	severityCount := map[string]int{
		"UNKNOWN":  0,
		"LOW":      0,
		"MEDIUM":   0,
		"HIGH":     0,
		"CRITICAL": 0,
	}

	for _, result := range results {
		target := kubetrivyv1.Target{
			Name:            result.FileName,
			Vulnerabilities: make([]kubetrivyv1.DetectedVulnerability, len(result.Vulnerabilities)),
		}
		for _, v := range result.Vulnerabilities {
			severityCount[v.Severity]++
		}
		for i, vuln := range result.Vulnerabilities {
			target.Vulnerabilities[i] = kubetrivyv1.DetectedVulnerability(vuln)
		}
		targets = append(targets, target)
	}

	var total int
	for _, c := range severityCount {
		total += c
	}
	severityCount["TOTAL"] = total
	if total == 0 {
		return nil
	}

	rep := strings.NewReplacer(":", "-", "/", "-")
	Vulnerability := kubetrivyv1.Vulnerability{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rep.Replace(name),
			Namespace: kt.Namespace,
		},
		Spec: kubetrivyv1.VulnerabilitySpec{
			Targets:    targets,
			Statistics: severityCount,
		},
	}

	_, err := kt.KubeTrivy.KubetrivyV1().Vulnerabilities(kt.Namespace).Create(&Vulnerability)
	if err != nil {
		return err
	}
	return nil
}

func (kt KubeTrivy) GetImages() (imageMap map[string]map[string][]string, err error) {
	imageMap = make(map[string]map[string][]string)

	imageMap[Deployment], err = kt.getDeploymentImage()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get images")
	}

	imageMap[DaemonSet], err = kt.getDaemonSetImage()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get images")
	}

	imageMap[StatefulSet], err = kt.getStatefulSetImage()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get images")
	}

	return imageMap, nil
}

func (kt KubeTrivy) getDeploymentImage() (map[string][]string, error) {
	deployMap := make(map[string][]string)
	deployments, err := kt.AppsV1().Deployments(kt.Namespace).List(
		metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to list deployments")
	}
	for _, deployment := range deployments.Items {
		var images []string
		for _, container := range deployment.Spec.Template.Spec.Containers {
			images = append(images, container.Image)
		}
		deployMap[deployment.ObjectMeta.Name] = images
	}

	return deployMap, nil
}

func (kt KubeTrivy) getDaemonSetImage() (map[string][]string, error) {
	dsMap := make(map[string][]string)
	daemonsets, err := kt.AppsV1().DaemonSets(kt.Namespace).List(
		metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to list deployments")
	}
	for _, daemonset := range daemonsets.Items {
		var images []string
		for _, container := range daemonset.Spec.Template.Spec.Containers {
			images = append(images, container.Image)
		}
		dsMap[daemonset.ObjectMeta.Name] = images
	}

	return dsMap, nil
}

func (kt KubeTrivy) getStatefulSetImage() (map[string][]string, error) {
	sfMap := make(map[string][]string)
	statefulsets, err := kt.AppsV1().StatefulSets(kt.Namespace).List(
		metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to list deployments")
	}
	for _, statefulset := range statefulsets.Items {
		var images []string
		for _, container := range statefulset.Spec.Template.Spec.Containers {
			images = append(images, container.Image)
		}
		sfMap[statefulset.ObjectMeta.Name] = images
	}

	return sfMap, nil
}
