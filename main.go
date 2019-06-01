package main

import (
	l "log"
	"os"
	"path/filepath"
	"time"

	"github.com/knqyf263/kube-trivy/pkg/config"
	c "github.com/knqyf263/kube-trivy/pkg/config"
	"github.com/knqyf263/kube-trivy/pkg/integration/slack"
	"github.com/knqyf263/kube-trivy/pkg/signals"
	"github.com/knqyf263/kube-trivy/pkg/trivy"
	"golang.org/x/xerrors"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {

	conf, err := c.Load("./config.toml")
	if err != nil {
		l.Fatal(err)
	}
	slack.Init(conf.Slack)

	config, err := getConfig(conf.KubeTrivy)
	if err != nil {
		l.Fatal(err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		l.Fatal(err.Error())
	}

	stopCh := signals.SetupSignalHandler()
	informerFactory := informers.NewSharedInformerFactory(clientset, time.Second*5)

	controller := NewController(clientset, informerFactory.Apps().V1().Deployments(), informerFactory.Apps().V1().DaemonSets())
	informerFactory.Start(stopCh)

	if err = trivy.Init(conf.Trivy); err != nil {
		l.Fatalf("Error init trivy: %s", err.Error())
	}
	if err = controller.Run(1, stopCh); err != nil {
		l.Fatalf("Error running controller: %s", err.Error())
	}
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE")
}

func getConfig(conf config.KubeTrivyConf) (*rest.Config, error) {
	if conf.LocalMode {
		config, err := getOutClusterConfig(conf.ConfigPath)
		return config, err
	}
	config, err := getInClusterConfig()
	return config, err
}

func getInClusterConfig() (*rest.Config, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, xerrors.Wrap(err, "")
	}
	return config, nil
}

func getOutClusterConfig(configPath string) (*rest.Config, error) {
	if configPath == "" {
		if home := homeDir(); home != "" {
			configPath = filepath.Join(home, ".kube", "config")
		}
	}

	config, err := clientcmd.BuildConfigFromFlags("", configPath)
	if err != nil {
		return nil, err
	}

	return config, nil
}
