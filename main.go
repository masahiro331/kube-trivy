package main

import (
	"flag"
	l "log"
	"os"
	"path/filepath"
	"time"

	"github.com/knqyf263/kube-trivy/pkg/signals"
	"github.com/knqyf263/kube-trivy/pkg/trivy"
	"github.com/knqyf263/trivy/pkg/log"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	var kubeconfig *string
	if home := homeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}

	flag.Parse()
	debug := true
	if err := log.InitLogger(debug); err != nil {
		l.Fatal(err)
	}

	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		l.Fatal(err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		l.Fatal(err.Error())
	}

	stopCh := signals.SetupSignalHandler()
	informerFactory := informers.NewSharedInformerFactory(clientset, time.Second*5)

	controller := NewController(clientset, informerFactory.Apps().V1().Deployments())
	informerFactory.Start(stopCh)

	if err = trivy.Init(); err != nil {
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

func GetConfig(context string, kubeconfig string) clientcmd.ClientConfig {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.DefaultClientConfig = &clientcmd.DefaultClientConfig

	overrides := &clientcmd.ConfigOverrides{ClusterDefaults: clientcmd.ClusterDefaults}

	if context != "" {
		overrides.CurrentContext = context
	}

	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}

	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
}
