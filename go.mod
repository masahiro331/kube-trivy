module github.com/masahiro331/kube-trivy

go 1.12

require (
	github.com/google/gofuzz v0.0.0-20170612174753-24818f796faf // indirect
	github.com/googleapis/gnostic v0.0.0-20170729233727-0c5108395e2d // indirect
	github.com/imdario/mergo v0.3.7 // indirect
	github.com/json-iterator/go v0.0.0-20180701071628-ab8a2e0c74be // indirect
	github.com/knqyf263/fanal v0.0.0-20190523002721-87ef54b8b37b // indirect
	github.com/knqyf263/trivy v0.1.1
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.1 // indirect
	github.com/spf13/pflag v1.0.1 // indirect
	github.com/urfave/cli v1.20.0
	golang.org/x/crypto v0.0.0-20190513172903-22d7a77e9e5f // indirect
	golang.org/x/oauth2 v0.0.0-20190523182746-aaccbc9213b0 // indirect
	golang.org/x/text v0.3.1-0.20181227161524-e6919f6577db // indirect
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4 // indirect
	golang.org/x/xerrors v0.0.0-20190513163551-3ee3066db522
	google.golang.org/appengine v1.5.0 // indirect
	gopkg.in/inf.v0 v0.9.0 // indirect
	k8s.io/api v0.0.0-20190313235455-40a48860b5ab
	k8s.io/apimachinery v0.0.0-20190313205120-d7deff9243b1
	k8s.io/client-go v11.0.0+incompatible
	k8s.io/klog v0.3.0
	k8s.io/utils v0.0.0-20190520173318-324c5df7d3f0 // indirect
	sigs.k8s.io/yaml v1.1.0 // indirect
)

replace github.com/genuinetools/reg => github.com/tomoyamachi/reg v0.16.2-0.20190418055600-c6010b917a55
