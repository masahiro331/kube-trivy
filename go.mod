module github.com/masahiro331/kube-trivy

go 1.12

require (
	github.com/genuinetools/reg v0.16.0
	github.com/knqyf263/fanal v0.0.0-20190706175150-0e953d070757
	github.com/knqyf263/kube-trivy v0.0.0-20190806021943-39c919419b57 // indirect
	github.com/knqyf263/trivy v0.1.4
	github.com/urfave/cli v1.20.0
	golang.org/x/xerrors v0.0.0-20190410155217-1f06c39b4373
	k8s.io/apimachinery v0.0.0-20190313205120-d7deff9243b1
	k8s.io/client-go v11.0.0+incompatible
)

replace github.com/genuinetools/reg => github.com/tomoyamachi/reg v0.16.1-0.20190706172545-2a2250fd7c00
