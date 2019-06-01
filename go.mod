module github.com/knqyf263/kube-trivy

go 1.12

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/etcd-io/bbolt v1.3.2
	github.com/golang/groupcache v0.0.0-20160516000752-02826c3e7903 // indirect
	github.com/google/go-cmp v0.3.0 // indirect
	github.com/google/gofuzz v0.0.0-20170612174753-24818f796faf // indirect
	github.com/googleapis/gnostic v0.0.0-20170729233727-0c5108395e2d // indirect
	github.com/gorilla/websocket v1.4.0 // indirect
	github.com/imdario/mergo v0.3.7 // indirect
	github.com/json-iterator/go v0.0.0-20180701071628-ab8a2e0c74be // indirect
	github.com/knqyf263/fanal v0.0.0-20190521154631-a2dde7e171c6
	github.com/knqyf263/trivy v0.1.1
	github.com/lusis/go-slackbot v0.0.0-20180109053408-401027ccfef5 // indirect
	github.com/lusis/slack-test v0.0.0-20190426140909-c40012f20018 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.1 // indirect
	github.com/nlopes/slack v0.5.0
	github.com/spf13/pflag v1.0.1 // indirect
	golang.org/x/text v0.3.1-0.20181227161524-e6919f6577db // indirect
	golang.org/x/xerrors v0.0.0-20190513163551-3ee3066db522
	gopkg.in/inf.v0 v0.9.0 // indirect
	k8s.io/api v0.0.0-20190313235455-40a48860b5ab
	k8s.io/apimachinery v0.0.0-20190313205120-d7deff9243b1
	k8s.io/client-go v11.0.0+incompatible
	k8s.io/klog v0.3.1 // indirect
	k8s.io/utils v0.0.0-20190520173318-324c5df7d3f0 // indirect
	sigs.k8s.io/yaml v1.1.0 // indirect
)

replace github.com/genuinetools/reg => github.com/tomoyamachi/reg v0.16.2-0.20190418055600-c6010b917a55

replace github.com/olekukonko/tablewriter => github.com/knqyf263/tablewriter v0.0.2
