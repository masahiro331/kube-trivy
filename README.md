A Simple and Comprehensive Vulnerability Scanner for Kubernetes


# Abstract

`KubeTrivy` is a extends trivy for kubernetes.
`KubeTrivy` is a simple and comprehensive vulnerability scanner for Kubernetes.
`KubeTrivy` detects vulnerabilities of OS packages (Alpine, RHEL, CentOS, etc.) and application dependencies (Bundler, Composer, npm, yarn etc.).
`KubeTrivy` is easy to use. Just install the binary and you're ready to scan. All you need to do for scanning is to specify an image name of container on kubernetes.


Check the about [Trivy](https://github.com/knqyf263/trivy)

# Features

- Detect comprehensive vulnerabilities
  - OS packages (Alpine, **Red Hat Universal Base Image**, Red Hat Enterprise Linux, CentOS, Debian and Ubuntu)
  - **Application dependencies** (Bundler, Composer, Pipenv, Poetry, npm, yarn and Cargo)
- Managing vulnerabilities using kubectl command
  - Create a CRD on your Kubernetes
  - Get vulnerability info `kubectl get vulnerability` or `kubetrivy get ${resourceName}`
- Extend Trivy features
  - kubetrivy is compatible with trivy's local DB.
  - kubetrivy is compatible with trivy's command options.
<!--
- Simple
  - Specify only an image name
  - See [Quick Start](#quick-start) and [Examples](#examples)
- Easy installation
  - **No need for prerequirements** such as installation of DB, libraries, etc.
  - `apt-get install`, `yum install` and `brew install` is possible (See [Installation](#installation))
- High accuracy
  - **Especially Alpine Linux and RHEL/CentOS** (See [Comparison with other scanners](#comparison-with-other-scanners))
  - Other OSes are also high
- DevSecOps
  - **Suitable for CI** such as Travis CI, CircleCI, Jenkins, etc.
  - See [CI Example](#continuous-integration-ci)
 -->

# TODO:
- Add kubectl plugin

# Install

```
$ git clone https://github.com/masahiro331/kube-trivy
$ cd kube-trivy
$ go build -o kubetrivy cmd/kubetrivy/main.go
$ kubectl apply -f crd.yaml
```


# Quick Start

## Basic

```
$ kubetrivy -n default scan
$ kubetrivy -n default scan
$ kubectl get vulnerability -n default
$ kubetrivy -n default get ${resourceName}
```
