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

# Install Mac

```
$ brew tap masahiro331/kube-tirvy
$ brew install kube-trivy
$ kubetrivy -h
```

# Install

```
$ go get -u github.com/masahiro331/kube-trivy
$ kubetrivy -h
```

# Quick Start

## Install CRD

```
$ cat << EOS > crd.yaml
apiVersion: apiextensions.k8s.io/v1beta1
kind: CustomResourceDefinition
metadata:
  name: vulnerabilities.kubetrivy.io
spec:
  group: kubetrivy.io
  version: v1
  names:
    kind: Vulnerability
    plural: vulnerabilities
  scope: Namespaced
  additionalPrinterColumns:
  - name: UNKNOWN
    type: integer
    description: The total of vulnerabilities launched by the kubetrivy
    JSONPath: .spec.statistics.UNKNOWN
  - name: LOW
    type: integer
    description: The total of vulnerabilities launched by the kubetrivy
    JSONPath: .spec.statistics.LOW
  - name: MEDIUM
    type: integer
    description: The total of vulnerabilities launched by the kubetrivy
    JSONPath: .spec.statistics.MEDIUM
  - name: HIGH
    type: integer
    description: The total of vulnerabilities launched by the kubetrivy
    JSONPath: .spec.statistics.HIGH
  - name: CRITICAL
    type: integer
    description: The total of vulnerabilities launched by the kubetrivy
    JSONPath: .spec.statistics.CRITICAL
EOS

$ kubectl apply -f crd.yaml
$ kubectl get vulnerability
```

## Basic

```
$ kubetrivy -n default scan
$ kubetrivy -n default scan
$ kubectl get vulnerability -n default
$ kubetrivy -n default get ${resourceName}
```
