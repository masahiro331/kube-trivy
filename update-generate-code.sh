# git clone https://kubernetes/code-generator

ROOT_PACKAGE="github.com/knqyf263/kube-trivy"
CUSTOM_RESOURCE_NAME="kubetrivy"
CUSTOM_RESOURCE_VERSION="v1"
./code-generator/generate-groups.sh all "$ROOT_PACKAGE/pkg/client" "$ROOT_PACKAGE/pkg/apis" "$CUSTOM_RESOURCE_NAME:$CUSTOM_RESOURCE_VERSION"
