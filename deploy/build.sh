#!/usr/bin/env bash
# Build the platform images and load them into the kind cluster.
set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER="${KIND_CLUSTER:-owasp-labs}"
case "$(uname -m)" in
  arm64|aarch64) ARCH=arm64 ;;
  *)             ARCH=amd64 ;;
esac
echo "▶ target arch: ${ARCH}"

echo "▶ building the checker binary for linux/${ARCH}"
mkdir -p terminal-server/bin
( cd checker && GOOS=linux GOARCH="${ARCH}" CGO_ENABLED=0 go build -o ../terminal-server/bin/owasp-k8s-checker . )

KUBECTL_VERSION="${KUBECTL_VERSION:-v1.31.4}"
if [ ! -x "terminal-server/bin/kubectl" ]; then
  echo "▶ downloading kubectl ${KUBECTL_VERSION} (linux/${ARCH}) for the terminal image"
  curl -fsSL -o terminal-server/bin/kubectl \
    "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${ARCH}/kubectl"
  chmod +x terminal-server/bin/kubectl
fi

echo "▶ building web image (nimbusmart-ctf-web:latest)"
docker build -t nimbusmart-ctf-web:latest -f web/Dockerfile web

echo "▶ building terminal image (nimbusmart-ctf-terminal:latest)"
docker build -t nimbusmart-ctf-terminal:latest \
  --build-arg "TARGETARCH=${ARCH}" -f terminal-server/Dockerfile .

echo "▶ loading images into kind cluster '${CLUSTER}'"
kind load docker-image nimbusmart-ctf-web:latest --name "${CLUSTER}"
kind load docker-image nimbusmart-ctf-terminal:latest --name "${CLUSTER}"

# ── K08 "cloud" lab images ──────────────────────────────────────────────────
# The K08 challenge simulates AWS with LocalStack + an IMDS emulator + the aws
# CLI. kind can't reliably `kind load` multi-arch Docker Hub images (containerd
# "content digest not found"), so we wrap each upstream image in a trivial local
# build (flattens to a single-platform image kind accepts) and load that. The
# K08 manifests reference the ctf-* names with imagePullPolicy: IfNotPresent.
echo "▶ preparing K08 cloud-sim images (localstack, aws-cli, nginx)"
provision_lab_image() { # $1 = local tag, $2 = upstream image
  local local_tag="$1" upstream="$2"
  docker image inspect "$upstream" >/dev/null 2>&1 || docker pull "$upstream"
  echo "FROM ${upstream}" | docker build -t "${local_tag}" - >/dev/null
  kind load docker-image "${local_tag}" --name "${CLUSTER}"
}
provision_lab_image ctf-localstack:latest  localstack/localstack:3.8
provision_lab_image ctf-aws-cli:latest     amazon/aws-cli:2.17.20
provision_lab_image ctf-imds-nginx:latest  nginx:1.27-alpine

echo "✔ images built and loaded"
