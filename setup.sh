#!/usr/bin/env bash
#
# NimbusMart CTF — one-command setup.
# Spins up a local kind cluster, builds & loads the platform images, deploys the
# web app + in-browser terminal + checker into the cluster, waits until they're
# ready, and prints the URL.
#
#   ./setup.sh            # fresh cluster + full platform
#   ./setup.sh --keep     # reuse an existing 'owasp-labs' cluster if present
#
set -euo pipefail
cd "$(dirname "$0")"

CLUSTER="owasp-labs"
WEB_PORT=30090
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

c()  { printf "\033[35m%s\033[0m\n" "$*"; }   # violet
ok() { printf "\033[32m✔ %s\033[0m\n" "$*"; }
die(){ printf "\033[31m✗ %s\033[0m\n" "$*" >&2; exit 1; }

c "▶ Checking prerequisites…"
for bin in docker kind kubectl go; do
  command -v "$bin" >/dev/null 2>&1 || die "'$bin' is required but not installed."
done
docker info >/dev/null 2>&1 || die "Docker doesn't seem to be running. Start Docker and retry."
ok "docker, kind, kubectl, go present"

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  if [ "$KEEP" = "1" ]; then
    c "▶ Reusing existing kind cluster '$CLUSTER' (--keep)"
  else
    c "▶ Removing existing kind cluster '$CLUSTER' for a clean start…"
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
fi

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  c "▶ Creating kind cluster '$CLUSTER' (maps ports 30080/30090/30091)…"
  kind create cluster --config labs/kind-cluster.yaml
fi
kubectl config use-context "kind-$CLUSTER" >/dev/null
ok "cluster ready"

c "▶ Building images (web + terminal) and loading them into kind…"
bash deploy/build.sh

c "▶ Deploying the platform…"
kubectl apply -f deploy/ >/dev/null
ok "manifests applied"

c "▶ Waiting for pods to become ready (first run pulls images, ~1-2 min)…"
kubectl -n nimbusmart-ctf rollout status deploy/web --timeout=240s
kubectl -n nimbusmart-ctf rollout status deploy/terminal --timeout=240s

URL="http://localhost:${WEB_PORT}"
echo
c "╔════════════════════════════════════════════════════════════╗"
c "║  NimbusMart CTF is up                                       ║"
c "╠════════════════════════════════════════════════════════════╣"
printf "\033[35m║\033[0m  🌐  Web app:  \033[1;36m%-43s\033[0m\033[35m║\033[0m\n" "$URL"
c "║  ⌨   Terminal: click the ‘Terminal’ button in the web app   ║"
c "║      (runs kubectl against THIS cluster, as cluster-admin)  ║"
c "╚════════════════════════════════════════════════════════════╝"
echo
echo "  Tear down:   kind delete cluster --name $CLUSTER"
echo "  Pod status:  kubectl get pods -n nimbusmart-ctf -w"
echo
# Best-effort: open the browser on macOS.
command -v open >/dev/null 2>&1 && open "$URL" >/dev/null 2>&1 || true
