# NimbusMart CTF — the OWASP Kubernetes Top 10, hands-on

A **capture-the-flag** built on the [OWASP Kubernetes Top 10 (2022)](https://owasp.org/www-project-kubernetes-top-ten/).
You've been hired to red-team **NimbusMart**, a fictional e-commerce company whose
cluster grew faster than its security. Ten challenges, one per OWASP risk — exploit
each weakness, **capture the flag**, then apply the fix and prove it with the checker.

For every challenge you get:

- 🎯 **A mission briefing** — the NimbusMart scenario, your foothold, and the objective.
- 🚩 **A flag to capture** — reachable only by performing the exploit (on the node, in another namespace, over the network…). Submit it in the web app; the scoreboard tracks your progress and points (browser localStorage).
- 💡 **Progressive hints + a spoiler walkthrough** — nudges first, full solution when you want it.
- 📖 **A deep-dive overview** — what the weakness is, how attackers abuse it, impact, root causes.
- 🛡️ **A defense guide** — concrete patches and a best-practices checklist.
- 🤖 **An automated checker** — a Go binary that scans your cluster and confirms, per risk, whether the fix holds.

The world bible (company, services, namespaces, flag scheme) lives in [`labs/NIMBUSMART.md`](labs/NIMBUSMART.md).

Everything runs locally on `kind`. **Never run the vulnerable manifests against a real cluster.**

Built by [**@hac01**](https://github.com/hac01).

---

## Run the whole platform inside one cluster

The web app, an in-browser terminal, and the checker can all run **inside the kind
cluster** — one command spins up everything and prints the URL:

```bash
./setup.sh          # or: make up
#   ▶ creates the kind cluster, builds+loads images, deploys, waits for ready
#   🌐 Web app: http://localhost:30090
#   ⌨  Terminal: the ‘Terminal’ button in the web app
```

`./setup.sh` (re)creates the cluster with the right port mappings, builds the two
images (`nimbusmart-ctf-web`, `nimbusmart-ctf-terminal`), loads them into kind, and
applies [`deploy/`](deploy). The terminal pod runs as a `cluster-admin`
ServiceAccount, so the **terminal in the browser drives this very cluster** — run
`kubectl apply -f labs/...` and `owasp-k8s-checker --check kNN` right there.

> ⚠️ The in-browser terminal is effectively cluster-admin over a WebSocket. It is
> safe only because it is bound to your local, disposable kind cluster on
> `localhost`. Never expose ports `30090`/`30091` to an untrusted network.

Prefer to develop the UI locally instead? `make web` (Next dev server on :3000) and
`make terminal-local` (terminal backend on :30091 using your `~/.kube/config`).

---

## Repository layout

```
.
├── web/         Next.js + React app (white/purple theme) — the UI
├── labs/        Real K8s manifests per risk (vulnerable.yaml + fixed.yaml + README)
│   └── kind-cluster.yaml   Shared local cluster config
└── checker/     Go binary that validates a cluster against the Top 10
```

## The Top 10 (2025)

| ID  | Risk | Lab folder |
|-----|------|-----------|
| K01 | Insecure Workload Configurations              | `labs/k01-insecure-workload` |
| K02 | Overly Permissive Authorization Configurations| `labs/k02-authorization` |
| K03 | Secrets Management Failures                   | `labs/k03-secrets` |
| K04 | Lack of Cluster-Level Policy Enforcement      | `labs/k04-policy-enforcement` |
| K05 | Missing Network Segmentation Controls         | `labs/k05-network-segmentation` |
| K06 | Overly Exposed Kubernetes Components          | `labs/k06-exposed-components` |
| K07 | Misconfigured and Vulnerable Cluster Components| `labs/k07-cluster-components` |
| K08 | Cluster-to-Cloud Lateral Movement             | `labs/k08-cluster-to-cloud` |
| K09 | Broken Authentication Mechanisms              | `labs/k09-authentication` |
| K10 | Inadequate Logging and Monitoring             | `labs/k10-logging-monitoring` |
| ★   | Supply Chain Vulnerabilities *(bonus)*        | `labs/kbonus-supply-chain` |

---

## Quick start

### 1. Run the web app

```bash
cd web
npm install
npm run dev
# open http://localhost:3000
```

### 2. Create a lab cluster

```bash
kind create cluster --config labs/kind-cluster.yaml
kubectl config use-context kind-owasp-labs
```

### 3. Play a challenge

Each challenge has its own README, but the pattern is the same:

```bash
# some challenges seed a target first (a node file, an ops secret, ...)
kubectl apply -f labs/k01-insecure-workload/setup.yaml       # only if present

# deploy the vulnerable resource and exploit it to capture the flag
kubectl apply -f labs/k01-insecure-workload/vulnerable.yaml
# ...follow the mission briefing / hints in the web app, grab FLAG{...}, submit it...

# apply the hardened version and confirm the flag path is closed
kubectl delete -f labs/k01-insecure-workload/vulnerable.yaml
kubectl apply  -f labs/k01-insecure-workload/fixed.yaml
```

### 4. Verify with the checker

```bash
cd checker
go run . --list            # show all checks
go run . --check k01       # run a single check
go run . --all             # scan the whole cluster
go run . --all --json      # machine-readable (for CI)
go run . --all -n apps     # scope to a namespace
```

The checker exits non-zero if any check fails, so it can gate CI.

Build a standalone binary:

```bash
cd checker
go build -o owasp-k8s-checker .
./owasp-k8s-checker --all
```

---

## How the checker maps to the labs

Each `checker/checks/kNN.go` validates the same control the matching lab teaches.
Deploy the `fixed.yaml`, run `go run . --check kNN`, and you should see **PASS**.
Deploy the `vulnerable.yaml` and the same check reports the specific findings.

> ⚠️ **Safety:** the vulnerable manifests are deliberately exploitable. Only use a
> local, disposable `kind`/`minikube` cluster. Delete it when you're done:
> `kind delete cluster --name owasp-labs`.
