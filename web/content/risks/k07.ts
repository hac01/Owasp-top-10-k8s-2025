import type { Risk } from "../types";

export const k07: Risk = {
  id: "K07",
  slug: "misconfigured-vulnerable-components",
  title: "Misconfigured and Vulnerable Cluster Components",
  severity: "High",
  tagline:
    "Insecure kubelet/API-server/etcd flags, token-mounting default ServiceAccounts and missing quotas, plus end-of-life versions and stale vulnerable images, all hand attackers the control plane.",
  icon: "🛠️",

  overview: [
    "Kubernetes is a distributed system stitched together from several core components: the API server, etcd, the scheduler, the controller manager, and a kubelet on every node - plus a long tail of add-ons like ingress-nginx, CoreDNS, CNI plugins, and CSI drivers. Each ships with dozens of flags whose defaults favour convenience over safety, and each has its own release stream and steady drip of security fixes. K07 covers both halves of that story: components that are *misconfigured* and components that are *outdated and vulnerable*.",
    "The classic misconfiguration offenders are anonymous kubelet authentication (`--anonymous-auth=true`), a kubelet authorization mode of `AlwaysAllow` instead of `Webhook`, an API server that permits anonymous requests, exposed insecure/read-only ports, and an etcd datastore reachable without client-certificate authentication. Any one of these lets an unauthenticated attacker read secrets, exec into pods, or rewrite cluster state.",
    "Misconfiguration also shows up at the namespace level. The `default` ServiceAccount in every namespace auto-mounts an API token into every pod that does not opt out, so a single compromised container gets a cluster credential for free. Namespaces without a ResourceQuota or LimitRange let one workload starve the node of CPU and memory - a trivial denial-of-service.",
    "The vulnerable half is quieter. Kubernetes maintains only the three most recent minor releases; once a version ages out it is end-of-life (EOL) and receives no more patches, so any CVE disclosed after that date is permanent. The same is true for third-party images pinned to an old tag - an nginx or ingress controller from a few years ago carries dozens of documented, exploitable vulnerabilities. Nothing looks misconfigured; the cluster simply drifts out of support because no one owns a patch cadence. Benchmarks like the CIS Kubernetes Benchmark (kube-bench) and image scanners like Trivy exist precisely because these defaults and stale versions are so easy to miss.",
  ],
  impact: [
    "Unauthenticated cluster access: anonymous kubelet or API-server auth lets anyone on the network exec into pods and read secrets.",
    "Full data exfiltration: an unauthenticated etcd endpoint exposes every Secret, ConfigMap, and object in plaintext.",
    "Free credentials: the auto-mounted default ServiceAccount token turns any container RCE into an authenticated API client.",
    "Denial of service: a namespace with no ResourceQuota/LimitRange lets a single pod consume all node CPU/memory and evict its neighbours.",
    "Remote code execution via a published CVE that was never patched (e.g. an EOL kubelet/API server, or the ingress-nginx CVE-2021-25742 / CVE-2023-5044 annotation-injection bugs).",
    "No remediation path: an EOL version gets no security fix, so the only option under fire is an emergency upgrade - and running unsupported software fails most audits (CIS, PCI, SOC 2).",
  ],
  rootCauses: [
    "Kubelet started with `--anonymous-auth=true` and `--authorization-mode=AlwaysAllow` (the permissive path).",
    "API server exposing anonymous access or a legacy insecure port instead of TLS-only, authenticated access; etcd reachable without `--client-cert-auth`.",
    "The namespace `default` ServiceAccount left with `automountServiceAccountToken` unset (defaults to mounting).",
    "Namespaces created without a ResourceQuota or LimitRange, so nothing caps resource consumption.",
    "No upgrade cadence - clusters and add-ons are stood up once and left until something breaks, so the control plane and node kubelets drift past EOL.",
    "Third-party images pinned to an old tag and never rebuilt, with no image or benchmark scan (Trivy, kube-bench) in CI to surface known CVEs or drifted flags.",
  ],

  attackScenario: {
    summary:
      "An attacker on the pod network abuses a mounted default token and an unbounded namespace to move from a single container to cluster-wide impact, then fingerprints a stale component and matches it to a public CVE for code execution.",
    steps: [
      "The attacker gets code execution in a pod running under the namespace's `default` ServiceAccount.",
      "The projected token at /var/run/secrets/kubernetes.io/serviceaccount/token was auto-mounted, so they immediately have an authenticated API identity - and they enumerate pods, secrets, and endpoints they were never meant to see.",
      "Finding the namespace has no ResourceQuota or LimitRange, they schedule a fork-bomb of memory-hungry pods to evict neighbours and degrade the node.",
      "They fingerprint the cluster's component versions (kubelet, API server) and third-party images and match them to a published CVE with a ready-made exploit - because the component is EOL / never patched, the exploit works.",
      "If the kubelet also allows anonymous auth, they hit the kubelet API directly on port 10250 to exec into other pods - no token required. A single stale, misconfigured component becomes a node and cluster compromise.",
    ],
  },

  challenge: {
    scenario:
      "You've landed a shell in NimbusMart's `platform/debug-shell` pod. The platform team never applied basic cluster hygiene to this namespace: the `default` ServiceAccount still auto-mounts an API token into every pod, and someone bound that `default` SA a Role that can read Secrets \"so the debug tooling can read its config\". There are no ResourceQuota or LimitRange guardrails either, and the tool has never been on a patch cadence. Your pod is silently holding a live cluster credential it never asked for.",
    objective:
      "Use the auto-mounted `default` ServiceAccount token to read the `platform-config` Secret in the `platform` namespace and capture the flag it holds.",
    difficulty: "Medium",
    points: 200,
    flagFormat: "FLAG{...}",
    flagHash:
      "e9145dbd9550d18c0daf714e539a0d9ab4e7392588920f8c9a43c36c7fd95544",
    hints: [
      "You didn't ask for credentials, but check `/var/run/secrets/kubernetes.io/serviceaccount/` - the namespace's `default` SA auto-mounts its token into every pod.",
      "That token is a real API identity. From the pod, `kubectl` uses it automatically in-cluster - try listing and reading Secrets in the `platform` namespace.",
      "The flag lives in the `platform-config` Secret, not in your pod's spec: `kubectl get secret platform-config -n platform -o jsonpath='{.data.flag}' | base64 -d`.",
    ],
  },

  lab: {
    objective:
      "Use the auto-mounted default ServiceAccount token in the guardrail-free `platform` namespace to read a secret, then harden the namespace (disable default-SA token auto-mount, add a ResourceQuota and LimitRange, and pin a current image) - and learn to check the cluster's control plane, kubelets, and images for EOL/vulnerable components.",
    prerequisites: [
      "A local cluster: `kind create cluster --config labs/kind-cluster.yaml`",
      "kubectl configured to talk to that cluster",
      "Trivy installed for image scanning (`brew install trivy` or see aquasecurity/trivy)",
    ],
    setupManifest: "labs/k07-cluster-components/setup.yaml",
    vulnerableManifest: "labs/k07-cluster-components/vulnerable.yaml",
    fixedManifest: "labs/k07-cluster-components/fixed.yaml",
    steps: [
      {
        title: "Seed the target and deploy the vulnerable debug-shell",
        description:
          "The setup manifest creates the `platform` namespace, the `platform-config` Secret holding the flag, and a RoleBinding that lets the namespace `default` ServiceAccount read Secrets. The vulnerable manifest deploys `debug-shell`, which uses that default SA with no ResourceQuota or LimitRange in the namespace.",
        command:
          "kubectl apply -f labs/k07-cluster-components/setup.yaml && kubectl apply -f labs/k07-cluster-components/vulnerable.yaml",
        expected:
          "namespace/platform created ... secret/platform-config created ... pod/debug-shell created",
        kind: "setup",
      },
      {
        title: "Prove the default-SA token was auto-mounted",
        description:
          "Because the `platform` default ServiceAccount does not set automountServiceAccountToken: false, Kubernetes projects a real API token into debug-shell.",
        command:
          "kubectl exec -n platform debug-shell -- cat /var/run/secrets/kubernetes.io/serviceaccount/token | head -c 40; echo",
        expected:
          "A JWT prefix (eyJ...) - the pod holds a live API credential it never asked for.",
        kind: "attack",
      },
      {
        title: "Confirm there are no resource guardrails",
        description:
          "List quotas and limit ranges in the namespace. Both come back empty, so nothing caps CPU/memory - a DoS primitive that sits alongside the free credential.",
        command: "kubectl get resourcequota,limitrange -n platform",
        expected: "No resources found in platform namespace.",
        kind: "attack",
      },
      {
        title: "Use the token to read the secret and capture the flag",
        description:
          "In-cluster, kubectl automatically authenticates with the mounted default token. The RoleBinding grants it Secret read, so it can pull platform-config - a secret debug-shell was never meant to see.",
        command:
          "kubectl exec -n platform debug-shell -- kubectl get secret platform-config -n platform -o jsonpath='{.data.flag}' | base64 -d; echo",
        expected:
          "FLAG{misconfigured_stale_cluster_component} - submit this on the Challenge tab.",
        kind: "attack",
      },
      {
        title: "Triage the outdated / vulnerable components",
        description:
          "The other half of K07: fingerprint versions the way an attacker matches a CVE. Scan the stale image the debug tool is annotated with and check the cluster's own support window (the aspect the k07 checker validates).",
        command:
          "trivy image nginx:1.14.0; kubectl version; kubectl get nodes -o wide",
        expected:
          "A long list of CRITICAL/HIGH CVEs for the EOL image; the Server (control-plane) minor and each node's kubelet VERSION - anything below v1.28 is EOL.",
        kind: "attack",
      },
      {
        title: "Harden the namespace and pin a current image",
        description:
          "Applies the fixed manifest: patches the default SA with automountServiceAccountToken: false, adds a ResourceQuota and a LimitRange, and redeploys debug-shell with automountServiceAccountToken: false, explicit resources, and a current image. If the first apply races the control plane's default-SA creation ('already exists'), just re-run apply.",
        command:
          "kubectl delete -f labs/k07-cluster-components/vulnerable.yaml && kubectl apply -f labs/k07-cluster-components/fixed.yaml",
        expected:
          "pod deleted / serviceaccount + resourcequota + limitrange + pod configured/created",
        kind: "fix",
      },
      {
        title: "Verify the token is gone and the flag path is blocked",
        description:
          "The hardened debug-shell has no service-account token mounted, so kubectl can no longer authenticate to read the secret, and the namespace now enforces a ResourceQuota and LimitRange.",
        command:
          "kubectl exec -n platform debug-shell -- ls /var/run/secrets/kubernetes.io/serviceaccount 2>&1 || echo NO_TOKEN; kubectl get resourcequota,limitrange -n platform",
        expected:
          "NO_TOKEN, plus a resourcequota and limitrange listed - the credential and DoS surfaces are closed and the secret is unreachable.",
        kind: "verify",
      },
    ],
  },

  defense: {
    summary:
      "Lock down control-plane component flags against the CIS Benchmark, stop namespaces from auto-mounting the default ServiceAccount token, bound every namespace with a ResourceQuota and LimitRange, and stay inside the support window for every component with scanning plus a regular patch cadence.",
    patches: [
      {
        title: "Disable token auto-mount on the default ServiceAccount",
        description:
          "Stops every pod in the namespace from silently receiving an API token. Pods that genuinely need one use a dedicated ServiceAccount and opt in explicitly.",
        lang: "yaml",
        code: `apiVersion: v1
kind: ServiceAccount
metadata:
  name: default
  namespace: platform
automountServiceAccountToken: false`,
      },
      {
        title: "Bound the namespace with a ResourceQuota and LimitRange",
        description:
          "Caps total CPU/memory the namespace can request and gives every container a sane default, preventing a single workload from exhausting the node.",
        lang: "yaml",
        code: `apiVersion: v1
kind: ResourceQuota
metadata:
  name: platform-quota
  namespace: platform
spec:
  hard:
    requests.cpu: "2"
    requests.memory: 2Gi
    limits.cpu: "4"
    limits.memory: 4Gi
---
apiVersion: v1
kind: LimitRange
metadata:
  name: platform-limits
  namespace: platform
spec:
  limits:
    - type: Container
      default:
        cpu: 500m
        memory: 256Mi
      defaultRequest:
        cpu: 100m
        memory: 64Mi`,
      },
      {
        title: "Harden kubelet and API-server flags (CIS Benchmark)",
        description:
          "Set on each node's kubelet and on the API server. These are the flags kube-bench validates; disable anonymous access and use Webhook authorization.",
        lang: "bash",
        code: `# kubelet (per node)
--anonymous-auth=false
--authorization-mode=Webhook
--read-only-port=0

# kube-apiserver
--anonymous-auth=false
--authorization-mode=Node,RBAC

# etcd
--client-cert-auth=true
--peer-client-cert-auth=true`,
      },
      {
        title: "Scan images and check versions against the support window",
        description:
          "Gate builds on a vulnerability scan so a stale image never ships, and audit the control plane and every kubelet, upgrading anything approaching or past EOL.",
        lang: "bash",
        code: `# CI step - non-zero exit blocks the pipeline
trivy image --exit-code 1 --severity HIGH,CRITICAL \\
  registry.example.com/web:1.27.4

# control plane + every node's kubelet version
kubectl version -o json | jq -r '.serverVersion.gitVersion'
kubectl get nodes -o custom-columns=NODE:.metadata.name,KUBELET:.status.nodeInfo.kubeletVersion`,
      },
    ],
    bestPractices: [
      "Run kube-bench (CIS Kubernetes Benchmark) against the control plane and nodes, in CI and on a schedule.",
      "Set automountServiceAccountToken: false on the default ServiceAccount in every namespace, and opt in per-pod when a token is required.",
      "Give every non-system namespace a ResourceQuota and a LimitRange.",
      "Disable anonymous auth and the read-only port on the kubelet; serve the API over TLS only and require client-cert auth on etcd.",
      "Track the Kubernetes patch-release support window and upgrade the control plane and node kubelets together before any component reaches EOL.",
      "Run image scanning (Trivy, Grype) in CI, pin images by digest, and keep add-ons (ingress-nginx, CoreDNS, CNI, CSI) on their own patch cadence.",
    ],
  },

  checker: {
    checkId: "k07",
    whatItChecks:
      "For each non-system namespace, checks that the default ServiceAccount disables token auto-mount and that the namespace defines a ResourceQuota or LimitRange; also queries the API server version and every node's kubelet version and flags any below the minimum supported Kubernetes minor (the EOL floor).",
    passCriteria: [
      "Each namespace's default ServiceAccount sets automountServiceAccountToken: false.",
      "Each namespace has at least one ResourceQuota or LimitRange.",
      "The control plane minor version is at or above the supported floor (v1.28+), and every node's kubelet is too.",
      "(Narrative) kubelet/API-server disable anonymous auth; etcd requires client-cert auth; container images are scanned and current.",
    ],
  },

  references: [
    {
      label: "OWASP K8s Top 10 (2025) - K07",
      url: "https://owasp.org/www-project-kubernetes-top-ten/",
    },
    {
      label: "CIS Kubernetes Benchmark",
      url: "https://www.cisecurity.org/benchmark/kubernetes",
    },
    {
      label: "kube-bench",
      url: "https://github.com/aquasecurity/kube-bench",
    },
    {
      label: "Kubernetes Patch Releases & Support Period",
      url: "https://kubernetes.io/releases/patch-releases/",
    },
    {
      label: "Trivy - container image vulnerability scanner",
      url: "https://trivy.dev/",
    },
  ],
};
