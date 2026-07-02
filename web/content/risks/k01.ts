import type { Risk } from "../types";

export const k01: Risk = {
  id: "K01",
  slug: "insecure-workload-configurations",
  title: "Insecure Workload Configurations",
  severity: "High",
  tagline:
    "A privileged batch job with the node's disk mounted is a container breakout waiting to happen.",
  icon: "📦",

  overview: [
    "A Kubernetes workload's security posture is defined largely by its `securityContext` and pod spec. When these are left at their permissive defaults, a single application vulnerability can escalate into full node - and often full cluster - compromise.",
    "The most common offenders are containers that run as UID 0 (root), request `privileged: true`, allow privilege escalation, mount the host filesystem, or share the host's PID/network/IPC namespaces. Each of these erodes the container isolation boundary that Kubernetes is supposed to provide.",
    "NimbusMart's `inventory-sync` job is a textbook example: a legacy batch job that someone made `privileged` and gave a `hostPath` mount of the entire node so it could 'write cache files fast'. That convenience is a breakout primitive.",
  ],
  impact: [
    "Container breakout: a privileged or hostPath-mounting pod can read/write the node filesystem and escape to the host.",
    "Node takeover: root-in-container plus a writable host mount lets an attacker add SSH keys or cron jobs on the node.",
    "Lateral movement: from a compromised node an attacker can steal the kubelet credentials and other pods' service account tokens.",
    "Cryptomining / resource abuse when no CPU/memory limits are set.",
  ],
  rootCauses: [
    "Security context omitted entirely, so containers run as root by default.",
    "`privileged: true` copied from a debugging example and never removed.",
    "hostPath volumes or `hostNetwork/hostPID` used for convenience.",
    "`allowPrivilegeEscalation` left unset (defaults to true).",
    "No admission control (Pod Security Standards / policy engine) to reject risky pods.",
  ],

  attackScenario: {
    summary:
      "An attacker who achieves code execution inside a permissively-configured pod pivots to the node and then the cluster.",
    steps: [
      "The app in the pod has an RCE (e.g. an SSRF or deserialization bug). The attacker gets a shell inside the container.",
      "The container runs as root and has `privileged: true`, so all host devices are visible under /dev.",
      "The attacker mounts the host root filesystem (or uses an already-present hostPath) and writes to /etc or the kubelet's directory.",
      "By reading /var/lib/kubelet or other pods' projected service account tokens, the attacker calls the API server with elevated rights.",
      "Game over: the single-pod compromise becomes a node and cluster compromise.",
    ],
  },

  challenge: {
    scenario:
      "You've landed a shell in NimbusMart's `data/inventory-sync` pod after exploiting a bug in its import script. It feels like a normal container - but the ops team left it `privileged` with the node's root filesystem mounted at `/host`. Sensitive operational data lives on the node itself, outside any container.",
    objective:
      "Break out of the container to the underlying node and read the ops secret the platform team stashed on the host at `/opt/nimbusmart/flag.txt`.",
    difficulty: "Medium",
    points: 200,
    flagFormat: "FLAG{...}",
    flagHash: "6642da6843baa0e0b5cee133b163ee0f4433b217c2bc7b015a7b588ba50dbd0e",
    hints: [
      "Check your privileges inside the pod: `id` and the container's capabilities. Are you actually contained?",
      "Look at what's mounted. A `hostPath` volume of `/` means the container can see the node's whole disk.",
      "The flag is on the NODE, not in the pod spec. Read it through the host mount: `cat /host/opt/nimbusmart/flag.txt`.",
    ],
  },

  lab: {
    objective:
      "Break out of the inventory-sync pod to the node, capture the flag, then redeploy a hardened version that blocks the same attack.",
    prerequisites: [
      "A local cluster: `kind create cluster --config labs/kind-cluster.yaml`",
      "kubectl configured to talk to that cluster",
    ],
    setupManifest: "labs/k01-insecure-workload/setup.yaml",
    vulnerableManifest: "labs/k01-insecure-workload/vulnerable.yaml",
    fixedManifest: "labs/k01-insecure-workload/fixed.yaml",
    steps: [
      {
        title: "Seed the node and deploy the vulnerable job",
        description:
          "The setup job plants the ops secret on the node; the vulnerable pod is the privileged `inventory-sync` you compromised.",
        command:
          "kubectl apply -f labs/k01-insecure-workload/setup.yaml && kubectl apply -f labs/k01-insecure-workload/vulnerable.yaml",
        expected: "job.batch/node-seed created / pod/inventory-sync created",
        kind: "setup",
      },
      {
        title: "Confirm you are root and privileged",
        description: "Exec into the pod and inspect your identity and capabilities.",
        command:
          "kubectl exec -it -n data inventory-sync -- sh -c 'id; cat /proc/1/status | grep CapEff'",
        expected: "uid=0(root) ... CapEff showing a full capability set (0000003fffffffff)",
        kind: "attack",
      },
      {
        title: "Break out to the node and capture the flag",
        description:
          "The hostPath mount exposes the node's entire root filesystem at /host. Read the ops secret the container was never meant to see.",
        command:
          "kubectl exec -it -n data inventory-sync -- cat /host/opt/nimbusmart/flag.txt",
        expected: "FLAG{nimbusmart_hostpath_broke_out_to_the_node} - submit this on the Challenge tab.",
        kind: "attack",
      },
      {
        title: "Clean up and deploy the hardened job",
        description:
          "The fixed manifest runs as a non-root user, drops all capabilities, forbids privilege escalation, and mounts a read-only root filesystem with no hostPath.",
        command:
          "kubectl delete -f labs/k01-insecure-workload/vulnerable.yaml && kubectl apply -f labs/k01-insecure-workload/fixed.yaml",
        expected: 'pod "inventory-sync" deleted / pod/inventory-sync created',
        kind: "fix",
      },
      {
        title: "Verify the breakout is now blocked",
        description:
          "Try the same move against the hardened pod. There is no /host mount, you are not root, and you cannot escalate.",
        command:
          "kubectl exec -it -n data inventory-sync -- sh -c 'id; ls /host 2>&1 || echo NO_HOST_MOUNT'",
        expected: "uid=10001 ... NO_HOST_MOUNT - the flag is unreachable.",
        kind: "verify",
      },
    ],
  },

  defense: {
    summary:
      "Set an explicit, least-privilege securityContext on every workload and enforce it at admission time so insecure pods are rejected before they ever run.",
    patches: [
      {
        title: "Run as non-root and drop all capabilities",
        description:
          "Force a non-root UID, forbid privilege escalation, drop every Linux capability, and use the RuntimeDefault seccomp profile.",
        lang: "yaml",
        code: `securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  allowPrivilegeEscalation: false
  privileged: false
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault
  readOnlyRootFilesystem: true`,
      },
      {
        title: "Never mount the host or share host namespaces",
        description:
          "Remove hostPath volumes and host namespace sharing unless there is a hard requirement (there almost never is for app workloads).",
        lang: "yaml",
        code: `# Pod spec - the safe defaults
hostPID: false
hostIPC: false
hostNetwork: false
volumes: []   # no hostPath volumes`,
      },
      {
        title: "Enforce the Restricted Pod Security Standard",
        description:
          "Label the namespace so the built-in Pod Security Admission controller rejects any pod that violates the 'restricted' profile.",
        lang: "yaml",
        code: `apiVersion: v1
kind: Namespace
metadata:
  name: data
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest`,
      },
    ],
    bestPractices: [
      "Apply the `restricted` Pod Security Standard to every non-system namespace.",
      "Always set resource requests and limits to prevent noisy-neighbor and DoS.",
      "Use a read-only root filesystem and mount writable scratch space as emptyDir.",
      "Scan manifests in CI with tools like kubesec, Checkov, or Trivy config.",
      "Prefer distroless / non-root base images so the container has no shell to abuse.",
    ],
  },

  checker: {
    checkId: "k01",
    whatItChecks:
      "Scans all pods for privileged containers, root execution, privilege escalation, hostPath mounts, host namespace sharing, and missing capability drops.",
    passCriteria: [
      "No container has privileged: true.",
      "runAsNonRoot is true (or runAsUser is > 0).",
      "allowPrivilegeEscalation is false.",
      "capabilities.drop includes ALL.",
      "No hostPath volumes and no hostPID/hostIPC/hostNetwork.",
    ],
  },

  references: [
    {
      label: "OWASP K8s Top 10 - K01",
      url: "https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K01-insecure-workload-configurations",
    },
    {
      label: "Pod Security Standards",
      url: "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
    },
    {
      label: "Configure a Security Context for a Pod",
      url: "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/",
    },
  ],
};
