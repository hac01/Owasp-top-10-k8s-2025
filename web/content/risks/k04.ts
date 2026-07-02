import type { Risk } from "../types";

export const k04: Risk = {
  id: "K04",
  slug: "missing-policy-enforcement",
  title: "Lack of Cluster-Level Policy Enforcement",
  severity: "Medium",
  tagline:
    "With no admission engine enforcing rules cluster-wide, insecure resources slip through in every namespace.",
  icon: "🛂",

  overview: [
    "Kubernetes accepts whatever you ask it to run. Unless something inspects each resource at admission time, a pod that is privileged, runs as root, or mounts the host is created just as happily as a hardened one. Security then depends on every engineer remembering every rule on every manifest - which never holds at scale.",
    "Centralized policy enforcement moves the rules from tribal knowledge into the API server's admission path. The built-in Pod Security Admission controller (via the `pod-security.kubernetes.io/*` namespace labels) or a policy engine like Kyverno or OPA/Gatekeeper evaluates every incoming resource and rejects the ones that violate policy - everywhere, automatically.",
    "The failure mode is not a single bad setting; it is the *absence* of a guardrail. A namespace with no `enforce` label, or one set to `privileged`, silently admits everything. Insecure workloads that K01-style controls would flag never even get stopped, and the same gap repeats across every unlabeled namespace in the cluster.",
  ],
  impact: [
    "Insecure workloads (privileged, root, hostPath, host-namespace) are admitted with no objection, cluster-wide.",
    "Security posture drifts silently: each new namespace starts with zero enforcement unless someone remembers to label it.",
    "Inconsistent controls - one team enforces 'restricted', another enforces nothing - make audits and compliance claims meaningless.",
    "A single missed namespace becomes the soft target an attacker deploys or pivots into.",
  ],
  rootCauses: [
    "No Pod Security Admission labels on namespaces, so the built-in controller enforces nothing.",
    "Enforcement set to `privileged` (the no-op level) instead of `baseline` or `restricted`.",
    "No policy engine (Kyverno, OPA/Gatekeeper) installed, so custom org rules are never checked.",
    "Policies run in `warn`/`audit` mode only and are never promoted to `enforce`.",
    "New namespaces created ad hoc without inheriting a default policy baseline.",
  ],

  attackScenario: {
    summary:
      "An attacker (or a careless deploy) lands an insecure pod in a namespace that no policy guards, then uses that foothold to escalate.",
    steps: [
      "The attacker gains the ability to create pods in a namespace - via a leaked kubeconfig, a CI token, or an over-broad RBAC role.",
      "That namespace has no `pod-security.kubernetes.io/enforce` label, so admission control does nothing.",
      "They apply a pod that is privileged, runs as root, and hostPath-mounts the node root filesystem - exactly what a 'restricted' policy would reject.",
      "The API server admits it without complaint because there is no policy to say no.",
      "From that privileged pod the attacker breaks out to the node and pivots across the cluster - a K01 breakout that centralized enforcement would have blocked at the door.",
    ],
  },

  challenge: {
    scenario:
      "You have permission to create pods in NimbusMart's `platform` namespace - the internal tooling domain where `ci-runner` and `admin-portal` live. It was spun up ad hoc and carries no Pod Security Admission labels, so nothing inspects what gets scheduled there. No engine stands between your manifest and the kubelet.",
    objective:
      "Drop a rogue `debug-shell` pod that is blatantly non-compliant - privileged, root, hostPID, host-root mounted - into the unguarded `platform` namespace. Because there is no admission control to say no, it is admitted and runs; read the flag it prints to prove an insecure workload sailed straight through.",
    difficulty: "Medium",
    points: 200,
    flagFormat: "FLAG{...}",
    flagHash: "c65a01d5ccb0bb962c5498e66abaa2c42d2d3a6077882de0ba1e3c9bf48d69d9",
    hints: [
      "Check the `platform` namespace for Pod Security Admission labels: `kubectl get ns platform -o jsonpath='{.metadata.labels}'`. No `pod-security.kubernetes.io/enforce` label means nothing is enforced.",
      "Apply the rogue `debug-shell` pod. In a guarded namespace admission would reject it; here it is created and reaches Running.",
      "The flag is only printed because the pod was actually admitted and ran. Read it with `kubectl logs -n platform debug-shell` (or `kubectl exec -n platform debug-shell -- cat /root/flag.txt`).",
    ],
  },

  lab: {
    objective:
      "Admit a wildly non-compliant `debug-shell` pod into the unguarded `platform` namespace and capture the flag it prints, then enable built-in Pod Security Admission and watch the same pod get rejected at admission time.",
    prerequisites: [
      "A local cluster: `kind create cluster --config labs/kind-cluster.yaml`",
      "kubectl configured to talk to that cluster",
      "No add-ons needed - this lab uses only built-in Pod Security Admission.",
    ],
    vulnerableManifest: "labs/k04-policy-enforcement/vulnerable.yaml",
    fixedManifest: "labs/k04-policy-enforcement/fixed.yaml",
    steps: [
      {
        title: "Create the unguarded namespace and admit the rogue debug-shell",
        description:
          "The `platform` namespace has no Pod Security Admission labels, so the privileged, root, hostPID debug-shell pod is admitted with no policy to stop it.",
        command:
          "kubectl apply -f labs/k04-policy-enforcement/vulnerable.yaml",
        expected:
          "namespace/platform created / pod/debug-shell created",
        kind: "setup",
      },
      {
        title: "Confirm the rogue pod was admitted",
        description:
          "Nothing rejected it. In a cluster with centralized enforcement this pod would never have been created.",
        command: "kubectl get pod debug-shell -n platform",
        expected:
          "debug-shell is Running - an insecure workload slipped straight through admission.",
        kind: "attack",
      },
      {
        title: "Read the flag the admitted pod printed",
        description:
          "The flag is emitted only because the pod actually ran. Pull it from the pod's logs (or exec and cat the file it wrote).",
        command: "kubectl logs -n platform debug-shell",
        expected:
          "FLAG{no_admission_control_admits_anything} - submit this on the Challenge tab.",
        kind: "attack",
      },
      {
        title: "Turn on centralized enforcement",
        description:
          "Apply the fixed manifest, which labels the same `platform` namespace with `pod-security.kubernetes.io/enforce: restricted` (plus audit/warn) and ships a compliant replacement workload.",
        command:
          "kubectl delete -f labs/k04-policy-enforcement/vulnerable.yaml --ignore-not-found && kubectl apply -f labs/k04-policy-enforcement/fixed.yaml",
        expected:
          "namespace/platform configured / pod/platform-tools created",
        kind: "fix",
      },
      {
        title: "Re-apply the rogue pod - now rejected",
        description:
          "With the namespace enforcing the 'restricted' profile, the built-in admission controller refuses the privileged debug-shell outright, so the flag can never be printed.",
        command:
          "kubectl apply -f labs/k04-policy-enforcement/vulnerable.yaml",
        expected:
          "Error from server (Forbidden): pods \"debug-shell\" is forbidden: violates PodSecurity \"restricted:latest\": privileged, host namespaces (hostPID=true), allowPrivilegeEscalation != false, ...",
        kind: "verify",
      },
      {
        title: "Confirm compliant workloads still run",
        description:
          "Centralized policy blocks the bad and admits the good - legitimate workloads are unaffected. The k04 checker now passes because `platform` enforces a Pod Security Standard.",
        command: "kubectl get pod platform-tools -n platform",
        expected:
          "platform-tools is Running - the guardrail rejects only what violates the policy.",
        kind: "verify",
      },
    ],
  },

  defense: {
    summary:
      "Make policy the default, not an afterthought: enforce a Pod Security Standard on every namespace and back it with a policy engine so no insecure resource is admitted anywhere.",
    patches: [
      {
        title: "Enforce a Pod Security Standard on every namespace",
        description:
          "Label each non-system namespace so the built-in Pod Security Admission controller rejects violating pods. Use audit/warn to surface issues before flipping enforce on.",
        lang: "yaml",
        code: `apiVersion: v1
kind: Namespace
metadata:
  name: apps
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted`,
      },
      {
        title: "Never leave enforcement at 'privileged'",
        description:
          "The `privileged` level is a no-op that admits everything. Use `baseline` for a minimal bar or `restricted` for hardened workloads.",
        lang: "yaml",
        code: `# BAD - enforces nothing
pod-security.kubernetes.io/enforce: privileged

# GOOD - rejects privilege escalation, host access, root, etc.
pod-security.kubernetes.io/enforce: restricted`,
      },
      {
        title: "Add a policy engine for org-specific rules",
        description:
          "Pod Security Admission covers pod hardening; a policy engine like Kyverno enforces rules PSA cannot, such as requiring image registries, labels, or resource limits - cluster-wide.",
        lang: "yaml",
        code: `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-resource-limits
spec:
  validationFailureAction: Enforce
  rules:
    - name: require-limits
      match:
        any:
          - resources:
              kinds: ["Pod"]
      validate:
        message: "CPU and memory limits are required."
        pattern:
          spec:
            containers:
              - resources:
                  limits:
                    cpu: "?*"
                    memory: "?*"`,
      },
    ],
    bestPractices: [
      "Apply a `baseline` or `restricted` enforce label to every non-system namespace - treat an unlabeled namespace as a bug.",
      "Roll out with `warn`/`audit` first, review violations, then promote to `enforce`.",
      "Automate namespace creation so new namespaces inherit a policy baseline by default.",
      "Layer a policy engine (Kyverno / OPA Gatekeeper) for rules Pod Security Admission cannot express.",
      "Continuously scan the cluster for namespaces missing enforcement (see the k04 checker).",
    ],
  },

  checker: {
    checkId: "k04",
    whatItChecks:
      "Lists all non-system namespaces and flags any that are missing the pod-security.kubernetes.io/enforce label or set it to the weak 'privileged' value.",
    passCriteria: [
      "Every non-system namespace has a pod-security.kubernetes.io/enforce label.",
      "No namespace enforces the 'privileged' (no-op) level.",
      "Enforcement is set to 'baseline' or 'restricted'.",
    ],
  },

  references: [
    {
      label: "OWASP K8s Top 10 - K04",
      url: "https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K04-policy-enforcement",
    },
    {
      label: "Enforce Pod Security Standards with Namespace Labels",
      url: "https://kubernetes.io/docs/tasks/configure-pod-container/enforce-standards-namespace-labels/",
    },
    {
      label: "Kyverno - Kubernetes Native Policy Management",
      url: "https://kyverno.io/docs/",
    },
  ],
};
