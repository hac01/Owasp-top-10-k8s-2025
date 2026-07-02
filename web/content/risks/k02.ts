import type { Risk } from "../types";

export const k02: Risk = {
  id: "K02",
  slug: "overly-permissive-authorization",
  title: "Overly Permissive Authorization Configurations",
  severity: "High",
  tagline:
    "A wildcard ClusterRole on NimbusMart's catalog-api turned one stolen token into a key to the ops vault.",
  icon: "🔑",

  overview: [
    "Role-Based Access Control (RBAC) is Kubernetes' primary authorization mechanism. `Role`/`ClusterRole` objects declare which verbs may be performed on which resources, and `RoleBinding`/`ClusterRoleBinding` objects grant those permissions to users, groups, and service accounts.",
    "RBAC is powerful but easy to over-grant. The most dangerous pattern is the wildcard rule - `verbs: [\"*\"]`, `resources: [\"*\"]`, `apiGroups: [\"*\"]` - which hands the subject the ability to do anything to anything. A close second is binding the built-in `cluster-admin` ClusterRole to a workload's service account or to a broad group like `system:authenticated`.",
    "Because every pod is issued a service account token by default, an over-permissive binding means an attacker who compromises a single container inherits those rights. NimbusMart's `storefront/catalog-api` is a textbook case: its ServiceAccount is bound to a wildcard ClusterRole, so a foothold in that one pod becomes a key that reads Secrets in *every* namespace - including the `nimbusmart-ops` vault.",
    "Least privilege is the goal: each identity should hold only the specific verbs on the specific resources it genuinely needs, and nothing more.",
  ],
  impact: [
    "Credential theft to cluster takeover: a token bound to a wildcard role can read every Secret, including other service accounts' tokens and cloud credentials.",
    "Privilege escalation: `create`/`bind`/`escalate` verbs let an attacker grant themselves more rights or run a pod that mounts a more powerful token.",
    "Data exfiltration: `get`/`list` on secrets and configmaps across namespaces exposes API keys, database passwords, and TLS private keys.",
    "Persistence and tampering: broad write access allows creating backdoor deployments, mutating webhooks, or cron jobs that survive remediation.",
  ],
  rootCauses: [
    "Copy-pasted `cluster-admin` bindings or wildcard rules used to 'just make it work' during development.",
    "Operators and Helm charts that request far more access than the workload actually uses.",
    "Binding roles to `system:authenticated` or `system:anonymous`, which effectively grants everyone.",
    "No review of `kubectl auth can-i --list` output before shipping a service account.",
    "Treating RBAC as all-or-nothing instead of enumerating the exact verbs/resources needed.",
  ],

  attackScenario: {
    summary:
      "An attacker who lands in a pod uses its over-permissioned service account token to read secrets and pivot to full cluster control.",
    steps: [
      "The attacker achieves code execution in an application pod (e.g. via an RCE) whose service account is bound to a wildcard Role.",
      "They read the projected token at /var/run/secrets/kubernetes.io/serviceaccount/token and point kubectl (or curl) at the API server.",
      "`kubectl auth can-i --list` reveals `*` on `*` - the token can do anything in the namespace.",
      "They dump every Secret, harvesting other service account tokens, registry pull credentials, and cloud provider keys.",
      "Using a more powerful stolen token - or a cluster-admin binding - they create workloads in kube-system and establish cluster-wide persistence.",
    ],
  },

  challenge: {
    scenario:
      "You've popped a shell in NimbusMart's `storefront/catalog-api` pod. It should only serve product listings, but whoever set it up bound its ServiceAccount to a wildcard ClusterRole - `verbs/resources/apiGroups: [\"*\"]`, cluster-wide. The real prize sits one namespace over: a Secret named `master-vault` in `nimbusmart-ops` that the storefront has no business reading.",
    objective:
      "Use the catalog-api pod's mounted ServiceAccount token to read the `master-vault` Secret in the `nimbusmart-ops` namespace and capture the flag.",
    difficulty: "Hard",
    points: 300,
    flagFormat: "FLAG{...}",
    flagHash: "15409df1d4e427c2a2e19668fa101b9ad81260319c570383950066ffb81bd9fa",
    hints: [
      "The pod already carries a token. Ask the API server what it can do: `kubectl exec -n storefront catalog-api -- kubectl auth can-i --list`.",
      "A wildcard *ClusterRole* is cluster-wide - it is not confined to the storefront namespace. Try `-n nimbusmart-ops`.",
      "The flag lives in a Secret. Read it and decode: `kubectl exec -n storefront catalog-api -- kubectl get secret master-vault -n nimbusmart-ops -o jsonpath='{.data.flag}' | base64 -d`.",
    ],
  },

  lab: {
    objective:
      "Abuse the catalog-api ServiceAccount's wildcard ClusterRole to read the ops-vault secret in another namespace, then redeploy a least-privilege namespaced Role that makes the vault unreachable.",
    prerequisites: [
      "A local cluster: `kind create cluster --config labs/kind-cluster.yaml`",
      "kubectl configured to talk to that cluster",
    ],
    setupManifest: "labs/k02-authorization/setup.yaml",
    vulnerableManifest: "labs/k02-authorization/vulnerable.yaml",
    fixedManifest: "labs/k02-authorization/fixed.yaml",
    steps: [
      {
        title: "Seed the ops vault and deploy the over-permissioned pod",
        description:
          "The setup manifest creates the `nimbusmart-ops` namespace with the high-value `master-vault` Secret. The vulnerable manifest is the compromised `catalog-api`: a ServiceAccount bound to a wildcard ClusterRole + ClusterRoleBinding, and a pod that mounts that token.",
        command:
          "kubectl apply -f labs/k02-authorization/setup.yaml && kubectl apply -f labs/k02-authorization/vulnerable.yaml",
        expected:
          "namespace/nimbusmart-ops created / secret/master-vault created / ... / clusterrole + clusterrolebinding created / pod/catalog-api created",
        kind: "setup",
      },
      {
        title: "Enumerate what the catalog-api token can do",
        description:
          "Ask the API server directly, using the pod's own mounted token. The wildcard ClusterRole means: anything, anywhere.",
        command:
          "kubectl exec -n storefront catalog-api -- kubectl auth can-i --list",
        expected:
          "A row showing *.* with verbs [*] - the SA can perform any action on any resource cluster-wide.",
        kind: "attack",
      },
      {
        title: "Read the ops vault across the namespace boundary",
        description:
          "Because the grant is a cluster-wide ClusterRole, the token can read Secrets in namespaces the storefront should never touch. Pull the flag out of `nimbusmart-ops`.",
        command:
          "kubectl exec -n storefront catalog-api -- kubectl get secret master-vault -n nimbusmart-ops -o jsonpath='{.data.flag}' | base64 -d",
        expected:
          "FLAG{wildcard_rbac_opens_the_ops_vault} - submit this on the Challenge tab.",
        kind: "attack",
      },
      {
        title: "Clean up and deploy least-privilege RBAC",
        description:
          "The fixed manifest deletes the wildcard ClusterRole/ClusterRoleBinding and replaces them with a namespaced Role that grants only get/list on configmaps in `storefront`.",
        command:
          "kubectl delete -f labs/k02-authorization/vulnerable.yaml && kubectl apply -f labs/k02-authorization/fixed.yaml",
        expected:
          "wildcard objects deleted / recreated with a scoped Role, RoleBinding, and ConfigMap",
        kind: "fix",
      },
      {
        title: "Verify the ops vault is now unreachable",
        description:
          "Re-run the exploit against the hardened pod. The cluster-wide wildcard is gone, so reading the vault in `nimbusmart-ops` is Forbidden.",
        command:
          "kubectl exec -n storefront catalog-api -- kubectl get secret master-vault -n nimbusmart-ops 2>&1 || echo FORBIDDEN",
        expected:
          "Error from server (Forbidden) - the flag is unreachable and the k02 checker passes.",
        kind: "verify",
      },
    ],
  },

  defense: {
    summary:
      "Grant only the specific verbs on the specific resources each identity needs, never wildcards, and reserve cluster-admin for real human administrators.",
    patches: [
      {
        title: "Replace wildcard rules with explicit, scoped rules",
        description:
          "Enumerate the exact apiGroups, resources, and verbs the workload uses - and pin to named resources where possible.",
        lang: "yaml",
        code: `rules:
  # Instead of apiGroups/resources/verbs all "*":
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["app-config"]
    verbs: ["get", "list", "watch"]`,
      },
      {
        title: "Prefer namespaced Roles over ClusterRoles",
        description:
          "Use a Role + RoleBinding to confine access to one namespace unless the workload genuinely needs cluster-wide reach.",
        lang: "yaml",
        code: `kind: RoleBinding          # not ClusterRoleBinding
metadata:
  name: app-rolebinding
  namespace: default
subjects:
  - kind: ServiceAccount
    name: app-sa
    namespace: default
roleRef:
  kind: Role               # not the cluster-admin ClusterRole
  name: app-role
  apiGroup: rbac.authorization.k8s.io`,
      },
      {
        title: "Never bind cluster-admin to workloads or wide groups",
        description:
          "Audit ClusterRoleBindings for cluster-admin granted to service accounts, system:authenticated, or system:anonymous, and remove them.",
        lang: "bash",
        code: `# Find every subject bound to cluster-admin
kubectl get clusterrolebindings -o json \\
  | jq '.items[] | select(.roleRef.name=="cluster-admin")
        | {name:.metadata.name, subjects}'`,
      },
    ],
    bestPractices: [
      "Audit permissions with `kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>` before shipping.",
      "Ban wildcards (`*`) in verbs, resources, and apiGroups via an admission policy (OPA/Gatekeeper, Kyverno).",
      "Disable automountServiceAccountToken on pods that never call the API server.",
      "Reserve cluster-admin for named human users; give workloads narrowly-scoped Roles.",
      "Regularly run RBAC linters like `rbac-tool`, `kubiscan`, or `kube-bench` to catch drift.",
    ],
  },

  checker: {
    checkId: "k02",
    whatItChecks:
      "Lists Roles and ClusterRoles for wildcard verbs/resources/apiGroups, and inspects ClusterRoleBindings for cluster-admin granted to service accounts or over-broad groups. Built-in system: roles are skipped to reduce noise.",
    passCriteria: [
      "No user-defined Role or ClusterRole uses \"*\" in verbs.",
      "No user-defined Role or ClusterRole uses \"*\" in resources.",
      "No user-defined Role or ClusterRole uses \"*\" in apiGroups.",
      "cluster-admin is not bound to any ServiceAccount.",
      "cluster-admin is not bound to system:authenticated, system:anonymous, or system:unauthenticated.",
    ],
  },

  references: [
    {
      label: "OWASP K8s Top 10 - K02",
      url: "https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K02-overly-permissive-authorization",
    },
    {
      label: "Using RBAC Authorization",
      url: "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
    },
    {
      label: "Role Based Access Control Good Practices",
      url: "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
    },
  ],
};
