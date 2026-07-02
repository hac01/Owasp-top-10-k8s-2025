import type { Risk } from "../types";

export const k03: Risk = {
  id: "K03",
  slug: "secrets-management-failures",
  title: "Secrets Management Failures",
  severity: "High",
  tagline:
    "Passwords and API keys hardcoded in env vars or ConfigMaps are one `kubectl get pod -o yaml` away from every attacker.",
  icon: "🔑",

  overview: [
    "Secrets management failures happen when credentials - database passwords, API keys, tokens, private keys - are stored, transmitted, or exposed in ways that make them trivially recoverable. In Kubernetes the classic mistake is hardcoding a secret as a plaintext `value` in a container's `env`, or stuffing it into a ConfigMap.",
    "Anything placed in a pod spec's `env` values or a ConfigMap is visible to anyone with `get pod` / `get configmap` rights, is printed by `kubectl exec ... env`, and is baked into the object stored in etcd. There is no encryption, no access boundary, and no rotation story - the credential is just sitting there in the clear.",
    "Even Kubernetes `Secret` objects are, by default, only base64-encoded rather than encrypted, and are stored in etcd. Without encryption-at-rest and tight RBAC, a compromised etcd backup or an over-permissioned service account hands an attacker every credential in the cluster.",
    "Doing it right means keeping credentials out of manifests entirely: source them from a `Secret` via `secretKeyRef` (ideally mounted as read-only files), turn on encryption-at-rest, and pull from an external secret manager so secrets are never committed to Git.",
  ],
  impact: [
    "Credential theft: a plaintext DB password or cloud API key in an env var is copied by anyone who can read the pod, leading to data breach or cloud account compromise.",
    "Blast radius beyond the cluster: leaked API keys (AWS, Stripe, third-party SaaS) let attackers pivot into external systems.",
    "Persistence: base64-only Secrets in an unencrypted etcd backup expose every credential the moment the backup leaks.",
    "No rotation / auditability: hardcoded secrets are rarely rotated and their exposure is invisible, so a leak can go unnoticed for months.",
  ],
  rootCauses: [
    "Credentials hardcoded as plaintext `value` fields in container `env`.",
    "Secrets stored in ConfigMaps, which are unencrypted and world-readable to anyone with `get configmap`.",
    "Secrets injected as environment variables (leak into `exec env`, child processes, and crash dumps) instead of mounted files.",
    "Encryption-at-rest for etcd never enabled, so `Secret` objects sit base64-only on disk.",
    "No external secret manager, so credentials get committed to Git and shared in manifests.",
    "Over-broad RBAC letting many service accounts `get` Secrets they never need.",
  ],

  attackScenario: {
    summary:
      "An attacker with even read-only access to a namespace harvests plaintext credentials from pod specs and pivots into the database and cloud account.",
    steps: [
      "The attacker gains a low-privilege foothold - a leaked kubeconfig, a compromised CI token, or an SSRF that can reach the API server with a service account that has `get pod` rights.",
      "They run `kubectl get pods -o yaml` and read the `env` blocks: `DB_PASSWORD` and `API_KEY` are right there in plaintext.",
      "For anything hidden in a ConfigMap, `kubectl get configmap -o yaml` reveals it just as easily - ConfigMaps are not secret.",
      "Using the stolen DB password, the attacker connects directly to the database and exfiltrates data; the cloud API key lets them enumerate and abuse external resources.",
      "Because the credentials were never rotated and the access left no obvious trace, the attacker maintains quiet, long-lived access.",
    ],
  },

  challenge: {
    scenario:
      "You've been handed read-only `get pod` access to NimbusMart's `checkout` namespace. The billing team rushed the `payments-api` to production and, to 'make it work quickly', pasted the live Stripe secret key straight into the Deployment's env block as a plaintext value. Anything sitting in a pod spec's env values is readable by anyone who can read the pod - and it's baked into etcd too.",
    objective:
      "Recover the hardcoded Stripe secret key from the `checkout/payments-api` pod spec - no RCE or exec required, just read what's already exposed.",
    difficulty: "Easy",
    points: 100,
    flagFormat: "FLAG{...}",
    flagHash: "c0b01b135741b76e5810ecec0b05e83e602b206d7f3adb095b5bf7239c29c12e",
    hints: [
      "You don't need a shell. `kubectl get pod` can dump the full spec, and env values are right there in it.",
      "Filter for the credential: `kubectl get pod -n checkout -o yaml | grep -i stripe`.",
      "If you'd rather read it from inside: `kubectl exec -n checkout deploy/payments-api -- env | grep STRIPE`. The STRIPE_SECRET_KEY value is the flag.",
    ],
  },

  lab: {
    objective:
      "Read the hardcoded Stripe key out of the payments-api pod spec, then redeploy a version that sources it from a Secret mounted as read-only files so the checker passes.",
    prerequisites: [
      "A local cluster: `kind create cluster --config labs/kind-cluster.yaml`",
      "kubectl configured to talk to that cluster",
    ],
    vulnerableManifest: "labs/k03-secrets/vulnerable.yaml",
    fixedManifest: "labs/k03-secrets/fixed.yaml",
    steps: [
      {
        title: "Deploy the vulnerable payments-api",
        description:
          "This Deployment hardcodes NimbusMart's Stripe secret key as a plaintext env value and drops a billing webhook token into a plaintext ConfigMap.",
        command: "kubectl apply -f labs/k03-secrets/vulnerable.yaml",
        expected:
          "namespace/checkout created / configmap/payments-config created / deployment.apps/payments-api created",
        kind: "setup",
      },
      {
        title: "Read the Stripe key straight out of the pod spec",
        description:
          "Anyone with `get pod` rights can recover the plaintext key - no exec, no exploit chain needed.",
        command:
          "kubectl get pod -n checkout -o yaml | grep -i stripe",
        expected:
          "value: FLAG{hardcoded_stripe_key_sk_live_nimbus} - the Stripe key in the clear. Submit it on the Challenge tab.",
        kind: "attack",
      },
      {
        title: "Or dump it from the container environment",
        description:
          "Secrets injected as env vars are trivially listed by anyone who can exec into the payments-api pod.",
        command:
          "kubectl exec -n checkout deploy/payments-api -- env | grep STRIPE",
        expected:
          "STRIPE_SECRET_KEY=FLAG{hardcoded_stripe_key_sk_live_nimbus} - the same flag from inside the container.",
        kind: "attack",
      },
      {
        title: "Confirm the ConfigMap leaks too",
        description:
          "ConfigMaps are unencrypted and readable to anyone with `get configmap` - never a place for credentials.",
        command:
          "kubectl get configmap payments-config -n checkout -o jsonpath='{.data.BILLING_WEBHOOK_TOKEN}'",
        expected: "whsec_9f8e7d6c5b4a3210nimbus - a second billing credential leaking from a ConfigMap.",
        kind: "attack",
      },
      {
        title: "Clean up and deploy the hardened payments-api",
        description:
          "The fixed manifest moves the Stripe key into a Secret mounted as read-only files under /etc/secrets and keeps only non-secret config in the ConfigMap.",
        command:
          "kubectl delete -f labs/k03-secrets/vulnerable.yaml && kubectl apply -f labs/k03-secrets/fixed.yaml",
        expected:
          "resources deleted / secret/payments-credentials created / deployment.apps/payments-api created",
        kind: "fix",
      },
      {
        title: "Verify the env no longer leaks the key and the checker passes",
        description:
          "The env is clean; the Stripe key now lives as a read-only file, not a literal in the pod spec, so the k03 check passes.",
        command:
          "kubectl exec -n checkout deploy/payments-api -- env | grep STRIPE || echo NO_SECRET_IN_ENV",
        expected: "NO_SECRET_IN_ENV - the plaintext env exposure is gone and `go run . --check k03 -n checkout` passes.",
        kind: "verify",
      },
    ],
  },

  defense: {
    summary:
      "Keep credentials out of manifests entirely: reference them from a Secret via secretKeyRef (or mount as files), enable encryption-at-rest, and source them from an external secret manager.",
    patches: [
      {
        title: "Reference a Secret instead of hardcoding a value",
        description:
          "Replace plaintext env values with `valueFrom.secretKeyRef` so the credential is never a literal in the pod spec.",
        lang: "yaml",
        code: `env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: app-credentials
        key: DB_PASSWORD`,
      },
      {
        title: "Prefer mounting secrets as read-only files",
        description:
          "Mounted files avoid env-var leakage into `exec env`, child processes, and crash dumps, and support live rotation.",
        lang: "yaml",
        code: `volumeMounts:
  - name: credentials
    mountPath: /etc/secrets
    readOnly: true
volumes:
  - name: credentials
    secret:
      secretName: app-credentials
      defaultMode: 0400`,
      },
      {
        title: "Enable encryption-at-rest for Secrets in etcd",
        description:
          "By default Secrets are only base64-encoded. Encrypt them at rest with a KMS provider (e.g. AWS KMS on EKS).",
        lang: "yaml",
        code: `apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources: ["secrets"]
    providers:
      - kms:
          name: aws-kms
          endpoint: unix:///var/run/kmsplugin/socket.sock
      - identity: {}`,
      },
    ],
    bestPractices: [
      "Never hardcode credentials in env values, ConfigMaps, or manifests committed to Git.",
      "Store secrets in a Secret and mount them as read-only files rather than env vars.",
      "Enable encryption-at-rest for etcd, backed by a KMS/HSM in production.",
      "Source secrets from an external manager (AWS Secrets Manager, HashiCorp Vault, External Secrets Operator, Secrets Store CSI driver) and rotate them regularly.",
      "Scope RBAC so only the workloads that need a Secret can `get` it.",
      "Scan manifests and images in CI for leaked credentials with tools like gitleaks or Trivy.",
    ],
  },

  checker: {
    checkId: "k03",
    whatItChecks:
      "Scans all pods for container environment variables whose name looks like a credential (PASSWORD, SECRET, TOKEN, API_KEY, etc.) and that carry a hardcoded plaintext value instead of a valueFrom.secretKeyRef.",
    passCriteria: [
      "No env var with a sensitive name (PASSWORD, PASSWD, SECRET, TOKEN, APIKEY, API_KEY, ACCESS_KEY, PRIVATE_KEY, CREDENTIAL) has a literal value.",
      "Sensitive env vars are sourced via valueFrom.secretKeyRef.",
      "Credentials are not stored in ConfigMaps.",
    ],
  },

  references: [
    {
      label: "OWASP K8s Top 10 - K03",
      url: "https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K03-secrets-management-failures",
    },
    {
      label: "Kubernetes Secrets",
      url: "https://kubernetes.io/docs/concepts/configuration/secret/",
    },
    {
      label: "Encrypting Secret Data at Rest",
      url: "https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/",
    },
  ],
};
