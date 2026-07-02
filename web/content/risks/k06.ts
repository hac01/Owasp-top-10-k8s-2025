import type { Risk } from "../types";

export const k06: Risk = {
  id: "K06",
  slug: "overly-exposed-components",
  title: "Overly Exposed Kubernetes Components",
  severity: "High",
  tagline:
    "An internal ops dashboard published on a NodePort is a wide-open admin console for anyone who can reach the node.",
  icon: "📡",

  overview: [
    "Kubernetes ships with many components and interfaces that are powerful precisely because they are trusted: the API server, the kubelet, etcd, dashboards, metrics and debug endpoints, and the services your own workloads expose. Every one of them is meant to live behind a boundary - reachable only from inside the cluster or from a small set of authenticated operators.",
    "Overly Exposed Kubernetes Components is what happens when those boundaries slip. A Service gets flipped from `ClusterIP` to `NodePort` or `LoadBalancer` for convenience, the Kubernetes Dashboard is deployed with a public endpoint, the kubelet's read-only or authenticated port is left reachable, or the API server accepts anonymous requests. Each of these turns an internal control surface into an external attack surface.",
    "NimbusMart's `platform/admin-portal` is the classic slip: an internal ops dashboard that an engineer needed to see from their laptop, so they changed its Service to `type: NodePort` on nodePort 30080. On the lab's kind cluster that node port is mapped straight to the host, so the dashboard - which has no authentication of its own - is now reachable from outside the cluster by anyone who can hit the node.",
  ],
  impact: [
    "Direct access to internal control surfaces (dashboards, admin UIs, debug endpoints) that assume they are only reachable from inside the cluster and therefore have weak or no authentication.",
    "Information disclosure: exposed metrics, kubelet endpoints, or dashboards leak pod specs, environment variables, tokens, and cluster topology to an attacker.",
    "Cluster takeover: an anonymously-reachable API server or an authenticated Kubernetes Dashboard with a powerful service account is game over.",
    "Expanded attack surface: every NodePort/LoadBalancer service is another internet-facing door that must be patched, rate-limited, and monitored.",
  ],
  rootCauses: [
    "Switching a Service to `NodePort` or `LoadBalancer` for quick access instead of using `kubectl port-forward` or an authenticated ingress.",
    "Deploying the Kubernetes Dashboard, metrics, or debug tooling with an external endpoint and no authentication in front of it.",
    "Leaving the kubelet's ports or the API server's anonymous-auth enabled and reachable from outside the node's trust boundary.",
    "No NetworkPolicy, so any exposure is cluster-wide rather than limited to the callers that actually need it.",
    "No review of `Service` types or ingress in CI/CD, so an internal component silently becomes internet-facing.",
  ],

  attackScenario: {
    summary:
      "An attacker who can reach a cluster node discovers an internal component published on a node port and talks to it directly, with none of the boundaries the component assumed were in place.",
    steps: [
      "The attacker scans the node's IP and finds an unexpected open port (e.g. 30080) answering HTTP.",
      "The service on that port is an internal ops dashboard that was only ever meant to be reached from inside the cluster, so it has no authentication.",
      "Because a `NodePort` Service publishes on every node and (on kind) is mapped to the host, the attacker reaches it from outside the cluster with a single `curl`.",
      "The dashboard exposes operational data, other services, and - in the worst case - credentials or an API surface that leads deeper into the cluster.",
      "What should have been an internal-only control plane is now an unauthenticated public endpoint.",
    ],
  },

  challenge: {
    scenario:
      "During recon against NimbusMart you port-scan a cluster node and find an unexpected HTTP service answering on port 30080. It turns out to be `platform/admin-portal` - an internal ops dashboard that was never meant to leave the cluster. Someone published it on a NodePort so they could reach it from their laptop, and it has no authentication.",
    objective:
      "Reach the exposed internal component from outside the cluster and read what the dashboard serves at `http://localhost:30080`.",
    difficulty: "Medium",
    points: 200,
    flagFormat: "FLAG{...}",
    flagHash: "f2dad7a0fa8c3604d40de232d0f4f9482d57486dedc0cc409572b85fc1d34cf3",
    hints: [
      "The dashboard is an *internal* component - but check its Service type. `kubectl get svc -n platform` will tell you how it's published.",
      "A `NodePort` Service is reachable on every node, and this lab's kind cluster maps nodePort 30080 to the host. You don't need to be inside the cluster.",
      "Just hit it from your machine: `curl -s http://localhost:30080`. The flag is whatever the exposed dashboard serves.",
    ],
  },

  lab: {
    objective:
      "Reach NimbusMart's internal admin-portal from outside the cluster via its NodePort, capture the flag, then redeploy it as an internal-only ClusterIP service so the exposure is closed.",
    prerequisites: [
      "A local cluster: `kind create cluster --config labs/kind-cluster.yaml` (this maps nodePort 30080 to localhost:30080)",
      "kubectl configured to talk to that cluster",
      "curl on the host",
    ],
    vulnerableManifest: "labs/k06-exposed-components/vulnerable.yaml",
    fixedManifest: "labs/k06-exposed-components/fixed.yaml",
    steps: [
      {
        title: "Deploy the exposed dashboard",
        description:
          "Create the platform namespace, the admin-portal pod, and its NodePort Service that publishes the internal dashboard on nodePort 30080.",
        command: "kubectl apply -f labs/k06-exposed-components/vulnerable.yaml",
        expected:
          "namespace/platform created / pod/admin-portal created / service/admin-portal created",
        kind: "setup",
      },
      {
        title: "Confirm the internal component is published externally",
        description:
          "Inspect the Service type. A NodePort service publishes on every node - and on kind that node port is mapped to the host.",
        command: "kubectl get svc -n platform admin-portal",
        expected: "TYPE is NodePort and PORT(S) shows 80:30080/TCP.",
        kind: "attack",
      },
      {
        title: "Reach it from outside the cluster and capture the flag",
        description:
          "The dashboard has no authentication and is now reachable from the host. Hit it directly - no kubectl, no cluster access needed.",
        command: "curl -s http://localhost:30080",
        expected:
          "FLAG{nodeport_exposed_the_kube_dashboard} - submit this on the Challenge tab.",
        kind: "attack",
      },
      {
        title: "Close the exposure",
        description:
          "The fixed manifest puts the Service back to ClusterIP (internal only) and adds a default-deny NetworkPolicy, so the dashboard is no longer published to the host.",
        command:
          "kubectl delete -f labs/k06-exposed-components/vulnerable.yaml && kubectl apply -f labs/k06-exposed-components/fixed.yaml",
        expected:
          "resources deleted / namespace, pod, ClusterIP service and NetworkPolicy created",
        kind: "fix",
      },
      {
        title: "Verify the component is no longer reachable",
        description:
          "The Service is ClusterIP again, so localhost:30080 no longer routes to it. Run the checker to confirm no component is externally published.",
        command:
          "curl -s --max-time 5 http://localhost:30080 || echo NOT_EXPOSED",
        expected:
          "NOT_EXPOSED - and `go run . --check k06 -n platform` passes.",
        kind: "verify",
      },
    ],
  },

  defense: {
    summary:
      "Keep internal components internal: default to ClusterIP, reach them with port-forward or an authenticated ingress, and constrain everything with NetworkPolicy. Never publish a control surface on a NodePort or LoadBalancer without authentication in front of it.",
    patches: [
      {
        title: "Use ClusterIP for internal services",
        description:
          "Internal components should not be published on the node or a cloud load balancer. Keep them ClusterIP and reach them with `kubectl port-forward` for ad-hoc access.",
        lang: "yaml",
        code: `apiVersion: v1
kind: Service
metadata:
  name: admin-portal
  namespace: platform
spec:
  type: ClusterIP        # not NodePort / LoadBalancer
  selector:
    app: admin-portal
  ports:
    - port: 80
      targetPort: 5678
# Ad-hoc access without exposing anything:
#   kubectl -n platform port-forward svc/admin-portal 8080:80`,
      },
      {
        title: "Put authentication and TLS in front of anything external",
        description:
          "If a component genuinely must be reachable from outside, front it with an ingress/gateway that enforces authentication and TLS - never expose the component directly.",
        lang: "yaml",
        code: `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: admin-portal
  namespace: platform
  annotations:
    nginx.ingress.kubernetes.io/auth-url: "https://auth.nimbusmart.internal/verify"
    cert-manager.io/cluster-issuer: "letsencrypt"
spec:
  tls:
    - hosts: ["admin.nimbusmart.example"]
      secretName: admin-portal-tls
  rules:
    - host: admin.nimbusmart.example
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: admin-portal
                port: { number: 80 }`,
      },
      {
        title: "Default-deny with NetworkPolicy",
        description:
          "Limit which pods can reach a component so that even inside the cluster it is not broadly reachable. Start with default-deny ingress, then allow only the callers that need it.",
        lang: "yaml",
        code: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: admin-portal-default-deny
  namespace: platform
spec:
  podSelector:
    matchLabels:
      app: admin-portal
  policyTypes: ["Ingress"]
  ingress: []   # deny all, then add explicit allow rules`,
      },
    ],
    bestPractices: [
      "Default every Service to ClusterIP; require an explicit, reviewed justification for any NodePort or LoadBalancer.",
      "Reach internal dashboards and debug endpoints with `kubectl port-forward`, not by publishing a node port.",
      "Disable API server anonymous auth and lock down the kubelet's ports to the control plane's trust boundary.",
      "Never deploy the Kubernetes Dashboard (or any admin UI) with an external endpoint and no authentication.",
      "Enforce default-deny NetworkPolicies and audit Service types in CI so an internal component can't silently become internet-facing.",
    ],
  },

  checker: {
    checkId: "k06",
    whatItChecks:
      "Lists Services in non-system namespaces and flags any of type NodePort or LoadBalancer, which publish an internal component outside the cluster boundary.",
    passCriteria: [
      "No Service in a non-system namespace is of type NodePort.",
      "No Service in a non-system namespace is of type LoadBalancer.",
      "Internal components use ClusterIP (or headless) Services only.",
    ],
  },

  references: [
    {
      label: "OWASP K8s Top 10 (2025) - K06 Overly Exposed Kubernetes Components",
      url: "https://owasp.org/www-project-kubernetes-top-ten/",
    },
    {
      label: "Kubernetes Service types (ClusterIP / NodePort / LoadBalancer)",
      url: "https://kubernetes.io/docs/concepts/services-networking/service/#publishing-services-service-types",
    },
    {
      label: "Securing a Cluster - controlling access to cluster components",
      url: "https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/",
    },
  ],
};
