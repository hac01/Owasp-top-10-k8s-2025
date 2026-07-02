import type { Risk } from "../types";

export const k05: Risk = {
  id: "K05",
  slug: "missing-network-segmentation",
  title: "Missing Network Segmentation Controls",
  severity: "High",
  tagline:
    "With no NetworkPolicies the pod network is flat - one compromised pod can reach every other pod, service, and the node metadata endpoint.",
  icon: "🕸️",

  overview: [
    "By default, every pod in a Kubernetes cluster can open a network connection to every other pod and service, in any namespace. There is no built-in segmentation: the pod network is flat and fully routable unless you explicitly restrict it with `NetworkPolicy` objects.",
    "This means the blast radius of a single compromised workload is the entire cluster. An attacker who lands in a low-value frontend pod can scan the pod CIDR, connect to internal databases, message queues, and admin APIs, and reach the cloud metadata endpoint (169.254.169.254) to steal node credentials.",
    "NetworkPolicies let you flip the model from 'allow all' to 'deny by default, allow what's needed.' A namespace-wide default-deny-ingress policy plus small, targeted allow policies recreate the tiered network segmentation that firewalls and VLANs provide in traditional infrastructure.",
    "The catch: NetworkPolicy objects are enforced by the CNI plugin, not by the API server. If your CNI doesn't support them (or you never wrote any), the objects are inert or absent and the network stays wide open.",
  ],
  impact: [
    "Lateral movement: a foothold in any pod becomes reachability to every database, cache, and internal service in the cluster.",
    "Data exfiltration: sensitive backends that assume 'only my clients can reach me' are directly connectable from unrelated, internet-facing pods.",
    "Metadata/credential theft: pods can reach the node metadata endpoint (169.254.169.254) and pull instance-role credentials.",
    "East-west attack surface: no segmentation means no containment - an incident in one team's namespace spreads freely to others.",
  ],
  rootCauses: [
    "No NetworkPolicies are defined, so Kubernetes' default 'allow all' pod networking applies.",
    "No default-deny-ingress baseline, so any pod added later is automatically reachable.",
    "A CNI plugin that does not enforce NetworkPolicy (or none installed) makes existing policies inert.",
    "Flat, single-namespace deployments that mix trust tiers (frontend + database) with no isolation.",
    "Policies written per-app as allow rules without a deny baseline, leaving gaps for unmatched traffic.",
  ],

  attackScenario: {
    summary:
      "An attacker who compromises NimbusMart's low-privilege `storefront/web-frontend` pod uses the flat network to pivot straight across namespaces to the `data/orders-db` datastore and the node metadata service.",
    steps: [
      "The public-facing `storefront/web-frontend` pod has an SSRF or RCE bug; the attacker gets code execution inside it.",
      "Because there is no NetworkPolicy, the attacker scans the pod network and cluster DNS for internal services in every namespace.",
      "They connect directly to `orders-db.data.svc.cluster.local` - a datastore in the `data` namespace that was never meant to accept traffic from the storefront tier - and read its contents.",
      "They also reach 169.254.169.254 and pull the node's cloud instance-role credentials.",
      "With database contents and node credentials in hand, the single-pod compromise becomes a cluster-wide breach.",
    ],
  },

  challenge: {
    scenario:
      "You have a shell in NimbusMart's internet-facing `storefront/web-frontend` pod. The cluster has no NetworkPolicy anywhere, so the pod network is completely flat - every pod can reach every other pod and service, across namespaces. The order records live in `data/orders-db`, a datastore in a different namespace that is supposed to be reachable only by the order-processing clients.",
    objective:
      "From the compromised `web-frontend` pod, pivot across namespaces to `orders-db.data.svc.cluster.local:5678` and read the flag it serves over HTTP.",
    difficulty: "Medium",
    points: 200,
    flagFormat: "FLAG{...}",
    flagHash:
      "424cf98124e8c6536c053972af571e71fc296fd79326fb258eaaf152c6da8494",
    hints: [
      "There is no segmentation. Check `kubectl get networkpolicies -A` - an empty list means every pod can talk to every other pod, in any namespace.",
      "Cluster DNS resolves services across namespaces as `<service>.<namespace>.svc.cluster.local`. The orders database is `orders-db` in the `data` namespace.",
      "The flag is served over HTTP on port 5678, not stored in the frontend. From inside web-frontend: `curl -s http://orders-db.data.svc.cluster.local:5678`.",
    ],
  },

  lab: {
    objective:
      "Prove that NimbusMart's `storefront/web-frontend` pod can freely reach the `data/orders-db` datastore across namespaces on a flat network, then apply a default-deny plus targeted-allow NetworkPolicy set so only intended clients are permitted.",
    prerequisites: [
      "A local cluster: `kind create cluster --config labs/kind-cluster.yaml`",
      "kubectl configured to talk to that cluster",
      "NetworkPolicy enforcement requires a CNI that supports it. Stock kind (kindnet) creates the policy objects but does NOT enforce them - the pivot may still succeed after the fix on default kind. Install Calico (`kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/calico.yaml`) to see traffic actually drop; either way the k05 checker validates that the policy objects exist.",
    ],
    vulnerableManifest: "labs/k05-network-segmentation/vulnerable.yaml",
    fixedManifest: "labs/k05-network-segmentation/fixed.yaml",
    steps: [
      {
        title: "Deploy the flat, unsegmented world",
        description:
          "Creates the `data` namespace with the `orders-db` pod/service (it serves the flag over HTTP on 5678) and the `storefront` namespace with your `web-frontend` foothold - and no NetworkPolicy at all.",
        command:
          "kubectl apply -f labs/k05-network-segmentation/vulnerable.yaml",
        expected:
          "namespace/data created / namespace/storefront created / pod/orders-db created / service/orders-db created / pod/web-frontend created",
        kind: "setup",
      },
      {
        title: "Confirm the network is flat",
        description:
          "List NetworkPolicies across all namespaces to see that nothing segments the traffic - the wide-open network is the weakness, not an accident.",
        command: "kubectl get networkpolicies -A",
        expected: "No resources found - there is no segmentation anywhere.",
        kind: "attack",
      },
      {
        title: "Pivot across namespaces to the orders DB",
        description:
          "The storefront frontend has no business talking to the orders datastore, but on a flat network it can resolve and reach it via cluster DNS. Curl the cross-namespace service to read the flag.",
        command:
          "kubectl exec -n storefront web-frontend -- curl -s http://orders-db.data.svc.cluster.local:5678",
        expected:
          "FLAG{flat_network_reached_the_orders_db} - submit this on the Challenge tab.",
        kind: "attack",
      },
      {
        title: "Segment the network",
        description:
          "The fixed manifest adds a default-deny-ingress policy in `data` plus a targeted allow that only lets app=orders-client pods reach orders-db, and a default-deny-ingress baseline in `storefront`.",
        command:
          "kubectl apply -f labs/k05-network-segmentation/fixed.yaml",
        expected:
          "networkpolicy.networking.k8s.io/default-deny-ingress created (data) / networkpolicy.networking.k8s.io/allow-orders-db-from-clients created / networkpolicy.networking.k8s.io/default-deny-ingress created (storefront)",
        kind: "fix",
      },
      {
        title: "Verify the segmentation is in place",
        description:
          "web-frontend is not labelled app=orders-client, so under the deny-by-default policy set it is no longer permitted to reach orders-db. CNI CAVEAT: on a stock kind cluster (kindnet) NetworkPolicy is NOT enforced, so this curl may STILL return the flag - that is a CNI limitation, not a broken fix. The real remediation signal (and what the k05 checker validates) is that the correct policy objects now exist; on a policy-enforcing CNI such as Calico the request is dropped.",
        command:
          "kubectl get networkpolicies -A && kubectl exec -n storefront web-frontend -- curl -s --max-time 5 http://orders-db.data.svc.cluster.local:5678 || echo BLOCKED_BY_NETWORKPOLICY",
        expected:
          "default-deny-ingress policies now exist in data and storefront. On an enforcing CNI the curl times out and prints BLOCKED_BY_NETWORKPOLICY; on default kindnet it may still return the flag (CNI does not enforce policy).",
        kind: "verify",
      },
    ],
  },

  defense: {
    summary:
      "Adopt a deny-by-default posture: put a default-deny-ingress NetworkPolicy in every namespace, then add small targeted allow policies for the traffic that is genuinely required - and run a CNI that enforces them.",
    patches: [
      {
        title: "Default-deny all ingress in the namespace",
        description:
          "An empty podSelector selects every pod; listing Ingress in policyTypes with no ingress rules drops all inbound traffic until you allow it explicitly.",
        lang: "yaml",
        code: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: data
spec:
  podSelector: {}        # every pod in the namespace
  policyTypes:
    - Ingress            # no ingress rules => deny all inbound`,
      },
      {
        title: "Allow only the traffic that is required",
        description:
          "Add a narrow allow policy so only pods with a specific label can reach the sensitive backend on a specific port.",
        lang: "yaml",
        code: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-orders-db-from-clients
  namespace: data
spec:
  podSelector:
    matchLabels:
      app: orders-db
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: orders-client
      ports:
        - protocol: TCP
          port: 5678`,
      },
      {
        title: "Also lock down egress to block metadata access",
        description:
          "A default-deny-egress policy prevents compromised pods from reaching the node metadata endpoint (169.254.169.254) and exfiltrating data.",
        lang: "yaml",
        code: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: data
spec:
  podSelector: {}
  policyTypes:
    - Egress
  # add explicit egress allows for DNS and required services only`,
      },
    ],
    bestPractices: [
      "Install and run a CNI that enforces NetworkPolicy (Calico, Cilium, Antrea) - policies without an enforcing CNI are inert.",
      "Put a default-deny-ingress (and ideally default-deny-egress) policy in every non-system namespace.",
      "Write targeted allow policies keyed on pod labels rather than IPs, and keep them minimal.",
      "Explicitly block egress to the cloud metadata endpoint (169.254.169.254/32) unless a pod truly needs it.",
      "Separate trust tiers into namespaces and use namespaceSelectors to control cross-namespace traffic.",
      "Test policies in CI (e.g. with `kubectl` connectivity probes or a tool like Cilium's connectivity test).",
    ],
  },

  checker: {
    checkId: "k05",
    whatItChecks:
      "For every non-system namespace that runs at least one pod, lists NetworkPolicies and flags namespaces that have none, plus namespaces that have policies but no default-deny-ingress baseline.",
    passCriteria: [
      "Every non-system namespace with workloads has at least one NetworkPolicy.",
      "A default-deny-ingress policy exists (empty podSelector {} with Ingress in policyTypes).",
      "Sensitive backends are reachable only via targeted allow policies.",
    ],
  },

  references: [
    {
      label: "OWASP K8s Top 10 - K05",
      url: "https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K05-network-segmentation",
    },
    {
      label: "Kubernetes - Network Policies",
      url: "https://kubernetes.io/docs/concepts/services-networking/network-policies/",
    },
    {
      label: "Declare Network Policy (walkthrough)",
      url: "https://kubernetes.io/docs/tasks/administer-cluster/declare-network-policy/",
    },
  ],
};
