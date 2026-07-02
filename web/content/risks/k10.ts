import type { Risk } from "../types";

export const k10: Risk = {
  id: "K10",
  slug: "inadequate-logging-monitoring",
  title: "Inadequate Logging and Monitoring",
  severity: "Medium",
  tagline:
    "Without audit logs, log shipping, and runtime monitoring, an attacker's every move - exec, secret read, lateral pivot - leaves no trace.",
  icon: "🔍",

  overview: [
    "Kubernetes generates a wealth of security-relevant signals: the API server can emit an audit log of every request, the kubelet and containers write logs to the node, and runtime sensors can watch syscalls for suspicious behaviour. But almost none of this is collected by default. A fresh cluster keeps container logs only until the pod is deleted or the node rotates them, and the API server audit log is disabled entirely unless you configure a policy.",
    "The result is a cluster that is effectively blind. When an attacker `kubectl exec`s into a pod, reads a Secret, or creates a privileged workload, those events are real and observable at the moment they happen - but if nothing is capturing them, there is no record afterward. Detection and forensics become impossible: you cannot investigate an incident whose evidence was never written down.",
    "Adequate observability has three layers that must all be present. API server audit logging records who did what to the control plane. A log aggregation agent (a DaemonSet such as fluent-bit or fluentd) ships container and node logs off the node to durable storage. And a runtime monitor (such as Falco) watches for anomalous in-container behaviour like shells spawned in production pods or writes to sensitive paths.",
    "Because logging costs money and adds moving parts, it is frequently deprioritised or half-implemented - audit logging left off, agents deployed to some clusters but not others, alerts configured but never routed to anyone. Each gap is a place an attacker can operate undetected.",
  ],
  impact: [
    "Undetected compromise: an attacker who reads Secrets, execs into pods, or escalates privileges generates no durable evidence, so the breach can continue for weeks or months.",
    "Impossible forensics: after an incident there is nothing to reconstruct the timeline - you cannot answer what was accessed, by whom, or when.",
    "No alerting: without collected signals there is nothing to alert on, so on-call is never paged for malicious activity.",
    "Compliance failure: frameworks such as SOC 2, PCI-DSS, and HIPAA require audit trails; missing logs are a direct control failure.",
    "Slow, blind recovery: cleanup after a breach cannot be scoped, so responders must assume total compromise and rebuild from scratch.",
  ],
  rootCauses: [
    "API server audit logging is disabled by default and needs an explicit `--audit-policy-file` and log backend to be turned on.",
    "Container logs live only on the node and are lost on pod deletion or log rotation - no aggregation agent is deployed to ship them off.",
    "No runtime security sensor (e.g. Falco) is installed, so in-cluster behaviour is never inspected.",
    "Logs may be collected but never centralised, retained, or alerted on, so nobody ever looks at them.",
    "Observability is treated as a cost centre and cut, or deployed inconsistently across clusters.",
  ],

  attackScenario: {
    summary:
      "An attacker with a foothold operates freely because no audit trail, log pipeline, or runtime sensor ever records their actions.",
    steps: [
      "The attacker obtains a service account token or kubeconfig with modest permissions (e.g. from a leaked CI secret).",
      "They `kubectl exec` into a running application pod to explore - a highly abnormal action that a runtime monitor like Falco would flag immediately, but nothing is watching.",
      "They read the application's Secrets (`kubectl get secret -o yaml`), harvesting database and cloud credentials. The API server could have audited this GET, but audit logging is off.",
      "They exfiltrate data and delete the pod they used. Because no aggregation agent shipped the container logs off the node, the local logs vanish with the pod.",
      "Weeks later the breach surfaces elsewhere. The security team goes to investigate and finds no audit log, no shipped container logs, and no runtime alerts - there is simply no evidence of what happened.",
    ],
  },

  challenge: {
    scenario:
      "You have a low-privilege kubeconfig for NimbusMart's cluster, lifted from a leaked CI secret. Your target is `checkout/payments-api`, which mounts a `payments-webhook` Secret (the Stripe callback signing key). Recon turns up something better than an exploit: the cluster has no API server audit logging, no log-aggregation DaemonSet, and no runtime monitor. Nothing is watching. You can simply take the secret.",
    objective:
      "Silently exfiltrate the `payments-webhook` Secret from the `checkout` namespace. The flag is the secret's `flag` value. Capture it knowing that, on this blind cluster, the read leaves no collected trace anywhere.",
    difficulty: "Easy",
    points: 100,
    flagFormat: "FLAG{...}",
    flagHash: "43d6af47c842cc87e0e60d9f47ad2716572b9db69e6e5845480083df5634e5f7",
    hints: [
      "You do not need an exploit - you need the absence of one. Check what observability exists first: `kubectl -n kube-system get daemonset` shows there is no logging agent.",
      "Read the Secret directly from the API server: `kubectl get secret payments-webhook -n checkout -o jsonpath='{.data.flag}'` returns base64 - pipe it through `base64 -d`.",
      "Prefer exec? The same Secret is mounted at `/etc/payments-webhook` in the `payments-api` pod: `kubectl exec -n checkout payments-api -- cat /etc/payments-webhook/flag`. Either way, nothing records it.",
    ],
  },

  lab: {
    objective:
      "Exfiltrate the checkout/payments-webhook Secret from an unmonitored cluster and confirm the read leaves no trace, then deploy a log-collector DaemonSet (and an audit-policy example) so the same read would now be captured - proving remediation via the checker, not by removing the flag.",
    prerequisites: [
      "A local cluster: `kind create cluster --config labs/kind-cluster.yaml`",
      "kubectl configured to talk to that cluster",
    ],
    vulnerableManifest: "labs/k10-logging-monitoring/vulnerable.yaml",
    fixedManifest: "labs/k10-logging-monitoring/fixed.yaml",
    steps: [
      {
        title: "Deploy the unmonitored payments-api",
        description:
          "Creates the `checkout` namespace, the `payments-webhook` Secret holding the flag, and the `payments-api` pod. Nothing around them collects logs or audits access.",
        command: "kubectl apply -f labs/k10-logging-monitoring/vulnerable.yaml",
        expected:
          "namespace/checkout created / secret/payments-webhook created / pod/payments-api created",
        kind: "setup",
      },
      {
        title: "Confirm the cluster is blind",
        description:
          "Look for any log-collection agent. On the vulnerable setup there is none, so any secret read or exec you perform next is invisible after the fact.",
        command:
          "kubectl -n kube-system get daemonset -l k8s-app=log-collector 2>&1 || echo NO_LOG_COLLECTOR",
        expected: "No resources found / NO_LOG_COLLECTOR - nothing is collecting evidence.",
        kind: "attack",
      },
      {
        title: "Exfiltrate the payments-webhook Secret",
        description:
          "Read the signing key straight from the API server the way an attacker harvesting credentials would. The API server could have audited this GET - but audit logging is off, so there is no record.",
        command:
          "kubectl get secret payments-webhook -n checkout -o jsonpath='{.data.flag}' | base64 -d",
        expected:
          "FLAG{silent_exfil_left_no_audit_trail} - submit this on the Challenge tab. No audit record of the read exists.",
        kind: "attack",
      },
      {
        title: "Or read it via a silent exec",
        description:
          "The same Secret is mounted into the payments-api pod. Exec in and read it - a highly abnormal action a runtime monitor like Falco would flag, but nothing here is watching.",
        command:
          "kubectl exec -n checkout payments-api -- cat /etc/payments-webhook/flag",
        expected:
          "The flag prints. On a monitored cluster this exec would alert; here it leaves no collected trace.",
        kind: "attack",
      },
      {
        title: "Deploy a log-collector and audit policy",
        description:
          "Apply a log-collector DaemonSet in kube-system (container named fluent-bit) that reads the node's /var/log, plus an example API server audit-policy ConfigMap. This is DETECTIVE: it does not remove the flag - it makes future reads visible.",
        command: "kubectl apply -f labs/k10-logging-monitoring/fixed.yaml",
        expected:
          "daemonset.apps/log-collector created / configmap/audit-policy created",
        kind: "fix",
      },
      {
        title: "Verify detection is now in place",
        description:
          "The DaemonSet tails node logs on every node. The flag is still readable - that is expected; the point is the same read would now be captured, and the k10 checker detects the logging agent as proof of remediation.",
        command:
          "kubectl -n kube-system rollout status ds/log-collector && kubectl -n kube-system logs -l k8s-app=log-collector --tail=20",
        expected:
          "The DaemonSet is Ready on all nodes and streams node/container log lines - evidence is now captured. Run `cd checker && go run . --check k10`; a PASS (agent detected) proves remediation.",
        kind: "verify",
      },
    ],
  },

  defense: {
    summary:
      "Turn on all three observability layers: API server audit logging with a real policy, a log-aggregation DaemonSet on every node, and a runtime security monitor that alerts on anomalous behaviour.",
    patches: [
      {
        title: "Enable an API server audit policy",
        description:
          "Configure the API server with an audit policy that records metadata for reads and full request/response bodies for sensitive resources like Secrets. On managed control planes (EKS/GKE/AKS) enable audit logging in the provider console.",
        lang: "yaml",
        code: `apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Full detail on Secret and ConfigMap access.
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets", "configmaps"]
  # Log exec/attach into pods.
  - level: Request
    resources:
      - group: ""
        resources: ["pods/exec", "pods/attach"]
  # Metadata for everything else.
  - level: Metadata`,
      },
      {
        title: "Ship logs off every node with a DaemonSet",
        description:
          "Run a log-aggregation agent as a DaemonSet so every node's container and system logs are collected and forwarded to durable, centralised storage.",
        lang: "yaml",
        code: `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: fluent-bit
  namespace: kube-system
  labels:
    k8s-app: fluent-bit
spec:
  selector:
    matchLabels:
      k8s-app: fluent-bit
  template:
    metadata:
      labels:
        k8s-app: fluent-bit
    spec:
      containers:
        - name: fluent-bit
          image: fluent/fluent-bit:2.2
          volumeMounts:
            - name: varlog
              mountPath: /var/log
              readOnly: true
      volumes:
        - name: varlog
          hostPath:
            path: /var/log`,
      },
      {
        title: "Add runtime threat detection",
        description:
          "Deploy Falco (or a comparable eBPF sensor) to watch syscalls and alert on suspicious runtime behaviour - shells in containers, writes to sensitive paths, unexpected network connections.",
        lang: "yaml",
        code: `# Falco rule: alert when a shell is spawned in a container.
- rule: Terminal shell in container
  desc: A shell was spawned in a container - likely an interactive exec.
  condition: >
    spawned_process and container
    and shell_procs and proc.tty != 0
  output: >
    Shell spawned in container (user=%user.name
    container=%container.name command=%proc.cmdline)
  priority: WARNING`,
      },
    ],
    bestPractices: [
      "Enable API server audit logging with a policy that captures Secret access and pod exec/attach.",
      "Run a log-aggregation agent (fluent-bit, fluentd, vector, promtail) as a DaemonSet on every node.",
      "Forward logs to durable, centralised, tamper-resistant storage with a defined retention period.",
      "Deploy a runtime security monitor such as Falco and route its alerts to on-call.",
      "Scrape metrics with Prometheus/node-exporter and alert on anomalies (spikes in API errors, new privileged pods).",
      "Regularly test that alerts actually fire and reach a human - an unmonitored pipeline is as good as none.",
    ],
  },

  checker: {
    checkId: "k10",
    whatItChecks:
      "Lists DaemonSets and Deployments across all namespaces and matches their names/images against known logging and monitoring agents (fluent-bit, fluentd, filebeat, promtail, vector, falco, prometheus, otel, datadog, node-exporter). Flags the cluster if none are found, and reminds that API server audit logging cannot be introspected via client-go and must be verified separately.",
    passCriteria: [
      "At least one recognised logging/monitoring agent (DaemonSet or Deployment) is running in the cluster.",
      "A log-aggregation agent ships node/container logs off each node.",
      "API server audit logging is enabled (verified out-of-band - not visible to the checker).",
    ],
  },

  references: [
    {
      label: "OWASP K8s Top 10 - K10",
      url: "https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K10-inadequate-logging",
    },
    {
      label: "Kubernetes Auditing",
      url: "https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/",
    },
    {
      label: "Logging Architecture",
      url: "https://kubernetes.io/docs/concepts/cluster-administration/logging/",
    },
    {
      label: "Falco - Runtime Security",
      url: "https://falco.org/docs/",
    },
  ],
};
