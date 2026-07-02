# K10 — Inadequate Logging and Monitoring · NimbusMart CTF

**Difficulty:** Easy · **100 pts** · **Flag:** `FLAG{...}`

## Briefing
NimbusMart's `checkout/payments-api` holds a `payments-webhook` Secret — the
signing key for Stripe callbacks. The cluster ships with NO audit logging, NO
log-aggregation agent, and NO runtime monitor. That means you can read the
secret and even exec into the pod and **nothing will ever record it**.

**Objective:** exfiltrate the `payments-webhook` secret value silently. There is
no trace to cover up, because there is no trace at all.

## Capture the flag
```bash
kubectl apply -f vulnerable.yaml

# Read the secret straight from the API server — no audit log captures this GET.
kubectl get secret payments-webhook -n checkout -o jsonpath='{.data.flag}' | base64 -d
#  -> FLAG{silent_exfil_left_no_audit_trail}

# Or exec into the pod and read the mounted copy — Falco would scream, but
# nothing is watching, so this leaves no collected trace either.
kubectl exec -n checkout payments-api -- cat /etc/payments-webhook/flag

# Confirm the cluster is blind: no log collector exists.
kubectl -n kube-system get daemonset -l k8s-app=log-collector 2>&1 || echo NO_LOG_COLLECTOR
```

## Patch & verify
Logging is a **detective** control, not a preventive one. Deploying it does
**not** remove the flag — the secret stays readable. What changes is that the
same read now leaves an audit trail. Remediation is proven by the checker
detecting a logging agent, **not** by the flag disappearing.

```bash
kubectl apply -f fixed.yaml

# A log-collector DaemonSet (container named fluent-bit) now tails /var/log on
# every node, and an example audit-policy ConfigMap documents what the API
# server should record (Secret GETs, pod exec/attach).
kubectl -n kube-system rollout status ds/log-collector
kubectl -n kube-system logs -l k8s-app=log-collector --tail=20

# The flag is STILL readable — but now the read would be captured:
kubectl get secret payments-webhook -n checkout -o jsonpath='{.data.flag}' | base64 -d

# Prove remediation with the checker (PASS = a logging agent is detected).
cd ../../checker && go run . --check k10
```

## Before / After
- **Before:** The secret read and pod exec are real events, but nothing captures
  them. There is no audit log, no shipped container logs, and no runtime alert —
  the exfiltration is invisible after the fact.
- **After:** A DaemonSet tails `/var/log` on every node and ships the lines off
  the node (a real pipeline forwards them to durable, centralised storage), and
  the `audit-policy` ConfigMap documents the API server policy that records
  Secret access and pod exec/attach. The flag is unchanged; the difference is
  that reading it now leaves a trace.

> Note: the DaemonSet uses busybox to tail node logs so the lab is applyable on
> any cluster. In production, run `fluent/fluent-bit` (or fluentd, vector,
> promtail) with the same hostPath `/var/log` mount, and add a runtime monitor
> such as Falco to alert on shells-in-containers and sensitive file access.

## Cleanup
```bash
kubectl delete -f fixed.yaml --ignore-not-found
kubectl delete -f vulnerable.yaml --ignore-not-found
```
