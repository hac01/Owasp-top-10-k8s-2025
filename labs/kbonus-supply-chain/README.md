# BONUS — Supply Chain Vulnerabilities · NimbusMart CTF

**Difficulty:** Hard · **300 pts** · **Flag:** `FLAG{...}`

## Briefing
NimbusMart's `storefront/recommendations` service is shipped from a mutable,
unverified image reference — `busybox:latest`, no digest, `imagePullPolicy:
Always`. An attacker who controls the upstream tag pushed a **poisoned build**
to `:latest`. Nothing in the manifest changed, so no review or alert fired, and
every new pod now runs the attacker's code. The payload dropped a backdoor file
inside the container.

**Objective:** capture the poisoned payload — the backdoor the untrusted image
planted at `/tmp/.backdoor`.

## Capture the flag
```bash
# Deploy the poisoned recommendations service (creates the storefront namespace)
kubectl apply -f vulnerable.yaml
kubectl rollout status -n storefront deploy/recommendations

# The reference is mutable and unprovable — no version, no digest
kubectl get deploy -n storefront recommendations \
  -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'
#  -> busybox:latest

# The poisoned build beacons in its logs...
kubectl logs -n storefront deploy/recommendations

# ...and dropped a backdoor. Read the payload that shipped inside the image:
kubectl exec -n storefront deploy/recommendations -- cat /tmp/.backdoor
#  -> FLAG{poisoned_latest_tag_shipped_to_prod}
```

## Patch & verify
```bash
kubectl delete -f vulnerable.yaml
kubectl apply -f fixed.yaml
kubectl rollout status -n storefront deploy/recommendations

# The image is now pinned by immutable @sha256 digest
kubectl get deploy -n storefront recommendations \
  -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'
#  -> busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662

# The clean build carries no backdoor — the flag is gone
kubectl exec -n storefront deploy/recommendations -- sh -c \
  'cat /tmp/.backdoor 2>&1 || echo NO_BACKDOOR'
#  -> NO_BACKDOOR

# Prove it with the checker
cd ../../checker && go run . --check kbonus -n storefront
```

## Cleanup
```bash
kubectl delete -f vulnerable.yaml -f fixed.yaml --ignore-not-found
```
