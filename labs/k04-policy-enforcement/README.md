# K04 — Lack of Cluster-Level Policy Enforcement · NimbusMart CTF

**Difficulty:** Medium · **200 pts** · **Flag:** `FLAG{...}`

## Briefing
NimbusMart's `platform` namespace (home to `ci-runner`, `admin-portal`, and
your foothold) was spun up in a hurry with **no Pod Security Admission labels**.
Nothing inspects what gets scheduled there. You can create pods — so drop a
rogue `debug-shell` that no sane policy would ever allow and let the cluster
admit it for you.

**Objective:** deploy a blatantly non-compliant `debug-shell` pod, prove it was
admitted, and read the flag it prints.

## Capture the flag
```bash
# Create the unguarded namespace + admit a wildly non-compliant rogue pod
kubectl apply -f vulnerable.yaml

# Nothing rejected it. With centralized enforcement this pod would never exist.
kubectl get pod debug-shell -n platform

# The flag is only printed because the pod was actually ADMITTED and ran
kubectl logs -n platform debug-shell
#  -> FLAG{no_admission_control_admits_anything}
# (equivalently: kubectl exec -n platform debug-shell -- cat /root/flag.txt)
```

## Patch & verify
```bash
# Turn on centralized enforcement: label the namespace for built-in Pod
# Security Admission (restricted) and ship a compliant replacement workload.
kubectl delete -f vulnerable.yaml --ignore-not-found
kubectl apply -f fixed.yaml

# Prove the guardrail works: re-applying the rogue pod is now DENIED at
# admission time by the built-in PodSecurity controller — the flag is
# unreachable because the pod never runs.
kubectl apply -f vulnerable.yaml
#  -> Error from server (Forbidden): error when creating "vulnerable.yaml":
#     pods "debug-shell" is forbidden: violates PodSecurity "restricted:latest":
#     privileged (container "shell" must not set securityContext.privileged=true),
#     host namespaces (hostPID=true), allowPrivilegeEscalation != false, ...

# The compliant replacement still runs fine under the same policy
kubectl get pod platform-tools -n platform

# Prove it with the checker (platform now has an enforce label -> PASS)
cd ../../checker && go run . --check k04 -n platform
```

## Cleanup
```bash
kubectl delete -f fixed.yaml --ignore-not-found
kubectl delete pod debug-shell -n platform --ignore-not-found
```
