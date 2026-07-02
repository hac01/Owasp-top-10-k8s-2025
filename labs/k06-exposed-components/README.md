# K06 — Overly Exposed Kubernetes Components · NimbusMart CTF

**Difficulty:** Medium · **200 pts** · **Flag:** `FLAG{...}`

## Briefing
NimbusMart runs an internal ops dashboard, `platform/admin-portal`, that was
only ever meant to be reachable from inside the cluster. To "check it from a
laptop", someone switched its Service to `type: NodePort` on nodePort `30080`.
On this kind cluster that node port is forwarded straight to the host — so the
internal dashboard is now published to the outside world with no authentication.

**Objective:** reach the exposed internal component from *outside* the cluster
and read what it serves.

## Capture the flag
```bash
# Deploy the exposed dashboard
kubectl apply -f vulnerable.yaml

# Confirm the internal component is published externally (NodePort)
kubectl get svc -n platform admin-portal
#  -> TYPE: NodePort   PORT(S): 80:30080/TCP

# Hit it from the HOST — no auth, no cluster boundary in the way
curl -s http://localhost:30080
#  -> FLAG{nodeport_exposed_the_kube_dashboard}
```

## Patch & verify
```bash
kubectl delete -f vulnerable.yaml
kubectl apply -f fixed.yaml

# The dashboard is ClusterIP again — no longer published to the host
kubectl get svc -n platform admin-portal
#  -> TYPE: ClusterIP
curl -s --max-time 5 http://localhost:30080 || echo NOT_EXPOSED

# Prove it with the checker
cd ../../checker && go run . --check k06 -n platform
```

## Cleanup
```bash
kubectl delete -f vulnerable.yaml -f fixed.yaml --ignore-not-found
```
