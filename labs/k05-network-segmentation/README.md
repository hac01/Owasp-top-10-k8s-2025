# K05 — Missing Network Segmentation Controls · NimbusMart CTF

**Difficulty:** Medium · **200 pts** · **Flag:** `FLAG{...}`

## Briefing
You've compromised NimbusMart's internet-facing `storefront/web-frontend` pod.
The cluster has NO NetworkPolicy anywhere, so the pod network is flat: every pod
can reach every other pod and service, across namespaces. That means your
low-value frontend can talk straight to `data/orders-db` — a datastore in a
different namespace that should only ever be reached by the order-processing
clients.

**Objective:** from `web-frontend`, reach across to `orders-db` and read the
flag it serves.

## Capture the flag
```bash
# Deploy the flat, unsegmented world (storefront/web-frontend + data/orders-db)
kubectl apply -f vulnerable.yaml

# Nothing is stopping cross-namespace traffic — confirm no policies exist
kubectl get networkpolicies -A

# Pivot from the frontend straight to the orders DB in another namespace
kubectl exec -n storefront web-frontend -- \
  curl -s http://orders-db.data.svc.cluster.local:5678
#  -> FLAG{flat_network_reached_the_orders_db}
```

## Patch & verify
```bash
# Segment the network: default-deny-ingress in data + a targeted allow,
# plus a default-deny baseline in storefront.
kubectl apply -f fixed.yaml

# Prove the policy objects are in place
kubectl get networkpolicies -A

# Re-run the pivot.
kubectl exec -n storefront web-frontend -- \
  curl -s --max-time 5 http://orders-db.data.svc.cluster.local:5678 \
  || echo BLOCKED_BY_NETWORKPOLICY
```

> **CNI caveat — read this.** NetworkPolicy objects are enforced by the CNI
> plugin, not by the API server. A stock `kind` cluster uses **kindnet, which
> does NOT enforce NetworkPolicy** — so the curl above may STILL return the flag
> even after applying `fixed.yaml`. That does not mean the fix is wrong: the
> real remediation signal is that the correct policy objects now EXIST, which is
> exactly what the k05 checker validates. To watch traffic actually drop,
> install a policy-capable CNI such as Calico:
>
> ```bash
> kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/calico.yaml
> ```
>
> On an enforcing CNI, `web-frontend` (not labelled `app=orders-client`) is
> denied and the command prints `BLOCKED_BY_NETWORKPOLICY`.

## Validate with the checker
```bash
cd ../../checker && go run . --check k05
```
The checker passes once every non-system namespace that runs pods has a
NetworkPolicy with a default-deny-ingress baseline.

## Clean up
```bash
kubectl delete -f fixed.yaml --ignore-not-found
# or, if you never applied the fix:
kubectl delete -f vulnerable.yaml --ignore-not-found
```
