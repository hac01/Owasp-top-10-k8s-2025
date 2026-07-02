# NimbusMart — CTF World Bible

> This document is the single source of truth for the CTF narrative. Every
> challenge (K01–K10) reuses these names, namespaces, and the flag scheme so the
> labs feel like one connected engagement against one company.

## The company

**NimbusMart** is a fast-growing online retailer ("everything, delivered by the
cloud"). Their platform runs on Kubernetes. Growth outpaced security, so the
board hired **you** — an external red team — to assess the cluster. You start
with a foothold in a single web pod and work deeper, capturing a flag at each
stage that proves the impact of a specific OWASP Kubernetes Top 10 weakness.

## Namespaces (domains)

| Namespace        | What lives there                                   |
|------------------|----------------------------------------------------|
| `storefront`     | Customer-facing: `web-frontend`, `catalog-api`, `recommendations` |
| `checkout`       | Money path: `payments-api`, `cart-api`             |
| `data`           | Datastores: `orders-db`, `inventory-db`, `inventory-sync` |
| `platform`       | Internal tooling: `ci-runner`, `admin-portal`, `debug-shell` |
| `nimbusmart-ops` | Ops vault: master secrets (high-value target)      |

Each challenge creates only the namespaces/resources it needs, so any single
challenge can be deployed and solved on its own. Reset between challenges with
`make clean-labs`.

## Challenge ↔ service ↔ weakness map  (OWASP Kubernetes Top 10 — **2025**)

| Risk | Title | Service (foothold → target)                | Weakness exploited                          | Difficulty | Points |
|------|-------|--------------------------------------------|---------------------------------------------|-----------|--------|
| K01  | Insecure Workload Configurations              | `data/inventory-sync`                       | privileged + hostPath → node breakout       | Medium | 200 |
| K02  | Overly Permissive Authorization Configurations| `storefront/catalog-api`                    | wildcard RBAC/authz reads any secret        | Hard   | 300 |
| K03  | Secrets Management Failures                   | `checkout/payments-api`                     | hardcoded Stripe key in env                 | Easy   | 100 |
| K04  | Lack of Cluster-Level Policy Enforcement      | `platform` (rogue `debug-shell`)            | no admission control admits a privileged pod| Medium | 200 |
| K05  | Missing Network Segmentation Controls         | `storefront/web-frontend` → `data/orders-db`| flat network, no NetworkPolicy              | Medium | 200 |
| K06  | Overly Exposed Kubernetes Components          | `platform/admin-portal`                     | internal dashboard published via NodePort   | Medium | 200 |
| K07  | Misconfigured and Vulnerable Cluster Components| `platform/debug-shell`                     | default SA token + no quotas + stale versions| Medium| 200 |
| K08  | Cluster-to-Cloud Lateral Movement             | `platform/data-exporter` → `imds`           | pod reaches node IMDS, steals cloud creds   | Hard   | 300 |
| K09  | Broken Authentication Mechanisms              | `storefront/web-frontend`                   | over-mounted default token + anon API access| Medium | 200 |
| K10  | Inadequate Logging and Monitoring             | `checkout/payments-api`                     | no audit/logging → silent secret exfil      | Easy   | 100 |
| ★    | Supply Chain Vulnerabilities *(bonus)*        | `storefront/recommendations`                | untrusted mutable `:latest` image           | Hard   | 300 |

Main list total: **2000 points** across 10 challenges (+300 bonus).

> Updated to the **2025** OWASP Kubernetes Top 10. Changes from 2022: authorization
> (was RBAC) broadened; secrets, network, authn, logging reordered; **Overly Exposed
> Components** and **Cluster-to-Cloud Lateral Movement** added; Misconfigured +
> Outdated merged into K07; Supply Chain moved to a bonus challenge.

## Flag scheme

- Format is always `FLAG{...}` (lowercase, underscores).
- The flag must be **capturable only by performing the exploit** — never printed
  in the fixed manifest, and where possible not sitting in the vulnerable pod's
  own spec (e.g. K01's flag is seeded onto the *node*, K07's is served by a
  *different* pod over the network, K03's lives in a secret in *another*
  namespace).
- The web app stores only the **SHA-256 hash** of each flag (in `flagHash`) so
  the literal answer is not shipped in the browser bundle. Compute a hash with:
  `printf '%s' 'FLAG{...}' | shasum -a 256`

### Canonical flags (plant these exact strings) — 2025 numbering

| Risk | Flag |
|------|------|
| K01 | `FLAG{nimbusmart_hostpath_broke_out_to_the_node}` |
| K02 | `FLAG{wildcard_rbac_opens_the_ops_vault}` |
| K03 | `FLAG{hardcoded_stripe_key_sk_live_nimbus}` |
| K04 | `FLAG{no_admission_control_admits_anything}` |
| K05 | `FLAG{flat_network_reached_the_orders_db}` |
| K06 | `FLAG{nodeport_exposed_the_kube_dashboard}` |
| K07 | `FLAG{misconfigured_stale_cluster_component}` |
| K08 | `FLAG{pod_stole_node_cloud_credentials}` |
| K09 | `FLAG{default_token_talked_to_the_apiserver}` |
| K10 | `FLAG{silent_exfil_left_no_audit_trail}` |
| ★ (bonus) | `FLAG{poisoned_latest_tag_shipped_to_prod}` |
