package checks

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func init() { Register(k07{}) }

// k07MinSupportedMinor is the oldest v1.x minor version considered supported.
// Anything below this is treated as end-of-life (EOL) and flagged. This floor
// MUST be bumped over time as older Kubernetes releases fall out of support —
// see https://kubernetes.io/releases/patch-releases/#support-period.
const k07MinSupportedMinor = 28

// k07 validates OWASP K07 (2025): Misconfigured and Vulnerable Cluster
// Components. It merges two reproducible, cluster-relevant concerns:
//
//	(a) Misconfiguration — for each non-system namespace, the `default`
//	    ServiceAccount auto-mounting API tokens into every pod, and namespaces
//	    that have neither a ResourceQuota nor a LimitRange (resource-exhaustion
//	    / DoS exposure).
//	(b) Outdated / vulnerable components — an end-of-life API server version and
//	    any node whose kubelet is below the minimum supported minor.
//
// Control-plane/kubelet/etcd flags (anonymous auth, authorization mode, insecure
// ports, unauthenticated etcd) and container-image currency are validated by
// CIS/kube-bench and Trivy respectively and are not editable at runtime in kind,
// so they are covered as narrative in the lab README rather than by this check.
type k07 struct{}

func (k07) ID() string    { return "k07" }
func (k07) Title() string { return "Misconfigured and Vulnerable Cluster Components" }
func (k07) Description() string {
	return fmt.Sprintf("Flags namespaces whose default ServiceAccount auto-mounts API tokens and namespaces lacking both a ResourceQuota and a LimitRange, plus an end-of-life control plane and any node whose kubelet is below the minimum supported minor (v1.%d).", k07MinSupportedMinor)
}

func (c k07) Run(ctx context.Context, client kubernetes.Interface, namespace string) Result {
	res := &Result{ID: c.ID(), Title: c.Title()}

	// (a) Misconfiguration: namespace-scoped default-SA token mounting and
	// missing resource guardrails.
	opts := metav1.ListOptions{}
	if namespace != "" {
		// Scope to the single requested namespace.
		opts.FieldSelector = "metadata.name=" + namespace
	}

	nsList, err := client.CoreV1().Namespaces().List(ctx, opts)
	if err != nil {
		res.add("cluster", "unable to list namespaces: "+err.Error(), SeverityHigh)
		return res.finalize("")
	}

	for i := range nsList.Items {
		ns := &nsList.Items[i]
		// System namespaces are managed by the control plane and are exempt.
		if isSystemNamespace(ns.Name) {
			continue
		}

		k07checkDefaultServiceAccount(ctx, client, res, ns.Name)
		k07checkResourceGuardrails(ctx, client, res, ns.Name)
	}

	// (b) Outdated / vulnerable components: control-plane and kubelet versions.
	k07checkComponentVersions(ctx, client, res)

	return res.finalize(fmt.Sprintf("Every non-system namespace disables default-SA token mounting and defines resource guardrails, and the control plane and all kubelets are at or above the supported floor (v1.%d).", k07MinSupportedMinor))
}

// k07checkDefaultServiceAccount flags a namespace whose `default` ServiceAccount
// mounts API tokens into pods (automountServiceAccountToken nil or true).
func k07checkDefaultServiceAccount(ctx context.Context, client kubernetes.Interface, res *Result, ns string) {
	sa, err := client.CoreV1().ServiceAccounts(ns).Get(ctx, "default", metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			// No default SA yet (e.g. brand-new namespace) — nothing to flag.
			return
		}
		res.add(ns, "unable to get default ServiceAccount: "+err.Error(), SeverityHigh)
		return
	}

	if sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
		res.add(ns, "default ServiceAccount auto-mounts API tokens into pods (set automountServiceAccountToken: false so pods do not receive a cluster credential unless they opt in)", SeverityMedium)
	}
}

// k07checkResourceGuardrails flags a namespace that has neither a ResourceQuota
// nor a LimitRange, so a single workload can exhaust node CPU/memory.
func k07checkResourceGuardrails(ctx context.Context, client kubernetes.Interface, res *Result, ns string) {
	quotas, err := client.CoreV1().ResourceQuotas(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		res.add(ns, "unable to list resource quotas: "+err.Error(), SeverityHigh)
		return
	}
	limits, err := client.CoreV1().LimitRanges(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		res.add(ns, "unable to list limit ranges: "+err.Error(), SeverityHigh)
		return
	}

	if len(quotas.Items) == 0 && len(limits.Items) == 0 {
		res.add(ns, fmt.Sprintf("has no ResourceQuota and no LimitRange — a single workload can consume all node CPU/memory (add at least one to bound consumption; found %d quota(s), %d limit range(s))", len(quotas.Items), len(limits.Items)), SeverityMedium)
	}
}

// k07checkComponentVersions flags an EOL API server version and any node whose
// kubelet is below the supported floor.
func k07checkComponentVersions(ctx context.Context, client kubernetes.Interface, res *Result) {
	// Control plane: check the API server version.
	ver, err := client.Discovery().ServerVersion()
	if err != nil {
		res.add("cluster", "unable to query the server version: "+err.Error(), SeverityHigh)
	} else {
		minor, ok := k07parseMinor(ver.Major, ver.Minor)
		if !ok {
			res.add("cluster", fmt.Sprintf("unable to parse the server version %q — verify it manually with `kubectl version`", ver.GitVersion), SeverityMedium)
		} else if minor < k07MinSupportedMinor {
			res.add("apiserver",
				fmt.Sprintf("control plane runs %s (v1.%d) which is below the supported floor v1.%d — this release is end-of-life and no longer receives security patches; upgrade the cluster", ver.GitVersion, minor, k07MinSupportedMinor),
				SeverityHigh)
		}
	}

	// Nodes: check each kubelet version.
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		res.add("cluster", "unable to list nodes: "+err.Error(), SeverityHigh)
		return
	}
	for i := range nodes.Items {
		node := &nodes.Items[i]
		kubelet := node.Status.NodeInfo.KubeletVersion
		minor, ok := k07parseVersionMinor(kubelet)
		if !ok {
			res.add("node/"+node.Name, fmt.Sprintf("unable to parse kubelet version %q — verify it manually with `kubectl get nodes`", kubelet), SeverityMedium)
			continue
		}
		if minor < k07MinSupportedMinor {
			res.add("node/"+node.Name,
				fmt.Sprintf("kubelet %s (v1.%d) is below the supported floor v1.%d — the node is running an EOL, unpatched kubelet; drain and upgrade it", kubelet, minor, k07MinSupportedMinor),
				SeverityHigh)
		}
	}
}

// k07parseMinor parses the minor number from the Major/Minor fields returned by
// the discovery API. Minor often carries a "+" suffix on managed clusters
// (e.g. "28+"), which is stripped before parsing.
func k07parseMinor(major, minor string) (int, bool) {
	// We only support the v1.x line; a non-"1" major is unexpected.
	if strings.TrimSpace(major) != "" && strings.TrimSpace(major) != "1" {
		return 0, false
	}
	return k07atoiClean(minor)
}

// k07parseVersionMinor extracts the minor number from a full version string such
// as "v1.27.3", "v1.30.0+k3s1", or "1.29.4-eks-1234". It strips a leading "v",
// splits on ".", and ignores any "+"/"-" build suffix on each component.
func k07parseVersionMinor(v string) (int, bool) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if v == "" {
		return 0, false
	}
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return 0, false
	}
	return k07atoiClean(parts[1])
}

// k07atoiClean parses a version component into an int, tolerating "+"/"-"
// build-metadata suffixes (e.g. "28+" -> 28, "29-eks" -> 29).
func k07atoiClean(s string) (int, bool) {
	s = strings.TrimSpace(s)
	// Cut at the first non-digit so suffixes like "+", "-eks", "rc.1" are dropped.
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(s[:end])
	if err != nil {
		return 0, false
	}
	return n, true
}
