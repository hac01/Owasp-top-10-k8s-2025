package checks

import (
	"context"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func init() { Register(k05{}) }

// k05 validates OWASP K05: Missing Network Segmentation Controls.
type k05 struct{}

func (k05) ID() string    { return "k05" }
func (k05) Title() string { return "Missing Network Segmentation Controls" }
func (k05) Description() string {
	return "Flags non-system namespaces that run pods but have no NetworkPolicy (flat, wide-open pod network), and namespaces that lack a default-deny-ingress baseline."
}

func (c k05) Run(ctx context.Context, client kubernetes.Interface, namespace string) Result {
	res := &Result{ID: c.ID(), Title: c.Title()}

	// Discover the namespaces that actually run workloads. Only namespaces that
	// contain at least one pod are worth flagging — an empty namespace has
	// nothing to segment.
	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		res.add("cluster", "unable to list pods: "+err.Error(), SeverityHigh)
		return res.finalize("")
	}

	nsWithPods := map[string]bool{}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		if namespace != "" && pod.Namespace != namespace {
			continue
		}
		nsWithPods[pod.Namespace] = true
	}

	for ns := range nsWithPods {
		policies, err := client.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			res.add(ns, "unable to list network policies: "+err.Error(), SeverityHigh)
			continue
		}

		if len(policies.Items) == 0 {
			res.add(ns, "runs pods but defines no NetworkPolicy — the pod network is flat, so any compromised pod can reach every other pod, service, and the node metadata endpoint", SeverityHigh)
			continue
		}

		if !k05HasDefaultDenyIngress(policies.Items) {
			res.add(ns, "has NetworkPolicies but no default-deny-ingress baseline (a policy with an empty podSelector {} and Ingress in policyTypes) — traffic not matched by an allow policy is still permitted", SeverityMedium)
		}
	}

	return res.finalize("Every non-system namespace with workloads has a NetworkPolicy and a default-deny-ingress baseline.")
}

// k05HasDefaultDenyIngress reports whether the given policies include a
// default-deny-ingress policy: one that selects every pod (empty podSelector)
// and lists Ingress among its policyTypes.
func k05HasDefaultDenyIngress(policies []networkingv1.NetworkPolicy) bool {
	for i := range policies {
		np := &policies[i]
		if !k05SelectsAllPods(np.Spec.PodSelector) {
			continue
		}
		if k05HasIngressPolicyType(np.Spec.PolicyTypes) {
			return true
		}
	}
	return false
}

// k05SelectsAllPods reports whether a podSelector is empty ({}), which matches
// every pod in the namespace.
func k05SelectsAllPods(sel metav1.LabelSelector) bool {
	return len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0
}

// k05HasIngressPolicyType reports whether Ingress appears in policyTypes.
func k05HasIngressPolicyType(types []networkingv1.PolicyType) bool {
	for _, t := range types {
		if t == networkingv1.PolicyTypeIngress {
			return true
		}
	}
	return false
}
