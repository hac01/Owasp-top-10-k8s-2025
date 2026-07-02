package checks

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func init() { Register(k04{}) }

// k04 validates OWASP K04: Lack of Cluster-Level Policy Enforcement.
type k04 struct{}

func (k04) ID() string    { return "k04" }
func (k04) Title() string { return "Lack of Cluster-Level Policy Enforcement" }
func (k04) Description() string {
	return "Flags namespaces with no Pod Security Admission enforce label (or a weak 'privileged' value), so insecure workloads are admitted freely."
}

const k04EnforceLabel = "pod-security.kubernetes.io/enforce"

func (c k04) Run(ctx context.Context, client kubernetes.Interface, namespace string) Result {
	res := &Result{ID: c.ID(), Title: c.Title()}

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

		enforce, ok := ns.Labels[k04EnforceLabel]
		switch {
		case !ok:
			res.add(ns.Name, fmt.Sprintf("has no %q label — Pod Security Admission is not enforced, so non-compliant pods are admitted freely (set it to 'restricted' or 'baseline')", k04EnforceLabel), SeverityMedium)
		case k04IsWeakEnforceLevel(enforce):
			res.add(ns.Name, fmt.Sprintf("enforces the weak %q=%q profile — this admits privileged workloads (use 'restricted' or 'baseline' instead)", k04EnforceLabel, enforce), SeverityMedium)
		}
	}

	return res.finalize("Every non-system namespace enforces a Pod Security Standard (baseline or restricted).")
}

// k04IsWeakEnforceLevel reports whether a Pod Security Admission enforce level
// provides no meaningful protection.
func k04IsWeakEnforceLevel(level string) bool {
	return level == "privileged"
}
