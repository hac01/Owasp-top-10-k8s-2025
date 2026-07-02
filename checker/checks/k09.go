package checks

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func init() { Register(k09{}) }

// k09 validates OWASP K09: Broken Authentication Mechanisms.
type k09 struct{}

func (k09) ID() string    { return "k09" }
func (k09) Title() string { return "Broken Authentication Mechanisms" }
func (k09) Description() string {
	return "Flags pods that auto-mount the default service account token unnecessarily and RBAC bindings that grant anonymous/unauthenticated identities access."
}

func (c k09) Run(ctx context.Context, client kubernetes.Interface, namespace string) Result {
	res := &Result{ID: c.ID(), Title: c.Title()}

	// (a) Pods that auto-mount a service account token they likely do not need.
	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		res.add("cluster", "unable to list pods: "+err.Error(), SeverityHigh)
		return res.finalize("")
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		// Skip system namespaces — their components legitimately need tokens.
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		ref := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)

		if k09tokenAutoMounted(pod) {
			if k09usesDefaultServiceAccount(pod) {
				res.add(ref, "auto-mounts an API token for the \"default\" service account (set automountServiceAccountToken: false, or use a dedicated service account that opts in only where needed)", SeverityHigh)
			} else {
				res.add(ref, "auto-mounts a service account token (set automountServiceAccountToken: false unless the workload calls the API server)", SeverityMedium)
			}
		}
	}

	// (b) RBAC bindings that grant anonymous / unauthenticated identities access.
	crbs, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		res.add("cluster", "unable to list clusterrolebindings: "+err.Error(), SeverityHigh)
		return res.finalize("")
	}
	for i := range crbs.Items {
		crb := &crbs.Items[i]
		// system:public-info-viewer is a built-in binding that intentionally
		// exposes only non-sensitive endpoints (/healthz, /version, /livez,
		// /readyz) to unauthenticated clients — it is safe by design, so skip it.
		if crb.Name == "system:public-info-viewer" {
			continue
		}
		ref := fmt.Sprintf("ClusterRoleBinding %s", crb.Name)
		for _, s := range crb.Subjects {
			if msg, anon := k09anonymousSubject(s); anon {
				res.add(ref, "grants API access to "+msg+" (anonymous auth) — remove the binding and disable anonymous access", SeverityHigh)
			}
		}
	}

	rbs, err := client.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		res.add("cluster", "unable to list rolebindings: "+err.Error(), SeverityHigh)
		return res.finalize("")
	}
	for i := range rbs.Items {
		rb := &rbs.Items[i]
		if isSystemNamespace(rb.Namespace) {
			continue
		}
		ref := fmt.Sprintf("RoleBinding %s/%s", rb.Namespace, rb.Name)
		for _, s := range rb.Subjects {
			if msg, anon := k09anonymousSubject(s); anon {
				res.add(ref, "grants API access to "+msg+" (anonymous auth) — remove the binding and disable anonymous access", SeverityHigh)
			}
		}
	}

	return res.finalize("No unnecessary token auto-mounting or anonymous bindings found.")
}

// k09tokenAutoMounted reports whether the pod receives a service account token.
// The token is mounted when automount is nil (default true) or explicitly true.
func k09tokenAutoMounted(pod *corev1.Pod) bool {
	return pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken
}

// k09usesDefaultServiceAccount reports whether the pod runs as the "default"
// service account (either explicitly or by omission).
func k09usesDefaultServiceAccount(pod *corev1.Pod) bool {
	sa := pod.Spec.ServiceAccountName
	return sa == "" || sa == "default"
}

// k09anonymousSubject returns a description and true when a binding subject is
// the anonymous user or the unauthenticated user/group.
func k09anonymousSubject(s rbacv1.Subject) (string, bool) {
	switch s.Kind {
	case "User":
		switch s.Name {
		case "system:anonymous", "system:unauthenticated":
			return fmt.Sprintf("the %q user", s.Name), true
		}
	case "Group":
		switch s.Name {
		case "system:unauthenticated", "system:anonymous":
			return fmt.Sprintf("the %q group", s.Name), true
		}
	}
	return "", false
}
