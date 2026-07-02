package checks

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func init() { Register(k01{}) }

// k01 validates OWASP K01: Insecure Workload Configurations.
type k01 struct{}

func (k01) ID() string    { return "k01" }
func (k01) Title() string { return "Insecure Workload Configurations" }
func (k01) Description() string {
	return "Flags privileged/root containers, privilege escalation, hostPath mounts, host namespaces, and missing capability drops."
}

func (c k01) Run(ctx context.Context, client kubernetes.Interface, namespace string) Result {
	res := &Result{ID: c.ID(), Title: c.Title()}

	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		res.add("cluster", "unable to list pods: "+err.Error(), SeverityHigh)
		return res.finalize("")
	}

	for i := range pods.Items {
		pod := &pods.Items[i]
		// Skip system namespaces — they legitimately need elevated access.
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		ref := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)

		// Pod-level: host namespace sharing and hostPath volumes.
		if pod.Spec.HostPID {
			res.add(ref, "shares the host PID namespace (hostPID: true)", SeverityHigh)
		}
		if pod.Spec.HostIPC {
			res.add(ref, "shares the host IPC namespace (hostIPC: true)", SeverityHigh)
		}
		if pod.Spec.HostNetwork {
			res.add(ref, "shares the host network namespace (hostNetwork: true)", SeverityHigh)
		}
		for _, v := range pod.Spec.Volumes {
			if v.HostPath != nil {
				res.add(ref, fmt.Sprintf("mounts hostPath %q (node filesystem exposure)", v.HostPath.Path), SeverityCritical)
			}
		}

		for _, ctr := range allContainers(pod) {
			cref := fmt.Sprintf("%s (container %s)", ref, ctr.Name)
			evaluateContainerSecurity(res, cref, pod.Spec.SecurityContext, ctr.SecurityContext)
		}
	}

	return res.finalize("All workloads run with least-privilege security contexts.")
}

// evaluateContainerSecurity applies the K01 rules to one container, taking the
// pod-level securityContext into account for runAsNonRoot/runAsUser inheritance.
func evaluateContainerSecurity(res *Result, ref string, pod *corev1.PodSecurityContext, sc *corev1.SecurityContext) {
	if sc != nil && sc.Privileged != nil && *sc.Privileged {
		res.add(ref, "runs privileged (privileged: true)", SeverityCritical)
	}
	// allowPrivilegeEscalation defaults to true when unset.
	if sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
		res.add(ref, "allows privilege escalation (set allowPrivilegeEscalation: false)", SeverityHigh)
	}
	if !runsAsNonRoot(pod, sc) {
		res.add(ref, "may run as root (set runAsNonRoot: true or runAsUser > 0)", SeverityHigh)
	}
	if !dropsAllCapabilities(sc) {
		res.add(ref, "does not drop ALL capabilities", SeverityMedium)
	}
	if sc == nil || sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
		res.add(ref, "has a writable root filesystem (set readOnlyRootFilesystem: true)", SeverityMedium)
	}
}

func runsAsNonRoot(pod *corev1.PodSecurityContext, sc *corev1.SecurityContext) bool {
	if sc != nil {
		if sc.RunAsNonRoot != nil && *sc.RunAsNonRoot {
			return true
		}
		if sc.RunAsUser != nil && *sc.RunAsUser > 0 {
			return true
		}
		if sc.RunAsUser != nil && *sc.RunAsUser == 0 {
			return false
		}
	}
	if pod != nil {
		if pod.RunAsNonRoot != nil && *pod.RunAsNonRoot {
			return true
		}
		if pod.RunAsUser != nil && *pod.RunAsUser > 0 {
			return true
		}
	}
	return false
}

func dropsAllCapabilities(sc *corev1.SecurityContext) bool {
	if sc == nil || sc.Capabilities == nil {
		return false
	}
	for _, c := range sc.Capabilities.Drop {
		if c == "ALL" || c == "all" {
			return true
		}
	}
	return false
}
