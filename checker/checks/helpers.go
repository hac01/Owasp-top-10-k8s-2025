package checks

import (
	corev1 "k8s.io/api/core/v1"
)

// systemNamespaces are skipped by workload-level checks because their
// components legitimately require elevated privileges.
var systemNamespaces = map[string]bool{
	"kube-system":        true,
	"kube-public":        true,
	"kube-node-lease":    true,
	"local-path-storage": true,
}

func isSystemNamespace(ns string) bool {
	return systemNamespaces[ns]
}

// allContainers returns init + regular + ephemeral containers of a pod.
func allContainers(pod *corev1.Pod) []corev1.Container {
	out := make([]corev1.Container, 0, len(pod.Spec.Containers)+len(pod.Spec.InitContainers))
	out = append(out, pod.Spec.InitContainers...)
	out = append(out, pod.Spec.Containers...)
	for _, ec := range pod.Spec.EphemeralContainers {
		out = append(out, corev1.Container(ec.EphemeralContainerCommon))
	}
	return out
}
