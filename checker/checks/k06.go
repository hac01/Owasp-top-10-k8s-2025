package checks

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func init() { Register(k06{}) }

// k06 validates OWASP K06: Overly Exposed Kubernetes Components.
type k06 struct{}

func (k06) ID() string    { return "k06" }
func (k06) Title() string { return "Overly Exposed Kubernetes Components" }
func (k06) Description() string {
	return "Flags internal components published outside the cluster via NodePort or LoadBalancer Services in non-system namespaces."
}

func (c k06) Run(ctx context.Context, client kubernetes.Interface, namespace string) Result {
	res := &Result{ID: c.ID(), Title: c.Title()}

	svcs, err := client.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		res.add("cluster", "unable to list services: "+err.Error(), SeverityHigh)
		return res.finalize("")
	}

	for i := range svcs.Items {
		svc := &svcs.Items[i]
		// Skip system namespaces — their components (e.g. kube-dns) are managed
		// by the platform and may be published intentionally.
		if isSystemNamespace(svc.Namespace) {
			continue
		}
		ref := fmt.Sprintf("%s/%s", svc.Namespace, svc.Name)

		switch svc.Spec.Type {
		case corev1.ServiceTypeNodePort:
			res.add(ref, fmt.Sprintf("is published outside the cluster via a NodePort Service (%s) — an internal component is reachable from the node/host with no cluster boundary in front of it", k06nodePorts(svc)), SeverityHigh)
		case corev1.ServiceTypeLoadBalancer:
			res.add(ref, "is published outside the cluster via a LoadBalancer Service — an internal component is exposed to external networks", SeverityHigh)
		}
	}

	return res.finalize("No internal components are published externally (only ClusterIP/headless Services found).")
}

// k06nodePorts renders the allocated nodePort(s) for a NodePort Service so the
// finding points at the exact externally-reachable port(s).
func k06nodePorts(svc *corev1.Service) string {
	msg := "nodePort"
	for _, p := range svc.Spec.Ports {
		if p.NodePort == 0 {
			continue
		}
		if msg == "nodePort" {
			msg = fmt.Sprintf("nodePort %d", p.NodePort)
			continue
		}
		msg = fmt.Sprintf("%s, %d", msg, p.NodePort)
	}
	return msg
}
