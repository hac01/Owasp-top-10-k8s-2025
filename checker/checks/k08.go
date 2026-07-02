package checks

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func init() { Register(k08{}) }

// k08 validates OWASP K08 (2025): Cluster-to-Cloud Lateral Movement.
type k08 struct{}

func (k08) ID() string    { return "k08" }
func (k08) Title() string { return "Cluster-to-Cloud Lateral Movement" }
func (k08) Description() string {
	return "Flags workloads that can pivot into the cloud account: pods on the node network (hostNetwork) that can reach the instance metadata service, and containers carrying over-broad cloud credentials in their environment."
}

// k08CloudCredentialEnvNames are environment variable NAMES whose presence means
// long-lived, over-broad cloud credentials are being injected into a pod instead
// of using a scoped, short-lived identity (IRSA / Workload Identity).
var k08CloudCredentialEnvNames = map[string]bool{
	"AWS_ACCESS_KEY_ID":              true,
	"AWS_SECRET_ACCESS_KEY":          true,
	"AWS_SESSION_TOKEN":              true,
	"GOOGLE_APPLICATION_CREDENTIALS": true,
	"AZURE_CLIENT_SECRET":            true,
}

func (c k08) Run(ctx context.Context, client kubernetes.Interface, namespace string) Result {
	res := &Result{ID: c.ID(), Title: c.Title()}

	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		res.add("cluster", "unable to list pods: "+err.Error(), SeverityHigh)
		return res.finalize("")
	}

	for i := range pods.Items {
		pod := &pods.Items[i]
		// Skip system namespaces — their components legitimately use the node
		// network and bootstrap credentials.
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		ref := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)

		// Pod-level: hostNetwork puts the pod on the node's network namespace,
		// giving it a route to the cloud instance metadata service
		// (169.254.169.254) and the node's IAM/instance credentials.
		if pod.Spec.HostNetwork {
			res.add(ref, "runs with hostNetwork: true — can reach the node's instance metadata service (169.254.169.254) and steal the node's cloud credentials", SeverityHigh)
		}

		// Container-level: over-broad cloud credentials injected via env.
		for _, ctr := range allContainers(pod) {
			cref := fmt.Sprintf("%s (container %s)", ref, ctr.Name)
			for _, name := range k08CloudCredsInContainer(ctr) {
				res.add(cref, fmt.Sprintf("injects cloud credential env var %q — use a scoped, short-lived identity (IRSA / Workload Identity) instead", name), SeverityHigh)
			}
		}
	}

	return res.finalize("No pods can pivot to the cloud: none use hostNetwork and none carry over-broad cloud credentials.")
}

// k08CloudCredsInContainer returns the names of any well-known cloud
// credential environment variables set on the container. A literal Value and a
// valueFrom reference both count — either way a static cloud credential is being
// handed to the pod instead of a scoped IRSA / Workload Identity token.
func k08CloudCredsInContainer(ctr corev1.Container) []string {
	var found []string
	for i := range ctr.Env {
		env := &ctr.Env[i]
		if k08CloudCredentialEnvNames[env.Name] {
			found = append(found, env.Name)
		}
	}
	return found
}
