package checks

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func init() { Register(k10{}) }

// k10 validates OWASP K10: Inadequate Logging and Monitoring.
type k10 struct{}

func (k10) ID() string    { return "k10" }
func (k10) Title() string { return "Inadequate Logging and Monitoring" }
func (k10) Description() string {
	return "Detects whether a logging/monitoring agent (fluent-bit, fluentd, falco, prometheus, etc.) is running and reminds to enable API server audit logging."
}

// k10knownAgents are substrings matched against workload and container
// names/images to recognise a logging or monitoring stack.
var k10knownAgents = []string{
	"fluent-bit",
	"fluentd",
	"filebeat",
	"promtail",
	"vector",
	"falco",
	"prometheus",
	"otel",
	"datadog",
	"node-exporter",
}

func (c k10) Run(ctx context.Context, client kubernetes.Interface, namespace string) Result {
	res := &Result{ID: c.ID(), Title: c.Title()}

	// Logging/monitoring agents run cluster-wide, so scan every namespace.
	var detected []string

	var daemonSets *appsv1.DaemonSetList
	daemonSets, err := client.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		res.add("cluster", "unable to list daemonsets: "+err.Error(), SeverityHigh)
		return res.finalize("")
	}
	for i := range daemonSets.Items {
		ds := daemonSets.Items[i]
		if agent := k10matchWorkload(ds.Name, ds.Spec.Template.Spec); agent != "" {
			detected = append(detected, fmt.Sprintf("DaemonSet %s/%s (%s)", ds.Namespace, ds.Name, agent))
		}
	}

	deployments, err := client.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		res.add("cluster", "unable to list deployments: "+err.Error(), SeverityHigh)
		return res.finalize("")
	}
	for i := range deployments.Items {
		dep := deployments.Items[i]
		if agent := k10matchWorkload(dep.Name, dep.Spec.Template.Spec); agent != "" {
			detected = append(detected, fmt.Sprintf("Deployment %s/%s (%s)", dep.Namespace, dep.Name, agent))
		}
	}

	// API server audit logging cannot be introspected through client-go — the
	// audit policy lives on the control plane — so it never blocks a PASS; it is
	// folded into the summary as an out-of-band reminder instead of a finding.
	const auditReminder = " Note: API server audit logging cannot be verified via client-go; confirm out-of-band that --audit-policy-file is set (self-managed) or audit logging is enabled by your managed provider (EKS/GKE/AKS)."

	if len(detected) == 0 {
		res.add("cluster",
			"no logging/monitoring agent detected (looked for fluent-bit, fluentd, filebeat, promtail, vector, falco, prometheus, otel, datadog, node-exporter as a DaemonSet or Deployment) — attacker actions such as exec and secret reads would leave no collected trace",
			SeverityHigh)
		return res.finalize("")
	}

	return res.finalize("A logging/monitoring agent is running: " + strings.Join(detected, ", ") + "." + auditReminder)
}

// k10matchWorkload returns the matched agent keyword if the workload name or
// any of its container names/images corresponds to a known agent.
func k10matchWorkload(name string, spec corev1.PodSpec) string {
	haystacks := []string{strings.ToLower(name)}
	haystacks = append(haystacks, k10containerStrings(spec.InitContainers)...)
	haystacks = append(haystacks, k10containerStrings(spec.Containers)...)
	for _, h := range haystacks {
		for _, agent := range k10knownAgents {
			if strings.Contains(h, agent) {
				return agent
			}
		}
	}
	return ""
}

// k10containerStrings returns the lower-cased names and images of containers.
func k10containerStrings(containers []corev1.Container) []string {
	out := make([]string, 0, len(containers)*2)
	for _, ctr := range containers {
		out = append(out, strings.ToLower(ctr.Name), strings.ToLower(ctr.Image))
	}
	return out
}
