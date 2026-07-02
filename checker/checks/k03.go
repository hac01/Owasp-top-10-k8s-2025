package checks

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func init() { Register(k03{}) }

// k03 validates OWASP K03: Secrets Management Failures.
type k03 struct{}

func (k03) ID() string    { return "k03" }
func (k03) Title() string { return "Secrets Management Failures" }
func (k03) Description() string {
	return "Flags plaintext secrets hardcoded directly in container environment variables instead of being sourced from a Secret via valueFrom.secretKeyRef."
}

// k03SensitiveKeywords are substrings (matched case-insensitively) in an env var
// NAME that strongly suggest the value is a credential.
var k03SensitiveKeywords = []string{
	"PASSWORD",
	"PASSWD",
	"SECRET",
	"TOKEN",
	"APIKEY",
	"API_KEY",
	"ACCESS_KEY",
	"PRIVATE_KEY",
	"CREDENTIAL",
}

func (c k03) Run(ctx context.Context, client kubernetes.Interface, namespace string) Result {
	res := &Result{ID: c.ID(), Title: c.Title()}

	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		res.add("cluster", "unable to list pods: "+err.Error(), SeverityHigh)
		return res.finalize("")
	}

	for i := range pods.Items {
		pod := &pods.Items[i]
		// Skip system namespaces — they legitimately carry bootstrap credentials.
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		ref := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)

		for _, ctr := range allContainers(pod) {
			cref := fmt.Sprintf("%s (container %s)", ref, ctr.Name)
			for j := range ctr.Env {
				env := &ctr.Env[j]
				// A ValueFrom (secretKeyRef/configMapKeyRef/etc.) is not a
				// literal — only a hardcoded, inline Value is a plaintext leak.
				if env.ValueFrom != nil {
					continue
				}
				if env.Value == "" {
					continue
				}
				if k03IsSensitiveName(env.Name) {
					res.add(cref, fmt.Sprintf("env var %q holds a hardcoded plaintext secret — source it from a Secret via valueFrom.secretKeyRef", env.Name), SeverityHigh)
				}
			}
		}
	}

	return res.finalize("No hardcoded plaintext secrets found in container environment variables.")
}

// k03IsSensitiveName reports whether an env var name contains a keyword that
// suggests its value is a credential.
func k03IsSensitiveName(name string) bool {
	upper := strings.ToUpper(name)
	for _, kw := range k03SensitiveKeywords {
		if strings.Contains(upper, kw) {
			return true
		}
	}
	return false
}
