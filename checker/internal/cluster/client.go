// Package cluster builds a Kubernetes client from the local kubeconfig.
package cluster

import (
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Connect returns a clientset. If kubeconfig is empty it uses, in order:
// the KUBECONFIG env var, in-cluster config, then ~/.kube/config.
func Connect(kubeconfig string) (kubernetes.Interface, string, error) {
	cfg, host, err := restConfig(kubeconfig)
	if err != nil {
		return nil, "", err
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, "", fmt.Errorf("building clientset: %w", err)
	}
	return cs, host, nil
}

func restConfig(kubeconfig string) (*rest.Config, string, error) {
	if kubeconfig == "" {
		kubeconfig = os.Getenv("KUBECONFIG")
	}
	// Try in-cluster first only when no explicit path and no default file.
	if kubeconfig == "" {
		if home, err := os.UserHomeDir(); err == nil {
			candidate := filepath.Join(home, ".kube", "config")
			if _, statErr := os.Stat(candidate); statErr == nil {
				kubeconfig = candidate
			}
		}
	}
	if kubeconfig == "" {
		cfg, err := rest.InClusterConfig()
		if err != nil {
			return nil, "", fmt.Errorf("no kubeconfig found and not running in-cluster: %w", err)
		}
		return cfg, cfg.Host, nil
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, "", fmt.Errorf("loading kubeconfig %q: %w", kubeconfig, err)
	}
	return cfg, cfg.Host, nil
}
