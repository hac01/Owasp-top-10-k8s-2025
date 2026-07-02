package checks

import (
	"context"
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func init() { Register(k02{}) }

// k02 validates OWASP K02: Overly Permissive Authorization Configurations.
type k02 struct{}

func (k02) ID() string    { return "k02" }
func (k02) Title() string { return "Overly Permissive Authorization Configurations" }
func (k02) Description() string {
	return "Flags Roles/ClusterRoles with wildcard verbs, resources, or apiGroups, and cluster-admin bindings granted to service accounts or wide groups."
}

func (c k02) Run(ctx context.Context, client kubernetes.Interface, namespace string) Result {
	res := &Result{ID: c.ID(), Title: c.Title()}

	// Namespaced Roles.
	roles, err := client.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		res.add("cluster", "unable to list roles: "+err.Error(), SeverityHigh)
		return res.finalize("")
	}
	for i := range roles.Items {
		role := &roles.Items[i]
		if isSystemNamespace(role.Namespace) {
			continue
		}
		ref := fmt.Sprintf("Role %s/%s", role.Namespace, role.Name)
		k02evaluateRules(res, ref, role.Rules)
	}

	// Cluster-scoped ClusterRoles.
	clusterRoles, err := client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		res.add("cluster", "unable to list clusterroles: "+err.Error(), SeverityHigh)
		return res.finalize("")
	}
	for i := range clusterRoles.Items {
		cr := &clusterRoles.Items[i]
		// Skip built-in system ClusterRoles — they legitimately need broad access.
		if k02isBuiltInClusterRole(cr.Name) {
			continue
		}
		ref := fmt.Sprintf("ClusterRole %s", cr.Name)
		k02evaluateRules(res, ref, cr.Rules)
	}

	// ClusterRoleBindings — flag dangerous cluster-admin grants.
	crbs, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		res.add("cluster", "unable to list clusterrolebindings: "+err.Error(), SeverityHigh)
		return res.finalize("")
	}
	for i := range crbs.Items {
		crb := &crbs.Items[i]
		if crb.RoleRef.Kind != "ClusterRole" || crb.RoleRef.Name != "cluster-admin" {
			continue
		}
		ref := fmt.Sprintf("ClusterRoleBinding %s", crb.Name)
		for _, s := range crb.Subjects {
			if msg, risky := k02riskyAdminSubject(s); risky {
				res.add(ref, "binds cluster-admin to "+msg, SeverityCritical)
			}
		}
	}

	return res.finalize("No wildcard RBAC rules or over-broad cluster-admin bindings found.")
}

// k02evaluateRules reports any policy rule that uses a wildcard in verbs,
// resources, or apiGroups.
func k02evaluateRules(res *Result, ref string, rules []rbacv1.PolicyRule) {
	for _, rule := range rules {
		if k02hasWildcard(rule.Verbs) {
			res.add(ref, "grants wildcard verbs [\"*\"] (allows every action)", SeverityHigh)
		}
		if k02hasWildcard(rule.Resources) {
			res.add(ref, "grants wildcard resources [\"*\"] (applies to every resource)", SeverityHigh)
		}
		if k02hasWildcard(rule.APIGroups) {
			res.add(ref, "grants wildcard apiGroups [\"*\"] (spans every API group)", SeverityHigh)
		}
	}
}

func k02hasWildcard(values []string) bool {
	for _, v := range values {
		if v == "*" {
			return true
		}
	}
	return false
}

// k02riskyAdminSubject returns a description and true when the subject of a
// cluster-admin binding is a service account or an over-broad group/user.
func k02riskyAdminSubject(s rbacv1.Subject) (string, bool) {
	switch s.Kind {
	case "ServiceAccount":
		return fmt.Sprintf("service account %s/%s", s.Namespace, s.Name), true
	case "Group":
		switch s.Name {
		case "system:authenticated", "system:unauthenticated", "system:anonymous":
			return fmt.Sprintf("wide group %q", s.Name), true
		}
	case "User":
		if s.Name == "system:anonymous" {
			return "the anonymous user", true
		}
	}
	return "", false
}

// k02isBuiltInClusterRole skips the default/system ClusterRoles that ship with
// Kubernetes so the check focuses on user-defined roles.
func k02isBuiltInClusterRole(name string) bool {
	if strings.HasPrefix(name, "system:") {
		return true
	}
	switch name {
	case "cluster-admin", "admin", "edit", "view":
		return true
	}
	return false
}
