// Package checks defines the OWASP Kubernetes Top 10 automated checks and a
// registry so `main` can discover and run them.
package checks

import (
	"context"
	"sort"

	"k8s.io/client-go/kubernetes"
)

// Severity mirrors the OWASP risk rating for the finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
)

// Finding is a single problem discovered by a check.
type Finding struct {
	Resource string   `json:"resource"` // e.g. "default/insecure-app (container app)"
	Message  string   `json:"message"`
	Severity Severity `json:"severity"`
}

// Result is the outcome of running one check.
type Result struct {
	ID       string    `json:"id"`       // "k01"
	Title    string    `json:"title"`    // "Insecure Workload Configurations"
	Passed   bool      `json:"passed"`   // true when no findings
	Summary  string    `json:"summary"`  // one-line human summary
	Findings []Finding `json:"findings"` // empty when Passed
}

// Fail is a convenience constructor for a failing result.
func (r *Result) add(resource, message string, sev Severity) {
	r.Findings = append(r.Findings, Finding{Resource: resource, Message: message, Severity: sev})
}

// finalize sets Passed/Summary based on findings.
func (r *Result) finalize(passMsg string) Result {
	r.Passed = len(r.Findings) == 0
	if r.Passed {
		r.Summary = passMsg
	} else {
		r.Summary = pluralize(len(r.Findings), "issue")
	}
	return *r
}

// Check is one OWASP Top 10 control validation.
type Check interface {
	ID() string
	Title() string
	Description() string
	// Run inspects the cluster (scoped to namespace, or all if "") and returns a Result.
	Run(ctx context.Context, client kubernetes.Interface, namespace string) Result
}

var registry = map[string]Check{}

// Register adds a check to the global registry. Called from each check's init().
func Register(c Check) {
	registry[c.ID()] = c
}

// Get returns a single check by id.
func Get(id string) (Check, bool) {
	c, ok := registry[id]
	return c, ok
}

// All returns every registered check sorted by id (k01..k10).
func All() []Check {
	ids := make([]string, 0, len(registry))
	for id := range registry {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Check, 0, len(ids))
	for _, id := range ids {
		out = append(out, registry[id])
	}
	return out
}

func pluralize(n int, word string) string {
	s := ""
	if n != 1 {
		s = "s"
	}
	return itoa(n) + " " + word + s + " found"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
