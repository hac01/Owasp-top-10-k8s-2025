// Command owasp-k8s-checker validates a Kubernetes cluster against the
// OWASP Kubernetes Top 10 controls used by the companion labs.
//
//	go run . --check k01           # run one check
//	go run . --all                 # run every check
//	go run . --all --json          # machine-readable output
//	go run . --all -n apps         # scope to a namespace
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/hac01/Owasp-top-10-k8s-2025/checker/checks"
	"github.com/hac01/Owasp-top-10-k8s-2025/checker/internal/cluster"
)

var (
	colReset  = "\033[0m"
	colRed    = "\033[31m"
	colGreen  = "\033[32m"
	colYellow = "\033[33m"
	colBold   = "\033[1m"
	colDim    = "\033[2m"
	colViolet = "\033[35m"
)

func main() {
	var (
		checkID    = flag.String("check", "", "run a single check by id (e.g. k01)")
		all        = flag.Bool("all", false, "run every registered check")
		list       = flag.Bool("list", false, "list available checks and exit")
		namespace  = flag.String("n", "", "namespace to scope the scan (default: all namespaces)")
		kubeconfig = flag.String("kubeconfig", "", "path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)")
		asJSON     = flag.Bool("json", false, "emit JSON instead of a formatted report")
		noColor    = flag.Bool("no-color", false, "disable ANSI colors")
	)
	flag.Parse()

	if *noColor || os.Getenv("NO_COLOR") != "" {
		disableColor()
	}

	if *list {
		listChecks()
		return
	}

	selected, err := selectChecks(*checkID, *all)
	if err != nil {
		fmt.Fprintln(os.Stderr, colRed+"error: "+err.Error()+colReset)
		flag.Usage()
		os.Exit(2)
	}

	client, host, err := cluster.Connect(*kubeconfig)
	if err != nil {
		fmt.Fprintln(os.Stderr, colRed+"could not connect to cluster: "+err.Error()+colReset)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	results := make([]checks.Result, 0, len(selected))
	for _, c := range selected {
		results = append(results, c.Run(ctx, client, *namespace))
	}

	if *asJSON {
		emitJSON(results)
	} else {
		printReport(host, *namespace, results)
	}

	for _, r := range results {
		if !r.Passed {
			os.Exit(1) // non-zero exit for CI gating
		}
	}
}

func selectChecks(id string, all bool) ([]checks.Check, error) {
	switch {
	case all && id != "":
		return nil, fmt.Errorf("use either --all or --check, not both")
	case all:
		return checks.All(), nil
	case id != "":
		c, ok := checks.Get(id)
		if !ok {
			return nil, fmt.Errorf("unknown check %q (try --list)", id)
		}
		return []checks.Check{c}, nil
	default:
		return nil, fmt.Errorf("specify --check <id> or --all")
	}
}

func listChecks() {
	fmt.Println(colBold + colViolet + "OWASP Kubernetes Top 10 — available checks" + colReset)
	for _, c := range checks.All() {
		fmt.Printf("  %s%s%s  %s\n", colBold, c.ID(), colReset, c.Title())
		fmt.Printf("        %s%s%s\n", colDim, c.Description(), colReset)
	}
}

func emitJSON(results []checks.Result) {
	passed := 0
	for _, r := range results {
		if r.Passed {
			passed++
		}
	}
	out := map[string]any{
		"summary": map[string]int{"total": len(results), "passed": passed, "failed": len(results) - passed},
		"results": results,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func printReport(host, namespace string, results []checks.Result) {
	scope := "all namespaces"
	if namespace != "" {
		scope = "namespace " + namespace
	}
	fmt.Printf("\n%s%s  OWASP Kubernetes Top 10 — Cluster Assessment%s\n", colBold, colViolet, colReset)
	fmt.Printf("%s  cluster: %s   scope: %s%s\n\n", colDim, host, scope, colReset)

	passed := 0
	for _, r := range results {
		badge := colGreen + "PASS" + colReset
		if !r.Passed {
			badge = colRed + "FAIL" + colReset
		} else {
			passed++
		}
		fmt.Printf("  [%s] %s%s%s — %s\n", badge, colBold, r.ID, colReset, r.Title)
		fmt.Printf("        %s%s%s\n", colDim, r.Summary, colReset)
		for _, f := range r.Findings {
			fmt.Printf("        %s• [%s] %s%s: %s\n", sevColor(f.Severity), f.Severity, f.Resource, colReset, f.Message)
		}
	}

	total := len(results)
	fmt.Printf("\n%s  %d/%d checks passed.%s\n\n", colBold, passed, total, colReset)
}

func sevColor(s checks.Severity) string {
	switch s {
	case checks.SeverityCritical:
		return colRed
	case checks.SeverityHigh:
		return colRed
	case checks.SeverityMedium:
		return colYellow
	default:
		return colReset
	}
}

// disableColor blanks all ANSI codes so output is plain text (for CI / files).
func disableColor() {
	colReset, colRed, colGreen, colYellow, colBold, colDim, colViolet = "", "", "", "", "", "", ""
}
