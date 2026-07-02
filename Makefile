# OWASP Kubernetes Top 10 — convenience targets
.PHONY: help web web-build cluster cluster-down checker check scan clean-labs \
        images deploy platform-down terminal-local up

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	 awk 'BEGIN{FS=":.*?## "}{printf "  \033[35m%-14s\033[0m %s\n", $$1, $$2}'

web: ## Run the web app in dev mode (http://localhost:3000)
	cd web && npm install && npm run dev

web-build: ## Production build of the web app
	cd web && npm install && npm run build

cluster: ## Create the local kind lab cluster
	kind create cluster --config labs/kind-cluster.yaml
	kubectl config use-context kind-owasp-labs

cluster-down: ## Delete the local kind lab cluster
	kind delete cluster --name owasp-labs

checker: ## Build the Go checker binary (./checker/owasp-k8s-checker)
	cd checker && go build -o owasp-k8s-checker .

scan: ## Run every check against the current cluster
	cd checker && go run . --all

check: ## Run a single check, e.g. make check ID=k01
	cd checker && go run . --check $(ID)

up: ## One shot: cluster + images + deploy, then print the URL (runs setup.sh)
	./setup.sh

images: ## Build the web + terminal images and load them into kind
	bash deploy/build.sh

deploy: ## Apply the platform manifests (web + terminal + RBAC) to the cluster
	kubectl apply -f deploy/
	@echo "web -> http://localhost:30090   (kubectl get pods -n nimbusmart-ctf -w)"

platform-down: ## Remove the CTF platform (keeps the cluster)
	kubectl delete -f deploy/ --ignore-not-found

terminal-local: ## Run the terminal backend locally on :30091 (dev, uses ~/.kube/config)
	cd terminal-server && npm install && PORT=30091 TERMINAL_CWD=$(PWD) npm start

clean-labs: ## Delete all lab resources from the cluster
	@for f in labs/*/setup.yaml labs/*/vulnerable.yaml labs/*/fixed.yaml; do \
	  [ -f $$f ] && kubectl delete -f $$f --ignore-not-found --wait=false >/dev/null 2>&1 || true; \
	done
	@kubectl delete ns storefront checkout data platform nimbusmart-ops --ignore-not-found --wait=false >/dev/null 2>&1 || true
	@kubectl delete ds log-collector -n kube-system --ignore-not-found >/dev/null 2>&1 || true
	@echo "lab resources deleted"
