import type { Risk } from "../types";

export const kbonus: Risk = {
  id: "BONUS",
  bonus: true,
  slug: "supply-chain-vulnerabilities",
  title: "Supply Chain Vulnerabilities",
  severity: "High",
  tagline:
    "NimbusMart's recommendations service ran a mutable `:latest` image - so the attacker who owned that tag was running code in the cluster.",
  icon: "🔗",

  overview: [
    "A container image is not a single artifact - it is the sum of a base image, dozens of OS and language packages, your application code, and the CI/CD machinery that assembled and pushed it. Every one of those inputs is a link in a supply chain, and Kubernetes will faithfully run whatever ends up in the registry.",
    "Supply chain risk shows up in the cluster as mutable, unverified image references: `:latest` tags that point at a moving target, images with no digest so their contents can change under the same name, and `imagePullPolicy: IfNotPresent` that quietly serves whatever stale layer a node happens to have cached.",
    "Without pinning by digest, provenance (who built this and from what source), an SBOM (what packages are inside), and signature verification (is this the artifact we intended), you have no way to answer the most basic security question: is the code running right now the code we reviewed and scanned?",
    "The failure is usually invisible until it isn't - the manifest applies cleanly, the pod runs, and the compromise arrives through an upstream dependency, a typosquatted package, or a poisoned base image that nobody chose on purpose.",
    "NimbusMart's `storefront/recommendations` Deployment is a textbook case: it pulls `busybox:latest` with no digest and `imagePullPolicy: Always`, so when an attacker replaced that mutable tag with a poisoned build, every rescheduled pod happily ran the backdoored image - and nobody could prove the running bytes were the ones that were reviewed.",
  ],
  impact: [
    "Malicious code execution: a poisoned base image or dependency runs with your workload's identity and network access.",
    "Silent drift: `:latest` can change between the version you scanned and the version that actually runs, invalidating every prior security review.",
    "Stale, unpatched layers: `imagePullPolicy: IfNotPresent` serves whatever a node cached, so 'urgent' image fixes never reach running pods.",
    "No incident response: with no digest, SBOM, or provenance you cannot tell which pods contain a vulnerable package during a zero-day.",
    "Registry/tag hijack: whoever controls the upstream tag or a mirror controls what executes in your cluster.",
  ],
  rootCauses: [
    "Images referenced by mutable tags (`:latest` or no tag at all) instead of an immutable `@sha256` digest.",
    "`imagePullPolicy: IfNotPresent` (or unset) so nodes reuse cached, unverified layers.",
    "No image signing or signature verification at admission time (no cosign / Sigstore, no policy engine).",
    "No SBOM generation or vulnerability scanning gate in CI, so unknown packages ship freely.",
    "Pulling from public/untrusted registries without a pull-through mirror or allowlist.",
  ],

  attackScenario: {
    summary:
      "An attacker poisons an upstream artifact your build trusts, and Kubernetes deploys it because nothing verifies what the image actually contains.",
    steps: [
      "A workload references `image: app:latest` with `imagePullPolicy: IfNotPresent` and no digest - a mutable, unverified reference.",
      "The attacker compromises an upstream link: a popular base image, a typosquatted dependency, or the registry account behind the tag.",
      "They push a new image to the same `:latest` tag. The reference in your manifest is unchanged, so no alert fires and no review is triggered.",
      "New pods (a rollout, a scale-up, or a rescheduled node) pull the moving tag and start running the attacker's code with your service account and network reach.",
      "Because there is no SBOM, digest, or provenance, defenders cannot even enumerate which pods are affected - the compromise blends into normal operation.",
    ],
  },

  challenge: {
    scenario:
      "NimbusMart's `storefront/recommendations` service is deployed straight from `busybox:latest` - a mutable tag, no digest, `imagePullPolicy: Always`. You have proof the upstream tag was hijacked: someone pushed a poisoned build to `:latest`, and because the manifest reference never changed, no review or alert fired. Every rescheduled pod now runs the attacker's image, which quietly dropped a backdoor inside the container.",
    objective:
      "Prove the compromise: exec into the running `recommendations` pod and read the payload the poisoned `:latest` image planted at `/tmp/.backdoor`.",
    difficulty: "Hard",
    points: 300,
    flagFormat: "FLAG{...}",
    flagHash: "79d80806488b8c7dbea3659fa0f686a6fdef89e03b648a929f4a2422f91d2d55",
    hints: [
      "Look at how the image is referenced: `kubectl get deploy -n storefront recommendations -o jsonpath='{.spec.template.spec.containers[0].image}'`. A bare `:latest` with no `@sha256:` digest is a moving target - you cannot prove what is running.",
      "The poisoned build behaves like a normal service but left traces. Check its logs (`kubectl logs -n storefront deploy/recommendations`) - the payload beacons on startup.",
      "The backdoor dropped a file. Read it: `kubectl exec -n storefront deploy/recommendations -- cat /tmp/.backdoor`.",
    ],
  },

  lab: {
    objective:
      "Deploy NimbusMart's recommendations service from a mutable `:latest` image, capture the flag the poisoned build planted in the container, then redeploy a version pinned to an immutable digest whose clean build no longer carries the payload.",
    prerequisites: [
      "A local cluster: `kind create cluster --config labs/kind-cluster.yaml`",
      "kubectl configured to talk to that cluster",
      "Optional: `crane` or `docker buildx` to resolve real image digests",
    ],
    vulnerableManifest: "labs/kbonus-supply-chain/vulnerable.yaml",
    fixedManifest: "labs/kbonus-supply-chain/fixed.yaml",
    steps: [
      {
        title: "Deploy the poisoned recommendations service",
        description:
          "Creates the storefront namespace and the recommendations Deployment, which pulls busybox:latest (mutable, no digest) with imagePullPolicy: Always - the reference the attacker hijacked upstream.",
        command:
          "kubectl apply -f labs/kbonus-supply-chain/vulnerable.yaml && kubectl rollout status -n storefront deploy/recommendations",
        expected:
          "namespace/storefront created / deployment.apps/recommendations created / deployment \"recommendations\" successfully rolled out",
        kind: "setup",
      },
      {
        title: "Show the reference is mutable and unprovable",
        description:
          "Inspect the image the manifest requested. A bare :latest with no @sha256 digest is a moving target - nothing here proves what actually runs.",
        command:
          "kubectl get deploy -n storefront recommendations -o jsonpath='{.spec.template.spec.containers[0].image}{\"\\n\"}'",
        expected: "busybox:latest - a moving target with no digest.",
        kind: "attack",
      },
      {
        title: "Spot the poisoned build in the logs",
        description:
          "The hijacked :latest image behaves like a normal service but its payload beacons on startup - the first sign that the running bytes are not the reviewed ones.",
        command: "kubectl logs -n storefront deploy/recommendations",
        expected:
          "[recommendations] poisoned :latest build active - backdoor installed",
        kind: "attack",
      },
      {
        title: "Capture the flag from the backdoor the image dropped",
        description:
          "The poisoned build planted an attacker file inside the container. Read it to prove the untrusted image ran code with the service's identity.",
        command:
          "kubectl exec -n storefront deploy/recommendations -- cat /tmp/.backdoor",
        expected:
          "FLAG{poisoned_latest_tag_shipped_to_prod} - submit this on the Challenge tab.",
        kind: "attack",
      },
      {
        title: "Clean up and deploy the hardened workload",
        description:
          "The fixed manifest pins the image by explicit version AND immutable @sha256 digest, keeps imagePullPolicy: Always, records provenance/SBOM/signature metadata as annotations, and runs a clean build with no backdoor.",
        command:
          "kubectl delete -f labs/kbonus-supply-chain/vulnerable.yaml && kubectl apply -f labs/kbonus-supply-chain/fixed.yaml && kubectl rollout status -n storefront deploy/recommendations",
        expected:
          'deployment.apps "recommendations" deleted / deployment.apps/recommendations created / successfully rolled out',
        kind: "fix",
      },
      {
        title: "Verify the reference is immutable and the flag is gone",
        description:
          "The image is now pinned by digest, so you can prove exactly what runs - and because the poisoned payload never shipped in the clean build, the backdoor file no longer exists.",
        command:
          "kubectl get deploy -n storefront recommendations -o jsonpath='{.spec.template.spec.containers[0].image}{\"\\n\"}' && kubectl exec -n storefront deploy/recommendations -- sh -c 'cat /tmp/.backdoor 2>&1 || echo NO_BACKDOOR'",
        expected:
          "An image reference ending in @sha256:… then NO_BACKDOOR - the poisoned payload and the flag are gone.",
        kind: "verify",
      },
    ],
  },

  defense: {
    summary:
      "Reference every image by an immutable digest, verify its signature and provenance at admission time, and generate an SBOM plus a vulnerability scan gate in CI so nothing unknown ever reaches the cluster.",
    patches: [
      {
        title: "Pin images by digest and always re-verify the pull",
        description:
          "Reference an explicit version and its immutable content digest, and set imagePullPolicy: Always so the digest is checked on every pull instead of trusting a node's cache.",
        lang: "yaml",
        code: `containers:
  - name: app
    # version tag for humans + immutable digest for machines
    image: nginx:1.27.3@sha256:<resolved-digest>
    imagePullPolicy: Always`,
      },
      {
        title: "Verify signatures and provenance at admission",
        description:
          "Use a policy engine (e.g. Sigstore policy-controller or Kyverno) to reject any image that is not signed by a trusted identity and does not carry attested provenance.",
        lang: "yaml",
        code: `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signatures
spec:
  validationFailureAction: Enforce
  rules:
    - name: require-cosign-signature
      match:
        any:
          - resources:
              kinds: ["Pod"]
      verifyImages:
        - imageReferences: ["registry.example.com/*"]
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/org/repo/.github/workflows/*"
                    issuer: "https://token.actions.githubusercontent.com"`,
      },
      {
        title: "Gate the build on an SBOM and a vulnerability scan",
        description:
          "Generate a Software Bill of Materials and fail the pipeline on HIGH/CRITICAL findings before the image is ever pushed.",
        lang: "bash",
        code: `# Generate an SBOM for the built image
syft packages registry.example.com/app:1.27.3 -o spdx-json > sbom.json

# Fail the build on serious, fixable vulnerabilities
trivy image --exit-code 1 --severity HIGH,CRITICAL registry.example.com/app:1.27.3

# Sign the image so admission control can verify it
cosign sign --yes registry.example.com/app@sha256:<resolved-digest>`,
      },
    ],
    bestPractices: [
      "Pin every image by @sha256 digest; treat a bare `:latest` reference as a build failure.",
      "Set imagePullPolicy: Always so cached, unverified layers are never silently served.",
      "Sign images with cosign/Sigstore and verify signatures at admission with a policy engine.",
      "Generate an SBOM per build and fail CI on HIGH/CRITICAL vulnerabilities before push.",
      "Pull only from trusted, allowlisted registries - mirror public images through a controlled proxy.",
      "Prefer minimal, distroless base images to shrink the dependency and attack surface.",
    ],
  },

  checker: {
    checkId: "kbonus",
    whatItChecks:
      "Scans all pods for containers using mutable image references (:latest or no tag), images not pinned by an @sha256 digest, and imagePullPolicy weaker than Always for mutable tags.",
    passCriteria: [
      "No container image uses the :latest tag or an implicit (missing) tag.",
      "Every container image is pinned by an @sha256 digest.",
      "imagePullPolicy is Always for any image that is not digest-pinned.",
      "Images come from trusted, verifiable references rather than moving tags.",
    ],
  },

  references: [
    {
      label: "OWASP K8s Top 10 - BONUS",
      url: "https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/BONUS-supply-chain-vulnerabilities",
    },
    {
      label: "Kubernetes - Images (pull policy & digests)",
      url: "https://kubernetes.io/docs/concepts/containers/images/",
    },
    {
      label: "SLSA - Supply-chain Levels for Software Artifacts",
      url: "https://slsa.dev/",
    },
    {
      label: "Sigstore / cosign - image signing & verification",
      url: "https://docs.sigstore.dev/",
    },
  ],
};
