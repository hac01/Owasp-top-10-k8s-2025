package checks

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func init() { Register(kbonus{}) }

// kbonus validates OWASP BONUS: Supply Chain Vulnerabilities.
type kbonus struct{}

func (kbonus) ID() string    { return "kbonus" }
func (kbonus) Title() string { return "Supply Chain Vulnerabilities" }
func (kbonus) Description() string {
	return "Flags containers using mutable image references (:latest or no tag), images not pinned by @sha256 digest, and imagePullPolicy weaker than Always for mutable tags."
}

func (c kbonus) Run(ctx context.Context, client kubernetes.Interface, namespace string) Result {
	res := &Result{ID: c.ID(), Title: c.Title()}

	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		res.add("cluster", "unable to list pods: "+err.Error(), SeverityHigh)
		return res.finalize("")
	}

	for i := range pods.Items {
		pod := &pods.Items[i]
		// Skip system namespaces — their images are managed by the platform.
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		ref := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)

		for _, ctr := range allContainers(pod) {
			cref := fmt.Sprintf("%s (container %s)", ref, ctr.Name)
			pinned := kbonusisPinnedByDigest(ctr.Image)
			mutable := kbonusisMutableTag(ctr.Image)

			if !pinned {
				res.add(cref, fmt.Sprintf("image %q is not pinned by @sha256 digest (contents can change under the same reference)", ctr.Image), SeverityHigh)
			}
			if mutable {
				res.add(cref, fmt.Sprintf("image %q uses a mutable tag (:latest or no tag) — pin an explicit version and digest", ctr.Image), SeverityHigh)
				// A mutable tag with a lax pull policy means the node may serve
				// a stale, unscanned layer from its local cache.
				if ctr.ImagePullPolicy != corev1.PullAlways {
					res.add(cref, fmt.Sprintf("imagePullPolicy is %q for a mutable image (set it to Always to avoid serving stale cached layers)", kbonuspullPolicy(ctr.ImagePullPolicy)), SeverityMedium)
				}
			}
		}
	}

	return res.finalize("All container images are pinned by digest and pulled from trusted, immutable references.")
}

// kbonusisPinnedByDigest reports whether the image reference is pinned to an
// immutable content digest (e.g. repo@sha256:...).
func kbonusisPinnedByDigest(image string) bool {
	return strings.Contains(image, "@sha256:")
}

// kbonusisMutableTag reports whether the image uses the ":latest" tag or has no
// tag/digest at all (which resolves to ":latest"). A digest-pinned image is
// never considered mutable.
func kbonusisMutableTag(image string) bool {
	if kbonusisPinnedByDigest(image) {
		return false
	}
	tag := kbonusimageTag(image)
	return tag == "" || tag == "latest"
}

// kbonusimageTag extracts the tag from an image reference, correctly ignoring a
// registry host:port and returning "" when no tag is present.
func kbonusimageTag(image string) string {
	// Strip any digest suffix first.
	if idx := strings.Index(image, "@"); idx >= 0 {
		image = image[:idx]
	}
	// Consider only the final path component so a "host:port/..." prefix is
	// not mistaken for a tag separator.
	name := image
	if slash := strings.LastIndex(image, "/"); slash >= 0 {
		name = image[slash+1:]
	}
	if colon := strings.LastIndex(name, ":"); colon >= 0 {
		return name[colon+1:]
	}
	return ""
}

func kbonuspullPolicy(p corev1.PullPolicy) string {
	if p == "" {
		return "unset"
	}
	return string(p)
}
