package kubernetes.general.container_registry

# Link to OPA Playground to play with this policy: https://play.openpolicyagent.org/p/x0hykec3E0

import data.kubernetes.util.validating.customer_specific as cs

operations = {"CREATE", "UPDATE"}

# approved_container_registries should contain a set of regexes to match acceptable Docker registries for Kubernetes pods
#approved_container_registries := ["^nginx$", "^https://my-approved-registry/"]
approved_container_registry := "my-registry/"

deny[msg] {
	input.kind == "Pod"
	image := input.spec.containers[_].image

	# trace(sprintf("image: %v", [image]))
	not startswith(image, cs.approved_container_registry)

	msg := sprintf("Image '%v' defined for deployment is not from an approved registry", [image])
}

deny[msg] {
	input.kind == "Deployment"
	image := input.spec.template.spec.containers[_].image
	not startswith(image, cs.approved_container_registry)

	msg := sprintf("Image '%v' defined for deployment is not from an approved registry", [image])
}
