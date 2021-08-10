package kubernetes.nsa.validating.audit_policy

# Link to OPA Playground to play with this policy: https://play.openpolicyagent.org/p/x0hykec3E0

import data.kubernetes.util.validating.customer_specific as cs

operations = {"CREATE", "UPDATE"}

# approved_container_registries should contain a set of regexes to match acceptable Docker registries for Kubernetes pods
#approved_container_registries := ["^nginx$", "^https://my-approved-registry/"]

deny[msg] {
	input.kind == "Pod"
	some i, j
	image := input.spec.containers[i].image
	not any([re_match(cs.approved_container_registries[j], image)])

	msg := sprintf("Image '%s' defined for deployment is not from an approved registry", [input.spec.containers[i].image])
}
