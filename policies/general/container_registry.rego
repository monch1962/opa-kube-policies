package kubernetes.nsa.validating.audit_policy

# Link to OPA Playground to play with this policy: https://play.openpolicyagent.org/p/x0hykec3E0

operations = {"CREATE", "UPDATE"}

deny[msg] {
	input.kind == "Pod"
	some i, j
	image := input.spec.containers[i].image
	not any([re_match(approved_container_registries[j], image)])

	msg := sprintf("Image '%s' defined for deployment is not from an approved registry", [input.spec.containers[i].image])
}
