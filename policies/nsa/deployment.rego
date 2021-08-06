package kubernetes.nsa.validating.deployment

# Link to OPA Playground to play with this policy: https://play.openpolicyagent.org/p/1aJxkfHXZ2

operations = {"CREATE", "UPDATE"}

deny[msg] {
	input.kind == "Deployment"
	not input.spec.template.spec.containers.securityContext

	msg := "No security context defined for containers in this deployment"
}

deny[msg] {
	input.kind == "Deployment"
	input.spec.template.spec.containers.securityContext
	not input.spec.template.spec.containers.securityContext.readOnlyRootFilesystem == true

	msg := "Container's root filesystem should be defined as read-only"
}
