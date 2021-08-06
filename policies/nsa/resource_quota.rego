package kubernetes.nsa.validating.resource_quota

# Link to OPA Playground to play with this policy: https://play.openpolicyagent.org/p/quDqYJo4k3

operations = {"CREATE", "UPDATE"}

deny[msg] {
	input.kind == "ResourceQuota"
	not input.spec.hard.requests.cpu

	msg := "Must set a hard CPU quota value (spec.hard.requests.cpu)"
}

deny[msg] {
	input.kind == "ResourceQuota"
	not input.spec.hard.requests.memory

	msg := "Must set a hard memory quota value (spec.hard.requests.memory)"
}

deny[msg] {
	input.kind == "ResourceQuota"
	not input.spec.hard.limits.cpu

	msg := "Must set a hard CPU limit value (spec.hard.limits.cpu)"
}

deny[msg] {
	input.kind == "ResourceQuota"
	not input.spec.hard.limits.memory

	msg := "Must set a hard memory limit value (spec.hard.limits.memory)"
}
