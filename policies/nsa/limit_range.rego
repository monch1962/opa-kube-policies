package kubernetes.nsa.validating.limit_range

# Link to OPA Playground to play with this policy: https://play.openpolicyagent.org/p/kaN6XjPy69

operations = {"CREATE", "UPDATE"}

deny[msg] {
	input.kind == "LimitRange"
	not input.spec.limits[0]["default"].cpu

	msg := "Need to define default CPU limit value"
}

deny[msg] {
	input.kind == "LimitRange"
	not input.spec.limits[0].defaultRequest.cpu

	msg := "Need to define default CPU request value"
}

deny[msg] {
	input.kind == "LimitRange"
	not input.spec.limits[0].max.cpu

	msg := "Need to define max CPU limit value"
}

deny[msg] {
	input.kind == "LimitRange"
	not input.spec.limits[0].min.cpu

	msg := "Need to define min CPU limit value"
}

deny[msg] {
	input.kind == "LimitRange"
	not input.spec.limits[0].type == "Container"

	msg := "Need to define limits at the container level"
}
