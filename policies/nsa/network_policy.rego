package kubernetes.nsa.validating.pod_security

# Link to OPA Playground to play with this policy: https://play.openpolicyagent.org/p/UIK9eMzs5V

operations = {"CREATE", "UPDATE"}

contains(arr, elem) {
	arr[_] = elem
}

deny[msg] {
	input.kind == "NetworkPolicy"
	not input.spec.podSelector

	msg := "Need a network policy defined for all pods"
}

deny[msg] {
	input.kind == "NetworkPolicy"
	not contains(input.spec.policyTypes, "Egress")

	msg := "Need a default egress policy for all pods"
}

deny[msg] {
	input.kind == "NetworkPolicy"
	input.spec.egress
	not input.spec.egress[0].ports

	msg := "Need a egress policy restricting ports for all pods"
}

deny[msg] {
	input.kind == "NetworkPolicy"
	input.spec.egress
	input.spec.egress[0].ports
	not input.spec.egress[0].ports[0].port

	msg := "Need a egress policy restricting ports for all pods"
}

deny[msg] {
	input.kind == "NetworkPolicy"
	input.spec.egress
	input.spec.egress[0].ports
	not input.spec.egress[0].ports[0].protocol

	msg := "Need a egress policy restricting protocols for all pods"
}

deny[msg] {
	input.kind == "NetworkPolicy"
	input.spec.egress
	input.spec.egress[0].ports
	not input.spec.egress[0].to

	msg := "Need a egress policy restricting IP addresses for all pods"
}

deny[msg] {
	input.kind == "NetworkPolicy"
	not contains(input.spec.policyTypes, "Ingress")

	msg := "Need a default ingress policy for all pods"
}

deny[msg] {
	input.kind == "NetworkPolicy"
	input.spec.ingress
	input.spec.ingress[0].ports
	not input.spec.ingress[0].ports[0].port

	msg := "Need a ingress policy restricting ports for all pods"
}

deny[msg] {
	input.kind == "NetworkPolicy"
	input.spec.ingress
	input.spec.ingress[0].ports
	not input.spec.ingress[0].ports[0].protocol

	msg := "Need a ingress policy restricting protocols for all pods"
}

deny[msg] {
	input.kind == "NetworkPolicy"
	input.spec.ingress
	input.spec.ingress[0].ports
	not input.spec.ingress[0].from

	msg := "Need a ingress policy restricting IP addresses for all pods"
}
