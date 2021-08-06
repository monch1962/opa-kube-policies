package kubernetes.nsa.validating.audit_policy

# Link to OPA Playground to play with this policy: https://play.openpolicyagent.org/p/KZm2TBblQK

operations = {"CREATE", "UPDATE"}

deny[msg] {
	input.kind == "Policy"

	not input.rules.level == "RequestResponse"
	msg := "No audit policy defined to log all RequestResponse events"
}
