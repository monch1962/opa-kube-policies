package kubernetes.nsa.validating.encryption_configuration

# Link to OPA Playground to play with this policy: https://play.openpolicyagent.org/p/8lgI1M42OI

operations = {"CREATE", "UPDATE"}

deny[msg] {
	input.kind == "EncryptionConfiguration"

	some i
	not input.resources.providers[i].kms
	msg := sprintf("KMS not defined under encryption configuration for provider %s", [input.resources.providers[i]])
}
