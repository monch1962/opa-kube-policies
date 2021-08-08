package kubernetes.nsa.validating.audit_policy

test_accept_request_response_logging_set {
	not deny with input as {
		"apiVersion": "audit.k8s.io/v1",
		"kind": "Policy",
		"rules": {"level": "RequestResponse"},
	}
}

test_deny_missing_request_response_logging_set {
	deny with input as {
		"apiVersion": "audit.k8s.io/v1",
		"kind": "Policy",
		"rules": {"level": "NotRequestResponse"},
	}
}
