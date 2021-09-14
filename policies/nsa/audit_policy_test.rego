package kubernetes.nsa.validating.audit_policy

test_accept_request_response_logging_set {
	count(deny) == 0 with input as {
		"apiVersion": "audit.k8s.io/v1",
		"kind": "Policy",
		"rules": {"level": "RequestResponse"},
	}

	trace(sprintf("deny: %v", [deny]))
}

test_deny_missing_request_response_logging_set {
	count(deny) == 1 with input as {
		"apiVersion": "audit.k8s.io/v1",
		"kind": "Policy",
		"rules": {"level": "NotRequestResponse"},
	}
}
