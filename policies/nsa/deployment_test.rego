package kubernetes.nsa.validating.deployment

test_accept_read_only_root_filesystem {
	not deny with input as {
		"kind": "Deployment",
		"metadata": {
			"labels": {"app": "web"},
			"name": "web",
		},
		"spec": {"template": {"spec": {"containers": {"securityContext": {"readOnlyRootFilesystem": true}}}}},
	}
}

test_deny_read_only_root_filesystem_false {
	deny with input as {
		"kind": "Deployment",
		"metadata": {
			"labels": {"app": "web"},
			"name": "web",
		},
		"spec": {"template": {"spec": {"containers": {"securityContext": {"readOnlyRootFilesystem": false}}}}},
	}
}

test_deny_missing_security_context {
	deny with input as {
		"kind": "Deployment",
		"metadata": {
			"labels": {"app": "web"},
			"name": "web",
		},
		"spec": {"template": {"spec": {"containers": ""}}},
	}
}
