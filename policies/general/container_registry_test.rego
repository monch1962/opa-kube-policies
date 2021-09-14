package kubernetes.nsa.validating.audit_policy

# Link to OPA Playground to play with this policy: https://play.openpolicyagent.org/p/KZm2TBblQK

test_unauthorised_registry_blocked {
	count(deny) == 0 with input as {
		"apiVersion": "audit.k8s.io/v1",
		"kind": "Pod",
		"spec": {"containers": [
			{
				"image": "https://my-approved-registry/hooli.com/nginx",
				"name": "nginx-frontend",
			},
			{
				"image": "mysql",
				"name": "mysql-backend",
			},
			{
				"image": "https://my-approved-registry/blah",
				"name": "mysql-backend",
			},
		]},
	}

	trace(sprintf("deny count: %v", [count(deny)]))
}

test_allow_authorised_registry {
	count(deny) == 0 with input as {
		"apiVersion": "audit.k8s.io/v1",
		"kind": "Pod",
		"spec": {"containers": [{
			"image": "https://my-approved-registry/hooli.com/nginx",
			"name": "nginx-frontend",
		}]},
	}
}
