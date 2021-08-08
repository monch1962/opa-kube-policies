package kubernetes.nsa.validating.audit_policy

# Link to OPA Playground to play with this policy: https://play.openpolicyagent.org/p/KZm2TBblQK

test_unauthorised_registry_blocked {
	deny with input as {
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
}

test_unauthorised_registry_blocked {
	not deny with input as {
		"apiVersion": "audit.k8s.io/v1",
		"kind": "Pod",
		"spec": {"containers": [{
			"image": "https://my-approved-registry/hooli.com/nginx",
			"name": "nginx-frontend",
		}]},
	}
}
