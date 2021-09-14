package kubernetes.general.container_registry

# Link to OPA Playground to play with this policy: https://play.openpolicyagent.org/p/KZm2TBblQK

test_unauthorised_registry_blocked {
	count(deny) == 3 with input as {
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
			"image": "my-registry/hooli.com/nginx",
			"name": "nginx-frontend",
		}]},
	}
}

test_allow_deploy_from_authorised_registry {
	count(deny) == 0 with input as {
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"metadata": {"name": "hello-kubernetes"},
		"spec": {"template": {"spec": {"containers": [{
			"name": "hello-kubernetes",
			"image": "my-registry/hello-kubernetes:1.5",
		}]}}},
	}
}

test_deny_deploy_from_unauthorised_registry {
	count(deny) == 1 with input as {
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"metadata": {"name": "hello-kubernetes"},
		"spec": {"template": {"spec": {"containers": [{
			"name": "hello-kubernetes",
			"image": "unapproved-registry/hello-kubernetes:1.5",
		}]}}},
	}
}
