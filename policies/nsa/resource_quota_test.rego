package kubernetes.nsa.validating.resource_quota

test_accept_all_important_resource_quotas_defined {
	not deny with input as {
		"apiVersion": "v1",
		"kind": "ResourceQuota",
		"metadata": {"name": "compute-resources"},
		"spec": {"hard": {
			"limits.cpu": "2",
			"limits.memory": "2Gi",
			"requests.cpu": "1",
			"requests.memory": "1Gi",
			"requests.nvidia.com/gpu": 4,
		}},
	}
}

test_deny_cpu_limits_missing {
	deny with input as {
		"apiVersion": "v1",
		"kind": "ResourceQuota",
		"metadata": {"name": "compute-resources"},
		"spec": {"hard": {
			"limits.memory": "2Gi",
			"requests.cpu": "1",
			"requests.memory": "1Gi",
			"requests.nvidia.com/gpu": 4,
		}},
	}
}

test_deny_limits_memory_missing {
	deny with input as {
		"apiVersion": "v1",
		"kind": "ResourceQuota",
		"metadata": {"name": "compute-resources"},
		"spec": {"hard": {
			"limits.cpu": "2",
			"requests.cpu": "1",
			"requests.memory": "1Gi",
			"requests.nvidia.com/gpu": 4,
		}},
	}
}

test_deny_requests_cpu_missing {
	deny with input as {
		"apiVersion": "v1",
		"kind": "ResourceQuota",
		"metadata": {"name": "compute-resources"},
		"spec": {"hard": {
			"limits.cpu": "2",
			"limits.memory": "2Gi",
			"requests.memory": "1Gi",
			"requests.nvidia.com/gpu": 4,
		}},
	}
}

test_deny_requests_memory_missing {
	not deny with input as {
		"apiVersion": "v1",
		"kind": "ResourceQuota",
		"metadata": {"name": "compute-resources"},
		"spec": {"hard": {
			"limits.cpu": "2",
			"limits.memory": "2Gi",
			"requests.cpu": "1",
			"requests.nvidia.com/gpu": 4,
		}},
	}
}
