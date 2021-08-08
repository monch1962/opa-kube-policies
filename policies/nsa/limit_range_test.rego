package kubernetes.nsa.validating.limit_range

test_accept_all_important_limits_defined {
	not deny with input as {
		"apiVersion": "v1",
		"kind": "LimitRange",
		"metadata": {"name": "cpu-min-max-demo-lr"},
		"spec": {"limits": [{
			"default": {"cpu": 1},
			"defaultRequest": {"cpu": 0.5},
			"max": {"cpu": 2},
			"min": {"cpu": 0.5},
			"type": "Container",
		}]},
	}
}

test_deny_missing_default_cpu {
	deny with input as {
		"apiVersion": "v1",
		"kind": "LimitRange",
		"metadata": {"name": "cpu-min-max-demo-lr"},
		"spec": {"limits": [{
			"defaultRequest": {"cpu": 0.5},
			"max": {"cpu": 2},
			"min": {"cpu": 0.5},
			"type": "Container",
		}]},
	}
}

test_deny_missing_defaultrequest_cpu {
	deny with input as {
		"apiVersion": "v1",
		"kind": "LimitRange",
		"metadata": {"name": "cpu-min-max-demo-lr"},
		"spec": {"limits": [{
			"default": {"cpu": 1},
			"max": {"cpu": 2},
			"min": {"cpu": 0.5},
			"type": "Container",
		}]},
	}
}

test_deny_missing_max_cpu {
	deny with input as {
		"apiVersion": "v1",
		"kind": "LimitRange",
		"metadata": {"name": "cpu-min-max-demo-lr"},
		"spec": {"limits": [{
			"default": {"cpu": 1},
			"defaultRequest": {"cpu": 0.5},
			"min": {"cpu": 0.5},
			"type": "Container",
		}]},
	}
}

test_deny_missing_min_cpu {
	deny with input as {
		"apiVersion": "v1",
		"kind": "LimitRange",
		"metadata": {"name": "cpu-min-max-demo-lr"},
		"spec": {"limits": [{
			"default": {"cpu": 1},
			"defaultRequest": {"cpu": 0.5},
			"max": {"cpu": 1},
			"type": "Container",
		}]},
	}
}

test_deny_missing_container_type {
	deny with input as {
		"apiVersion": "v1",
		"kind": "LimitRange",
		"metadata": {"name": "cpu-min-max-demo-lr"},
		"spec": {"limits": [{
			"default": {"cpu": 1},
			"defaultRequest": {"cpu": 0.5},
			"max": {"cpu": 2},
			"min": {"cpu": 0.5},
		}]},
	}
}
