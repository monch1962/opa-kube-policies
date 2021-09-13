package kubernetes.nsa.validating.pod_security

test_accept_all_important_fields_defined {
	deny with input as {
		"apiVersion": "policy/v1beta1",
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "example"},
		"spec": {
			"fsGroup": {"rule": "RunAsAny"},
			"privileged": false,
			"runAsUser": {"rule": "RunAsAny"},
			"seLinux": {"rule": "RunAsAny"},
			"supplementalGroups": {"rule": "RunAsAny"},
			"volumes": ["*"],
		},
	}
}
