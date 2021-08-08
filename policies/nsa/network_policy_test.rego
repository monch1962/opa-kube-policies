package kubernetes.nsa.validating.pod_security

test_accept_all_required_policies_defined {
	not deny with input as {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {
			"name": "test-network-policy",
			"namespace": "default",
		},
		"spec": {
			"egress": [{
				"ports": [{
					"port": 5978,
					"protocol": "TCP",
				}],
				"to": [{"ipBlock": {"cidr": "10.0.0.0/24"}}],
			}],
			"ingress": [{
				"from": [
					{"ipBlock": {
						"cidr": "172.17.0.0/16",
						"except": ["172.17.1.0/24"],
					}},
					{"namespaceSelector": {"matchLabels": {"project": "myproject"}}},
					{"podSelector": {"matchLabels": {"role": "frontend"}}},
				],
				"ports": [{
					"port": 6379,
					"protocol": "TCP",
				}],
			}],
			"podSelector": {"matchLabels": {"role": "db"}},
			"policyTypes": [
				"Ingress",
				"Egress",
			],
		},
	}
}

test_deny_missing_network_policy {
	deny with input as {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {
			"name": "test-network-policy",
			"namespace": "default",
		},
		"spec": {
			"egress": [{
				"ports": [{
					"port": 5978,
					"protocol": "TCP",
				}],
				"to": [{"ipBlock": {"cidr": "10.0.0.0/24"}}],
			}],
			"ingress": [{
				"from": [
					{"ipBlock": {
						"cidr": "172.17.0.0/16",
						"except": ["172.17.1.0/24"],
					}},
					{"namespaceSelector": {"matchLabels": {"project": "myproject"}}},
					{"podSelector": {"matchLabels": {"role": "frontend"}}},
				],
				"ports": [{
					"port": 6379,
					"protocol": "TCP",
				}],
			}],
			"podSelector": {"matchLabels": {"role": "db"}},
		},
	}
}

test_deny_missing_egress_policy {
	deny with input as {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {
			"name": "test-network-policy",
			"namespace": "default",
		},
		"spec": {
			"ingress": [{
				"from": [
					{"ipBlock": {
						"cidr": "172.17.0.0/16",
						"except": ["172.17.1.0/24"],
					}},
					{"namespaceSelector": {"matchLabels": {"project": "myproject"}}},
					{"podSelector": {"matchLabels": {"role": "frontend"}}},
				],
				"ports": [{
					"port": 6379,
					"protocol": "TCP",
				}],
			}],
			"podSelector": {"matchLabels": {"role": "db"}},
			"policyTypes": [
				"Ingress",
				"Egress",
			],
		},
	}
}

test_deny_missing_egress_ports_section {
	deny with input as {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {
			"name": "test-network-policy",
			"namespace": "default",
		},
		"spec": {
			"egress": [{"to": [{"ipBlock": {"cidr": "10.0.0.0/24"}}]}],
			"ingress": [{
				"from": [
					{"ipBlock": {
						"cidr": "172.17.0.0/16",
						"except": ["172.17.1.0/24"],
					}},
					{"namespaceSelector": {"matchLabels": {"project": "myproject"}}},
					{"podSelector": {"matchLabels": {"role": "frontend"}}},
				],
				"ports": [{
					"port": 6379,
					"protocol": "TCP",
				}],
			}],
			"podSelector": {"matchLabels": {"role": "db"}},
			"policyTypes": [
				"Ingress",
				"Egress",
			],
		},
	}
}

test_deny_missing_egress_port_definition {
	deny with input as {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {
			"name": "test-network-policy",
			"namespace": "default",
		},
		"spec": {
			"egress": [{
				"ports": [{"protocol": "TCP"}],
				"to": [{"ipBlock": {"cidr": "10.0.0.0/24"}}],
			}],
			"ingress": [{
				"from": [
					{"ipBlock": {
						"cidr": "172.17.0.0/16",
						"except": ["172.17.1.0/24"],
					}},
					{"namespaceSelector": {"matchLabels": {"project": "myproject"}}},
					{"podSelector": {"matchLabels": {"role": "frontend"}}},
				],
				"ports": [{
					"port": 6379,
					"protocol": "TCP",
				}],
			}],
			"podSelector": {"matchLabels": {"role": "db"}},
			"policyTypes": [
				"Ingress",
				"Egress",
			],
		},
	}
}

test_deny_missing_egress_port_protocol {
	deny with input as {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {
			"name": "test-network-policy",
			"namespace": "default",
		},
		"spec": {
			"egress": [{
				"ports": [{"port": 5978}],
				"to": [{"ipBlock": {"cidr": "10.0.0.0/24"}}],
			}],
			"ingress": [{
				"from": [
					{"ipBlock": {
						"cidr": "172.17.0.0/16",
						"except": ["172.17.1.0/24"],
					}},
					{"namespaceSelector": {"matchLabels": {"project": "myproject"}}},
					{"podSelector": {"matchLabels": {"role": "frontend"}}},
				],
				"ports": [{
					"port": 6379,
					"protocol": "TCP",
				}],
			}],
			"podSelector": {"matchLabels": {"role": "db"}},
			"policyTypes": [
				"Ingress",
				"Egress",
			],
		},
	}
}

test_deny_missing_egress_to_section {
	deny with input as {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {
			"name": "test-network-policy",
			"namespace": "default",
		},
		"spec": {
			"egress": [{"ports": [{
				"port": 5978,
				"protocol": "TCP",
			}]}],
			"ingress": [{
				"from": [
					{"ipBlock": {
						"cidr": "172.17.0.0/16",
						"except": ["172.17.1.0/24"],
					}},
					{"namespaceSelector": {"matchLabels": {"project": "myproject"}}},
					{"podSelector": {"matchLabels": {"role": "frontend"}}},
				],
				"ports": [{
					"port": 6379,
					"protocol": "TCP",
				}],
			}],
			"podSelector": {"matchLabels": {"role": "db"}},
			"policyTypes": [
				"Ingress",
				"Egress",
			],
		},
	}
}

test_deny_missing_ingress_policy {
	deny with input as {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {
			"name": "test-network-policy",
			"namespace": "default",
		},
		"spec": {
			"egress": [{
				"ports": [{
					"port": 5978,
					"protocol": "TCP",
				}],
				"to": [{"ipBlock": {"cidr": "10.0.0.0/24"}}],
			}],
			"podSelector": {"matchLabels": {"role": "db"}},
			"policyTypes": [
				"Ingress",
				"Egress",
			],
		},
	}
}

test_deny_missing_ingress_section {
	deny with input as {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {
			"name": "test-network-policy",
			"namespace": "default",
		},
		"spec": {
			"egress": [{
				"ports": [{
					"port": 5978,
					"protocol": "TCP",
				}],
				"to": [{"ipBlock": {"cidr": "10.0.0.0/24"}}],
			}],
			"podSelector": {"matchLabels": {"role": "db"}},
			"policyTypes": [
				"Ingress",
				"Egress",
			],
		},
	}
}

test_deny_missing_ingress_from_section {
	deny with input as {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {
			"name": "test-network-policy",
			"namespace": "default",
		},
		"spec": {
			"egress": [{
				"ports": [{
					"port": 5978,
					"protocol": "TCP",
				}],
				"to": [{"ipBlock": {"cidr": "10.0.0.0/24"}}],
			}],
			"ingress": [{"ports": [{
				"port": 6379,
				"protocol": "TCP",
			}]}],
			"podSelector": {"matchLabels": {"role": "db"}},
			"policyTypes": [
				"Ingress",
				"Egress",
			],
		},
	}
}

test_deny_missing_ingress_port {
	deny with input as {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {
			"name": "test-network-policy",
			"namespace": "default",
		},
		"spec": {
			"egress": [{
				"ports": [{
					"port": 5978,
					"protocol": "TCP",
				}],
				"to": [{"ipBlock": {"cidr": "10.0.0.0/24"}}],
			}],
			"ingress": [{
				"from": [
					{"ipBlock": {
						"cidr": "172.17.0.0/16",
						"except": ["172.17.1.0/24"],
					}},
					{"namespaceSelector": {"matchLabels": {"project": "myproject"}}},
					{"podSelector": {"matchLabels": {"role": "frontend"}}},
				],
				"ports": [{"protocol": "TCP"}],
			}],
			"podSelector": {"matchLabels": {"role": "db"}},
			"policyTypes": [
				"Ingress",
				"Egress",
			],
		},
	}
}

test_deny_missing_ingress_protocol {
	deny with input as {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {
			"name": "test-network-policy",
			"namespace": "default",
		},
		"spec": {
			"egress": [{
				"ports": [{
					"port": 5978,
					"protocol": "TCP",
				}],
				"to": [{"ipBlock": {"cidr": "10.0.0.0/24"}}],
			}],
			"ingress": [{
				"from": [
					{"ipBlock": {
						"cidr": "172.17.0.0/16",
						"except": ["172.17.1.0/24"],
					}},
					{"namespaceSelector": {"matchLabels": {"project": "myproject"}}},
					{"podSelector": {"matchLabels": {"role": "frontend"}}},
				],
				"ports": [{"port": 6379}],
			}],
			"podSelector": {"matchLabels": {"role": "db"}},
			"policyTypes": [
				"Ingress",
				"Egress",
			],
		},
	}
}
