package kubernetes.nsa.validating.encryption_configuration

test_not_deny_with_kms_encryption_defined {
	count(deny) == 0 with input as {
		"apiVersion": "apiserver.config.k8s.io/v1",
		"kind": "EncryptionConfiguration",
		"resources": [
			{"resources": ["secrets"]},
			{"providers": [
				{
					"cachesize": 100,
					"endpoint": "unix://tmp/socketfile.sock",
					"kms": null,
					"name": "myKMSPlugin",
					"timeout": "3s",
				},
				{"aescbc": {"keys": [{
					"name": "key1",
					"secret": "<base64 encoded secret>",
				}]}},
			]},
		],
	}
}

test_deny_with_kms_encryption_missing {
	deny with input as {
		"apiVersion": "apiserver.config.k8s.io/v1",
		"kind": "EncryptionConfiguration",
		"resources": [
			{"resources": ["secrets"]},
			{"providers": []},
		],
	}
}
