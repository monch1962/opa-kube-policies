package kubernetes.nsa.validating.pod_security

# Link to OPA Playground to play with this policy: https://play.openpolicyagent.org/p/TDi3M1FHCc

operations = {"CREATE", "UPDATE"}

deny[msg] {
	input.kind == PodSecurityPolicy
	not input.spec.privileged.allowPrivilegeEscalation == false

	msg := "Need to prevent pod privilege escalation"
}

deny[msg] {
	input.kind == PodSecurityPolicy
	not input.spec.runAsUser.rule == "MustRunAsNonRoot"

	msg := "Need to set MustRunAsNonRoot for pod"
}

deny[msg] {
	input.kind == PodSecurityPolicy
	not input.SELinux.supplementalGroups.rule == "MustRunAs"

	msg := "Must set SELinux group MustRunAs configuration"
}

deny[msg] {
	input.kind == PodSecurityPolicy
	input.SELinux.supplementalGroups.rule == "MustRunAs"
	not input.SELinux.supplementalGroups.ranges.min >= 1

	msg := "Must change group MustRunAs to something other than 0 (root)"
}

deny[msg] {
	input.kind == PodSecurityPolicy
	not input.SELinux.runAsGroup.rule == "MustRunAs"

	msg := "Must set SELinux group MustRunAs configuration"
}

deny[msg] {
	input.kind == PodSecurityPolicy
	input.SELinux.runAsGroup.rule == "MustRunAs"
	not input.SELinux.runAsGroup.ranges.min >= 1

	msg := "Must change SELinux group MustRun to something other than 0 (root)"
}

deny[msg] {
	input.kind == PodSecurityPolicy
	not input.SELinux.fsGroup.rule == "MustRunAs"

	msg := "Must set a SELinux file system group MustRunAs configuration"
}

deny[msg] {
	input.kind == PodSecurityPolicy
	input.SELinux.fsGroup.rule == "MustRunAs"
	not input.SELinux.fsGroup.ranges.min >= 1

	msg := "Must change SELinux file system group range to something other than 0 (root)"
}
