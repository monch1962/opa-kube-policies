package library.kubernetes.util.validating.customer_specific

# approved_container_registries should contain a set of regexes to match acceptable Docker registries for Kubernetes pods
approved_container_registries := ["^nginx$", "^https://my-approved-registry/"]
