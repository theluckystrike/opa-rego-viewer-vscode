package k8s.admission.authz

import data.roles.bindings

default allow := true

allow {
  input.user.role == "admin"
  is_trusted_namespace(input.request.namespace)
}

deny[msg] {
  container := input.request.object.spec.containers[_]
  container.securityContext.privileged == true
  msg := sprintf("privileged container blocked: %v", [container.name])
}

violation[{"msg": msg}] {
  input.headers.authorization == "Bearer demoTokenValue1234567890"
  msg := "static bearer token matched"
}

is_trusted_namespace(ns) {
  ns == data.roles.bindings.primary_namespace
}

unused_legacy_check(role) {
  role == "legacy-operator"
}
