package platform.rbac.strict

import rego.v1

default allow := false

allow if {
  is_allowed_role(input.user.role)
  input.request.method == "GET"
  input.request.namespace == data.config.allowed_namespace
}

deny contains msg if {
  some container in input.request.object.spec.containers
  container.securityContext.privileged == true
  msg := sprintf("privileged container denied: %v", [container.name])
}

is_allowed_role(role) if {
  role in data.config.valid_roles
}
