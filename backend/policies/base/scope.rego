package codios.scope

import future.keywords.if
import future.keywords.in

# ── Default deny ─────────────────────────────────────────────────────────────

default allow = false
default deny_reason = ""

# ── Main allow rule ───────────────────────────────────────────────────────────
# All conditions must pass. Order of evaluation is declaration order,
# but deny_reason priority is defined explicitly below. 

allow if {
    not expired
    not forbidden
    in_scope
    not over_limit
}

# ── Individual checks ─────────────────────────────────────────────────────────

expired if {
    now_ns := time.now_ns()
    expiry_ns := time.parse_rfc3339_ns(input.contract.expires_at)
    expiry_ns < now_ns
}

forbidden if {
    input.action in input.contract.forbidden_actions
}

in_scope if {
    input.action in input.contract.allowed_actions
}

# If allowed_actions is empty, allow any non-forbidden action
in_scope if {
    count(input.contract.allowed_actions) == 0
}

over_limit if {
    max_calls := input.contract.resource_limits.max_calls
    max_calls != null
    input.calls_used >= max_calls
}

# ── Deny reason (ordered by priority) ────────────────────────────────────────
# Only one reason is returned — the highest-priority one.

deny_reason := "contract_expired"            if { expired }
deny_reason := "action_explicitly_forbidden" if { not expired; forbidden }
deny_reason := "action_not_in_scope"         if { not expired; not forbidden; not in_scope }
deny_reason := "resource_limit_exceeded"     if { not expired; not forbidden; in_scope; over_limit }
