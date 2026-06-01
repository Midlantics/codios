package codios.finance

import future.keywords.if
import future.keywords.in

# ── Finance policy ────────────────────────────────────────────────────────────
# High-value transfer actions require an explicit "high_value_transfer" capability
# in the contract's allowed_actions list. This prevents a general "transfer"
# permission from authorizing wire transfers or withdrawals over a threshold.
# 
# Usage: combine with base/scope.rego — this policy adds an extra check on top.

default allow_transfer = false
default block_action = false

# High-value transfer requires explicit capability flag
allow_transfer if {
    "high_value_transfer" in input.contract.allowed_actions
    input.action in {"transfer", "withdraw", "wire", "send_funds"}
}

# Block transfer-family actions without the explicit flag
block_action if {
    contains(input.action, "transfer")
    not allow_transfer
}

block_action if {
    contains(input.action, "withdraw")
    not allow_transfer
}

block_action if {
    contains(input.action, "wire")
    not allow_transfer
}

# Contracts older than 15 minutes cannot authorize financial actions
stale_contract if {
    issued_ns := time.parse_rfc3339_ns(input.contract.issued_at)
    now_ns := time.now_ns()
    age_minutes := (now_ns - issued_ns) / 60000000000
    age_minutes > 15
}

block_action if {
    input.action in {"transfer", "withdraw", "wire", "send_funds", "payment"}
    stale_contract
}
