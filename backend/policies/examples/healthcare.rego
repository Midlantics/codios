package codios.healthcare

import future.keywords.if
import future.keywords.in

# ── Healthcare / PHI policy ───────────────────────────────────────────────────
# Actions that access patient data require the contract to declare
# data_classification = "phi" in resource_limits.
# Payload logging is always forbidden for PHI-classified contracts.
#
# Compliance: HIPAA minimum necessary rule, EU AI Act data minimization.

default allow_patient_access = false
default block_logging = false

phi_classified if {
    input.contract.resource_limits.data_classification == "phi"
}

# Any action containing "patient" requires explicit PHI classification
allow_patient_access if {
    phi_classified
    contains(input.action, "patient")
}

# Block patient data access without PHI flag
block_action if {
    contains(input.action, "patient")
    not phi_classified
}

block_action if {
    contains(input.action, "medical_record")
    not phi_classified
}

# Forbid payload logging (audit.payload_hash is still OK, but raw payload storage is not)
block_logging if {
    phi_classified
}

# PHI contracts expire in at most 1 hour regardless of contract TTL
stale_phi_contract if {
    phi_classified
    issued_ns := time.parse_rfc3339_ns(input.contract.issued_at)
    now_ns := time.now_ns()
    age_minutes := (now_ns - issued_ns) / 60000000000
    age_minutes > 60
}

block_action if {
    stale_phi_contract
    contains(input.action, "patient")
}
