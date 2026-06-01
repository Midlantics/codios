package codios.identity

import future.keywords.if

# ── Agent identity verification ───────────────────────────────────────────────
# The caller's DID must match the issuer DID recorded in the contract. 
# This prevents Agent C from reusing a contract issued to Agent A.

default trusted = false
default has_nonce = false

trusted if {
    input.caller_did != ""
    input.caller_did == input.contract.issuer.did
}

# Nonce presence check — actual uniqueness enforced by Redis SET NX, not OPA.
# Belt-and-suspenders: a contract with an empty nonce is always rejected.
has_nonce if {
    count(input.contract.nonce) > 0
}
