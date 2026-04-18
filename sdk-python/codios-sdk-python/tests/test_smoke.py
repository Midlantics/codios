"""Smoke tests — no external dependencies, run in CI."""
import pytest
from codios import generate_keypair, verify_contract, issue_contract, encode_contract, decode_contract


def _platform_keys():
    return generate_keypair()


def test_generate_keypair():
    kp = generate_keypair()
    assert kp["did"].startswith("did:key:z6Mk")
    assert len(kp["public_key"]) > 10
    assert len(kp["private_key"]) > 10


def test_issue_and_verify():
    platform = _platform_keys()
    agent_a = generate_keypair()
    agent_b = generate_keypair()

    contract = issue_contract(
        issuer_agent_id="agt_a",
        issuer_did=agent_a["did"],
        target_agent_id="agt_b",
        target_did=agent_b["did"],
        allowed_actions=["transfer", "read"],
        codios_private_key=platform["private_key"],
    )

    result = verify_contract(contract, platform["public_key"], action="transfer")
    assert result.valid
    assert result.payload is not None


def test_encode_decode_roundtrip():
    platform = _platform_keys()
    agent_a = generate_keypair()
    agent_b = generate_keypair()

    contract = issue_contract(
        issuer_agent_id="agt_a",
        issuer_did=agent_a["did"],
        target_agent_id="agt_b",
        target_did=agent_b["did"],
        allowed_actions=["summarize"],
        codios_private_key=platform["private_key"],
    )
    encoded = encode_contract(contract)
    decoded = decode_contract(encoded)

    result = verify_contract(encoded, platform["public_key"])
    assert result.valid
    assert decoded["contract_id"] == contract["contract_id"]


def test_wrong_key_fails():
    platform = _platform_keys()
    other = _platform_keys()
    agent_a = generate_keypair()
    agent_b = generate_keypair()

    contract = issue_contract(
        issuer_agent_id="agt_a",
        issuer_did=agent_a["did"],
        target_agent_id="agt_b",
        target_did=agent_b["did"],
        allowed_actions=["read"],
        codios_private_key=platform["private_key"],
    )
    result = verify_contract(contract, other["public_key"])
    assert not result.valid
    assert result.reason == "invalid_signature"


def test_action_not_allowed():
    platform = _platform_keys()
    agent_a = generate_keypair()
    agent_b = generate_keypair()

    contract = issue_contract(
        issuer_agent_id="agt_a",
        issuer_did=agent_a["did"],
        target_agent_id="agt_b",
        target_did=agent_b["did"],
        allowed_actions=["read"],
        codios_private_key=platform["private_key"],
    )
    result = verify_contract(contract, platform["public_key"], action="delete")
    assert not result.valid
    assert result.reason == "action_not_allowed"


def test_forbidden_action():
    platform = _platform_keys()
    agent_a = generate_keypair()
    agent_b = generate_keypair()

    contract = issue_contract(
        issuer_agent_id="agt_a",
        issuer_did=agent_a["did"],
        target_agent_id="agt_b",
        target_did=agent_b["did"],
        allowed_actions=["read", "write"],
        forbidden_actions=["delete"],
        codios_private_key=platform["private_key"],
    )
    result = verify_contract(contract, platform["public_key"], action="delete")
    assert not result.valid
    assert result.reason == "action_not_allowed"


def test_missing_contract():
    platform = _platform_keys()
    result = verify_contract("", platform["public_key"])
    assert not result.valid
    assert result.reason == "missing"
