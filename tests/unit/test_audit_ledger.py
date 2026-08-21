"""
Unit tests for the tamper-evident cryptographic audit ledger.
"""

import json
from pathlib import Path

from atlas.audit.ledger import AuditLedger
from atlas.models import DecisionOutcome


def test_hash_chain_integrity(tmp_path: Path):
    log_file = tmp_path / "test_audit.jsonl"
    ledger = AuditLedger(log_file=log_file)

    # Record 3 receipts
    r1 = ledger.record_decision(
        trace_id="tr_1",
        user_id="user_1",
        tenant_id="tenant_a",
        agent_id="agent_1",
        agent_role="analyst",
        tool_name="sql_query",
        arguments={"query": "SELECT 1"},
        decision=DecisionOutcome.ALLOW,
        policy_name="atlas.authz.allow",
    )

    r2 = ledger.record_decision(
        trace_id="tr_2",
        user_id="user_2",
        tenant_id="tenant_a",
        agent_id="agent_2",
        agent_role="analyst",
        tool_name="sql_query",
        arguments={"query": "DROP TABLE users"},
        decision=DecisionOutcome.DENY,
        policy_name="atlas.sql.drop_block",
        violation_reasons=["Destructive SQL"],
    )

    assert r1.prev_hash == ledger.genesis_hash
    assert r2.prev_hash == r1.current_hash

    # Verify ledger integrity
    valid, count, msg = ledger.verify_ledger()
    assert valid is True
    assert count == 2


def test_tampering_detection(tmp_path: Path):
    log_file = tmp_path / "test_audit_tampered.jsonl"
    ledger = AuditLedger(log_file=log_file)

    # Record 2 receipts
    ledger.record_decision(
        trace_id="tr_1",
        user_id="user_1",
        tenant_id="tenant_a",
        agent_id="agent_1",
        agent_role="analyst",
        tool_name="sql_query",
        arguments={"query": "SELECT 1"},
        decision=DecisionOutcome.ALLOW,
        policy_name="atlas.authz.allow",
    )
    ledger.record_decision(
        trace_id="tr_2",
        user_id="user_2",
        tenant_id="tenant_a",
        agent_id="agent_2",
        agent_role="analyst",
        tool_name="sql_query",
        arguments={"query": "SELECT 2"},
        decision=DecisionOutcome.ALLOW,
        policy_name="atlas.authz.allow",
    )

    # Tamper with the first line in the log file (modify argument payload)
    lines = []
    with open(log_file, encoding="utf-8") as f:
        for line in f:
            lines.append(json.loads(line))

    # Alter data
    lines[0]["arguments"] = {"query": "SELECT * FROM hacked"}

    with open(log_file, "w", encoding="utf-8") as f:
        for item in lines:
            f.write(json.dumps(item) + "\n")

    # Re-verify ledger
    valid, count, msg = ledger.verify_ledger()
    assert valid is False
    assert "Tampering detected" in msg or "Hash mismatch" in msg


def test_tail_truncation_detected_via_checkpoint(tmp_path: Path):
    """Regression: a file truncated to drop its most recent entries is still a
    perfectly valid, self-consistent hash chain from genesis to wherever it was
    cut -- the forward walk alone cannot detect this. The sidecar checkpoint must."""
    log_file = tmp_path / "test_audit_truncated.jsonl"
    ledger = AuditLedger(log_file=log_file)

    for i in range(5):
        ledger.record_decision(
            trace_id=f"tr_{i}",
            user_id="user_1",
            tenant_id="tenant_a",
            agent_id="agent_1",
            agent_role="analyst",
            tool_name="sql_query",
            arguments={"query": f"SELECT {i}"},
            decision=DecisionOutcome.ALLOW,
            policy_name="atlas.authz.allow",
        )

    valid, count, msg = ledger.verify_ledger()
    assert valid is True
    assert count == 5

    # Drop the last 2 receipts. The remaining 3 lines are still an internally
    # consistent chain starting from genesis.
    with open(log_file, encoding="utf-8") as f:
        lines = f.readlines()
    with open(log_file, "w", encoding="utf-8") as f:
        f.writelines(lines[:3])

    # Simulate a fresh process (e.g. `atlas verify-audit`) reading the tampered file.
    reloaded = AuditLedger(log_file=log_file)
    valid, count, msg = reloaded.verify_ledger()
    assert valid is False
    assert "tampering" in msg.lower() or "deleted" in msg.lower()


def test_signed_checkpoint_rejects_forged_checkpoint(tmp_path: Path, monkeypatch):
    """With ATLAS_AUDIT_HMAC_SECRET set, an attacker with filesystem write access to
    both files but not the secret cannot forge a checkpoint that passes verification."""
    monkeypatch.setenv("ATLAS_AUDIT_HMAC_SECRET", "test-secret-for-unit-tests-only")
    log_file = tmp_path / "test_audit_signed.jsonl"
    ledger = AuditLedger(log_file=log_file)
    ledger.record_decision(
        trace_id="tr_1",
        user_id="u",
        tenant_id="t",
        agent_id="a",
        agent_role="analyst",
        tool_name="sql_query",
        arguments={"query": "SELECT 1"},
        decision=DecisionOutcome.ALLOW,
        policy_name="atlas.authz.allow",
    )
    valid, _, _ = ledger.verify_ledger()
    assert valid is True

    forged = {"last_hash": ledger._last_hash, "count": ledger._count, "hmac": "0" * 64}
    with open(str(log_file) + ".checkpoint", "w", encoding="utf-8") as f:
        json.dump(forged, f)

    valid, _, msg = ledger.verify_ledger()
    assert valid is False
    assert "signature" in msg.lower()
