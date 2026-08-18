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
