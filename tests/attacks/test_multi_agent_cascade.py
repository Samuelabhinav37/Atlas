"""
Adversarial Attack Simulation: Multi-Agent Swarm Cascades & Spoofing.
Tests protection against OWASP ASI07 (Insecure Inter-Agent Comm) and ASI08 (Cascading Failures).
"""

from atlas.auth.delegation import AgentDelegationManager


def test_swarm_cascade_depth_circuit_breaker():
    """Adversary triggers recursive agent swarm cascade exceeding max depth (ASI08)."""
    manager = AgentDelegationManager(max_cascade_depth=3)

    # Agent 1 -> Agent 2 (depth 1)
    t1 = manager.issue_delegation_token("agent_1", "agent_2", "user_1", ["sql_query:execute"], current_depth=1)
    res1 = manager.verify_delegation(t1, "agent_2")
    assert res1.is_valid is True

    # Agent 2 -> Agent 3 (depth 2)
    t2 = manager.issue_delegation_token("agent_2", "agent_3", "user_1", ["sql_query:execute"], current_depth=2)
    res2 = manager.verify_delegation(t2, "agent_3")
    assert res2.is_valid is True

    # Agent 3 -> Agent 4 (depth 3)
    t3 = manager.issue_delegation_token("agent_3", "agent_4", "user_1", ["sql_query:execute"], current_depth=3)
    res3 = manager.verify_delegation(t3, "agent_4")
    assert res3.is_valid is True

    # Agent 4 -> Agent 5 (depth 4: EXCEEDS LIMIT -> BLOCKED)
    t4 = manager.issue_delegation_token("agent_4", "agent_5", "user_1", ["sql_query:execute"], current_depth=4)
    res4 = manager.verify_delegation(t4, "agent_5")

    assert res4.is_valid is False
    assert res4.taxonomy.owasp_category == "ASI08"
    assert res4.taxonomy.atlas_technique == "AML.T0057"
    assert "depth limit exceeded" in res4.violation_reason


def test_spoofed_inter_agent_handoff():
    """Adversary injects a fake unverified delegation instruction between agents (ASI07)."""
    manager = AgentDelegationManager()

    # Fake forged token
    fake_token = (
        '{"parent_agent_id": "trusted_root", "child_agent_id": "target_agent", "delegated_scopes": ["admin:all"]}'
    )

    res = manager.verify_delegation(fake_token, "target_agent")
    assert res.is_valid is False
    assert res.taxonomy.owasp_category == "ASI07"
    assert "Unsigned" in res.violation_reason or "signature" in res.violation_reason.lower()
