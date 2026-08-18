"""
Unit tests for Inter-Agent Cryptographic Delegation (ADT).
"""

from atlas.auth.delegation import AgentDelegationManager


def test_issue_and_verify_valid_token():
    manager = AgentDelegationManager()
    token = manager.issue_delegation_token(
        parent_agent_id="planner_bot",
        child_agent_id="coder_bot",
        human_user_id="alice",
        delegated_scopes=["read_file:execute", "sql_query:execute"],
        current_depth=1,
    )

    res = manager.verify_delegation(
        token_str=token,
        target_child_agent_id="coder_bot",
        required_scope="sql_query:execute",
    )

    assert res.is_valid is True
    assert "sql_query:execute" in res.allowed_scopes


def test_reject_unauthorized_child_agent():
    manager = AgentDelegationManager()
    token = manager.issue_delegation_token(
        parent_agent_id="planner_bot",
        child_agent_id="coder_bot",
        human_user_id="alice",
        delegated_scopes=["read_file:execute"],
    )

    # An unauthorized agent tries to use the token
    res = manager.verify_delegation(
        token_str=token,
        target_child_agent_id="rogue_bot",
        required_scope="read_file:execute",
    )

    assert res.is_valid is False
    assert "identity mismatch" in res.violation_reason


def test_reject_unauthorized_scope_elevation():
    manager = AgentDelegationManager()
    token = manager.issue_delegation_token(
        parent_agent_id="planner_bot",
        child_agent_id="coder_bot",
        human_user_id="alice",
        delegated_scopes=["read_file:execute"],  # Only read_file delegated
    )

    # Coder bot tries to execute payment using read-only token
    res = manager.verify_delegation(
        token_str=token,
        target_child_agent_id="coder_bot",
        required_scope="execute_payment:execute",
    )

    assert res.is_valid is False
    assert "Child agent lacks delegated scope" in res.violation_reason


def test_reject_tampered_token_signature():
    manager = AgentDelegationManager()
    token = manager.issue_delegation_token(
        parent_agent_id="planner_bot",
        child_agent_id="coder_bot",
        human_user_id="alice",
        delegated_scopes=["read_file:execute"],
    )

    # Tamper with token payload string
    tampered_token = token.replace("coder_bot", "super_admin")

    res = manager.verify_delegation(
        token_str=tampered_token,
        target_child_agent_id="super_admin",
        required_scope="read_file:execute",
    )

    assert res.is_valid is False
    assert "signature" in res.violation_reason.lower()
