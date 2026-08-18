"""
Unit tests for the Atlas Policy Decision Point (PDP) evaluator.
"""

from atlas.engine.evaluator import PolicyEvaluator
from atlas.models import (
    AgentIdentity,
    DecisionOutcome,
    SessionState,
    UserIdentity,
)


def test_allowed_select_query():
    evaluator = PolicyEvaluator()
    user = UserIdentity(user_id="alice", scopes=["sql_query:execute"])
    agent = AgentIdentity(agent_id="analyst_1", role="analyst")
    session = SessionState(session_id="s1")

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="sql_query",
        args={"query": "SELECT id, name FROM employees WHERE dept = 'Eng';"},
        session=session,
    )

    assert decision.allowed is True
    assert decision.outcome == DecisionOutcome.ALLOW


def test_blocked_drop_table():
    evaluator = PolicyEvaluator()
    user = UserIdentity(user_id="alice", scopes=["sql_query:execute"])
    agent = AgentIdentity(agent_id="analyst_1", role="analyst")
    session = SessionState(session_id="s1")

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="sql_query",
        args={"query": "DROP TABLE employees;"},
        session=session,
    )

    assert decision.allowed is False
    assert decision.outcome == DecisionOutcome.DENY
    assert decision.mapping.atlas_technique == "AML.T0086"
    assert decision.mapping.owasp_category == "ASI02"


def test_blocked_restricted_table():
    evaluator = PolicyEvaluator()
    user = UserIdentity(user_id="alice", scopes=["sql_query:execute"])
    agent = AgentIdentity(agent_id="analyst_1", role="analyst")
    session = SessionState(session_id="s1")

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="sql_query",
        args={"query": "SELECT * FROM salary_records;"},
        session=session,
    )

    assert decision.allowed is False
    assert decision.outcome == DecisionOutcome.DENY
    assert "salary_records" in decision.reasons[0]


def test_blocked_path_traversal():
    evaluator = PolicyEvaluator()
    user = UserIdentity(user_id="bob", scopes=["read_file:execute"])
    agent = AgentIdentity(agent_id="reader_1", role="analyst")
    session = SessionState(session_id="s1")

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="read_file",
        args={"path": "../../etc/shadow"},
        session=session,
    )

    assert decision.allowed is False
    assert decision.outcome == DecisionOutcome.DENY
    assert decision.mapping.owasp_category == "ASI05"


def test_blocked_cloud_metadata_ssrf():
    evaluator = PolicyEvaluator()
    user = UserIdentity(user_id="charlie", scopes=["fetch_url:execute"])
    agent = AgentIdentity(agent_id="crawler_1", role="analyst")
    session = SessionState(session_id="s1")

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="fetch_url",
        args={"url": "http://169.254.169.254/latest/meta-data/"},
        session=session,
    )

    assert decision.allowed is False
    assert decision.outcome == DecisionOutcome.DENY
    assert "cloud instance metadata" in decision.reasons[0]


def test_step_up_challenge():
    evaluator = PolicyEvaluator()
    user = UserIdentity(user_id="dave", scopes=["execute_payment:execute"])
    agent = AgentIdentity(agent_id="operator_1", role="operator")
    session = SessionState(session_id="s1", step_up_approved=False)

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="execute_payment",
        args={"amount": 1000},
        session=session,
    )

    assert decision.allowed is False
    assert decision.outcome == DecisionOutcome.STEP_UP_REQUIRED
