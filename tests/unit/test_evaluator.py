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
    assert "SSRF attempt" in decision.reasons[0]


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


def test_blocked_absolute_path_etc_passwd():
    """Phase 1.1: Absolute path /etc/passwd (no ..) must be blocked."""
    evaluator = PolicyEvaluator()
    user = UserIdentity(user_id="bob", scopes=["read_file:execute"])
    agent = AgentIdentity(agent_id="reader_1", role="analyst")
    session = SessionState(session_id="s1")

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="read_file",
        args={"path": "/etc/passwd"},
        session=session,
    )

    assert decision.allowed is False
    assert decision.outcome == DecisionOutcome.DENY


def test_blocked_absolute_path_windows():
    """Phase 1.1: Windows absolute path outside sandbox must be blocked."""
    evaluator = PolicyEvaluator()
    user = UserIdentity(user_id="bob", scopes=["read_file:execute"])
    agent = AgentIdentity(agent_id="reader_1", role="analyst")
    session = SessionState(session_id="s1")

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="read_file",
        args={"path": "C:\\Windows\\System32\\config\\SAM"},
        session=session,
    )

    assert decision.allowed is False
    assert decision.outcome == DecisionOutcome.DENY


def test_allowed_file_in_workspace():
    """Phase 1.1: File within workspace_root must be ALLOWED."""
    evaluator = PolicyEvaluator(workspace_root="C:/Users/samue")
    user = UserIdentity(user_id="bob", scopes=["read_file:execute"])
    agent = AgentIdentity(agent_id="reader_1", role="analyst")
    session = SessionState(session_id="s1")

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="read_file",
        args={"path": "C:/Users/samue/Atlas/README.md"},
        session=session,
    )

    assert decision.allowed is True
    assert decision.outcome == DecisionOutcome.ALLOW


def test_blocked_filepath_arg_key():
    """Phase 1.1: filepath arg key (not just path) must be caught."""
    evaluator = PolicyEvaluator()
    user = UserIdentity(user_id="bob", scopes=["read_file:execute"])
    agent = AgentIdentity(agent_id="reader_1", role="analyst")
    session = SessionState(session_id="s1")

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="read_file",
        args={"filepath": "/etc/shadow"},
        session=session,
    )

    assert decision.allowed is False
    assert decision.outcome == DecisionOutcome.DENY


def test_blocked_localhost_ssrf():
    """Phase 1.2: http://127.0.0.1 must be blocked."""
    evaluator = PolicyEvaluator()
    user = UserIdentity(user_id="charlie", scopes=["fetch_url:execute"])
    agent = AgentIdentity(agent_id="crawler_1", role="analyst")
    session = SessionState(session_id="s1")

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="fetch_url",
        args={"url": "http://127.0.0.1:8080/admin"},
        session=session,
    )

    assert decision.allowed is False
    assert decision.outcome == DecisionOutcome.DENY
    assert "SSRF attempt" in decision.reasons[0]


def test_blocked_rfc1918_ssrf():
    """Phase 1.2: http://10.0.0.1 (RFC1918) must be blocked."""
    evaluator = PolicyEvaluator()
    user = UserIdentity(user_id="charlie", scopes=["fetch_url:execute"])
    agent = AgentIdentity(agent_id="crawler_1", role="analyst")
    session = SessionState(session_id="s1")

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="fetch_url",
        args={"url": "http://10.0.0.1/internal"},
        session=session,
    )

    assert decision.allowed is False
    assert decision.outcome == DecisionOutcome.DENY
    assert "SSRF attempt" in decision.reasons[0]


def test_blocked_ipv6_loopback_ssrf():
    """Phase 1.2: http://[::1] (IPv6 loopback) must be blocked."""
    evaluator = PolicyEvaluator()
    user = UserIdentity(user_id="charlie", scopes=["fetch_url:execute"])
    agent = AgentIdentity(agent_id="crawler_1", role="analyst")
    session = SessionState(session_id="s1")

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="fetch_url",
        args={"url": "http://[::1]/admin"},
        session=session,
    )

    assert decision.allowed is False
    assert decision.outcome == DecisionOutcome.DENY


def test_allowed_public_url():
    """Phase 1.2: Public URL must be ALLOWED."""
    evaluator = PolicyEvaluator()
    user = UserIdentity(user_id="charlie", scopes=["fetch_url:execute"])
    agent = AgentIdentity(agent_id="crawler_1", role="analyst")
    session = SessionState(session_id="s1")

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="fetch_url",
        args={"url": "https://api.example.com/data"},
        session=session,
    )

    assert decision.allowed is True
    assert decision.outcome == DecisionOutcome.ALLOW
