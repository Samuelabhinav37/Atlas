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


def test_sql_denied_when_rewriter_reports_unsafe(monkeypatch):
    """Regression: rewrite_and_harden() re-parses with an explicit postgres dialect,
    which can fail even when the earlier generic-dialect parse succeeded -- when that
    happens rewritten_sql silently falls back to the *unmodified* original query (no
    LIMIT, no tenant isolation), but the evaluator used to return ALLOW anyway without
    ever checking is_safe. Force that condition deterministically via monkeypatch
    rather than hunting for a fragile real dialect-divergent query string."""
    from atlas.engine.sql_rewriter import SQLRewriteResult

    evaluator = PolicyEvaluator()
    user = UserIdentity(user_id="alice", scopes=["sql_query:execute"])
    agent = AgentIdentity(agent_id="analyst_1", role="analyst")
    session = SessionState(session_id="s1")

    def fake_rewrite(self, query, dialect="postgres", tenant_id=None):
        return SQLRewriteResult(
            original_sql=query,
            rewritten_sql=query,
            transformations_applied=["unparseable_syntax"],
            is_safe=False,
            dialect=dialect,
        )

    monkeypatch.setattr(
        "atlas.engine.sql_rewriter.SQLSecurityRewriter.rewrite_and_harden", fake_rewrite
    )

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="sql_query",
        args={"query": "SELECT id FROM employees;"},
        session=session,
    )

    assert decision.allowed is False
    assert decision.outcome == DecisionOutcome.DENY


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


def test_blocked_drop_table_by_non_analyst_non_admin_role():
    """Regression: only 'analyst' used to be restricted to SELECT-only SQL, so any
    other role -- including an operator, or a typo'd/unrecognized role -- got
    unrestricted DROP/DELETE/UPDATE/INSERT gated only by the small hardcoded
    forbidden_tables blocklist. Every role except 'admin' must be read-only."""
    evaluator = PolicyEvaluator()
    user = UserIdentity(user_id="op_bob", scopes=["sql_query:execute"])
    agent = AgentIdentity(agent_id="operator_1", role="operator")
    session = SessionState(session_id="s1")

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="sql_query",
        args={"query": "DROP TABLE orders;"},
        session=session,
    )

    assert decision.allowed is False
    assert decision.outcome == DecisionOutcome.DENY


def test_blocked_drop_table_by_unrecognized_role():
    """A made-up/unrecognized role string must default to read-only, not
    unrestricted -- fail closed, not fail open, for an unknown role."""
    evaluator = PolicyEvaluator()
    user = UserIdentity(user_id="mystery", scopes=["sql_query:execute"])
    agent = AgentIdentity(agent_id="agent_1", role="totally_made_up_role")
    session = SessionState(session_id="s1")

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="sql_query",
        args={"query": "DROP TABLE orders;"},
        session=session,
    )

    assert decision.allowed is False
    assert decision.outcome == DecisionOutcome.DENY


def test_allowed_drop_table_by_admin_role():
    """admin remains the one role trusted with mutating SQL (matching
    tool_authz.rego's is_valid_role_invocation, where admin is unrestricted)."""
    evaluator = PolicyEvaluator()
    user = UserIdentity(user_id="root", scopes=["sql_query:execute"])
    agent = AgentIdentity(agent_id="admin_1", role="admin")
    session = SessionState(session_id="s1")

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="sql_query",
        args={"query": "DROP TABLE orders;"},
        session=session,
    )

    assert decision.allowed is True
    assert decision.outcome == DecisionOutcome.ALLOW


def test_admin_bare_delete_gets_tenant_isolation_injected():
    """Regression: SQLSecurityRewriter only injected the tenant_id WHERE filter
    inside the `isinstance(parsed, exp.Select)` branch, so a mutating statement --
    the one case tenant isolation exists to contain, since admin is the only role
    permitted to run them -- passed through completely unmodified. A tenant-scoped
    admin's bare 'DELETE FROM accounts;' (no WHERE clause) used to be allowed
    through to the real downstream tool call exactly as written, wiping every
    tenant's rows instead of just its own."""
    evaluator = PolicyEvaluator()
    user = UserIdentity(user_id="root", scopes=["sql_query:execute"], tenant_id="tenant_42")
    agent = AgentIdentity(agent_id="admin_1", role="admin")
    session = SessionState(session_id="s1")

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="sql_query",
        args={"query": "DELETE FROM accounts;"},
        session=session,
    )

    assert decision.allowed is True
    assert decision.outcome == DecisionOutcome.ALLOW
    rewritten = decision.modified_args["query"]
    assert "tenant_42" in rewritten
    assert "WHERE" in rewritten


def test_admin_insert_with_spoofed_tenant_id_is_denied():
    """Regression: SQLSecurityRewriter never touched INSERT statements at all,
    so a tenant-scoped admin could write rows explicitly claiming a different
    tenant_id -- e.g. INSERT INTO orders (tenant_id, item) VALUES
    ('other_tenant', 'stolen_widget') -- and it sailed through as ALLOW with
    the spoofed value untouched."""
    evaluator = PolicyEvaluator()
    user = UserIdentity(user_id="root", scopes=["sql_query:execute"], tenant_id="tenant_42")
    agent = AgentIdentity(agent_id="admin_1", role="admin")
    session = SessionState(session_id="s1")

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="sql_query",
        args={
            "query": "INSERT INTO orders (tenant_id, item) VALUES ('other_tenant', 'stolen_widget');"
        },
        session=session,
    )

    assert decision.allowed is False
    assert decision.outcome == DecisionOutcome.DENY
    assert "other_tenant" in decision.reasons[0]


def test_admin_insert_missing_tenant_id_gets_it_injected():
    evaluator = PolicyEvaluator()
    user = UserIdentity(user_id="root", scopes=["sql_query:execute"], tenant_id="tenant_42")
    agent = AgentIdentity(agent_id="admin_1", role="admin")
    session = SessionState(session_id="s1")

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="sql_query",
        args={"query": "INSERT INTO orders (item) VALUES ('widget');"},
        session=session,
    )

    assert decision.allowed is True
    assert "tenant_42" in decision.modified_args["query"]


def test_blocked_rm_wildcard_root_via_execute_command():
    """End-to-end regression for the shell_inspector wildcard bypass: 'rm -rf
    /*' reached the real evaluate_tool_call() as ALLOW before the fix, since
    ShellASTInspector's target check did a string-equality comparison that a
    trailing '*' defeated."""
    evaluator = PolicyEvaluator()
    user = UserIdentity(user_id="alice", scopes=["execute_command:execute"])
    agent = AgentIdentity(agent_id="op_1", role="operator")
    session = SessionState(session_id="s1")

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="execute_command",
        args={"command": "rm -rf /*"},
        session=session,
    )

    assert decision.allowed is False
    assert decision.outcome == DecisionOutcome.DENY


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
    session = SessionState(session_id="s1")

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="execute_payment",
        args={"amount": 1000},
        session=session,
    )

    assert decision.allowed is False
    assert decision.outcome == DecisionOutcome.STEP_UP_REQUIRED


def test_step_up_cannot_be_self_declared_via_session():
    """Regression: step-up must never be satisfiable by anything the caller controls
    directly -- only evaluate_tool_call's own step_up_verified parameter, which the
    caller (server.py) must derive from a genuinely verified approved challenge."""
    evaluator = PolicyEvaluator()
    user = UserIdentity(user_id="dave", scopes=["execute_payment:execute"])
    agent = AgentIdentity(agent_id="operator_1", role="operator")
    session = SessionState(session_id="s1")

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="execute_payment",
        args={"amount": 999999, "recipient": "attacker_account"},
        session=session,
        step_up_verified=False,
    )
    assert decision.outcome == DecisionOutcome.STEP_UP_REQUIRED

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="execute_payment",
        args={"amount": 999999, "recipient": "attacker_account"},
        session=session,
        step_up_verified=True,
    )
    assert decision.allowed is True


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


def test_blocked_unpadded_base64_obfuscated_sensitive_file():
    """Regression: a base64-encoded sensitive filename with no '=' padding and no
    base64/b64/decode hint nearby must still be de-obfuscated and caught."""
    import base64

    evaluator = PolicyEvaluator()
    user = UserIdentity(user_id="bob", scopes=["read_file:execute"])
    agent = AgentIdentity(agent_id="reader_1", role="analyst")
    session = SessionState(session_id="s1")

    encoded = base64.b64encode(b"id_rsa").decode()
    assert not encoded.endswith("="), "test payload must be unpadded to exercise the bug"

    decision = evaluator.evaluate_tool_call(
        user=user,
        agent=agent,
        tool="read_file",
        args={"path": encoded},
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
