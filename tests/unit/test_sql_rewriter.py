"""
Unit tests for the autonomous SQL AST Security Rewriter.
"""

from atlas.engine.sql_rewriter import SQLSecurityRewriter


def test_auto_inject_limit():
    rewriter = SQLSecurityRewriter(default_limit=50)
    query = "SELECT id, email FROM users WHERE active = true"
    res = rewriter.rewrite_and_harden(query)

    assert res.is_safe is True
    assert "LIMIT 50" in res.rewritten_sql
    assert any("injected_limit" in t for t in res.transformations_applied)


def test_clamp_excessive_limit():
    rewriter = SQLSecurityRewriter(default_limit=100)
    query = "SELECT * FROM transactions LIMIT 1000000"
    res = rewriter.rewrite_and_harden(query)

    assert res.is_safe is True
    assert "LIMIT 100" in res.rewritten_sql
    assert any("clamped_limit" in t for t in res.transformations_applied)


def test_inject_tenant_isolation():
    rewriter = SQLSecurityRewriter(default_limit=100)
    query = "SELECT * FROM orders WHERE status = 'pending'"
    res = rewriter.rewrite_and_harden(query, tenant_id="tenant_finance")

    assert res.is_safe is True
    assert "tenant_finance" in res.rewritten_sql
    assert any("injected_tenant_isolation" in t for t in res.transformations_applied)


def test_inject_tenant_isolation_on_bare_delete():
    """A DELETE with no WHERE clause must still get a tenant filter injected --
    otherwise a tenant-scoped agent can wipe every tenant's rows in one query."""
    rewriter = SQLSecurityRewriter(default_limit=100)
    res = rewriter.rewrite_and_harden("DELETE FROM accounts", tenant_id="tenant_42")

    assert res.is_safe is True
    assert "tenant_42" in res.rewritten_sql
    assert "WHERE" in res.rewritten_sql
    assert any("injected_tenant_isolation" in t for t in res.transformations_applied)


def test_inject_tenant_isolation_on_update_with_existing_where():
    rewriter = SQLSecurityRewriter(default_limit=100)
    res = rewriter.rewrite_and_harden(
        "UPDATE accounts SET balance = 0 WHERE id = 5", tenant_id="tenant_42"
    )

    assert res.is_safe is True
    assert "tenant_42" in res.rewritten_sql
    assert "id = 5" in res.rewritten_sql
    assert any("injected_tenant_isolation" in t for t in res.transformations_applied)


def test_no_tenant_isolation_injected_without_tenant_id():
    rewriter = SQLSecurityRewriter(default_limit=100)
    res = rewriter.rewrite_and_harden("DELETE FROM accounts", tenant_id=None)

    assert res.is_safe is True
    assert res.rewritten_sql.strip().rstrip(";") == "DELETE FROM accounts"
    assert not any("injected_tenant_isolation" in t for t in res.transformations_applied)
