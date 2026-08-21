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


def test_insert_with_spoofed_tenant_id_is_blocked():
    """An INSERT that explicitly names a tenant_id column and writes a value
    for a *different* tenant than the caller must be blocked, not silently
    allowed through -- otherwise a tenant-scoped caller can inject rows
    attributed to any other tenant it likes."""
    rewriter = SQLSecurityRewriter(default_limit=100)
    res = rewriter.rewrite_and_harden(
        "INSERT INTO orders (tenant_id, item) VALUES ('other_tenant', 'stolen_widget')",
        tenant_id="tenant_42",
    )

    assert res.is_safe is False
    assert "other_tenant" in res.blocked_reason
    assert "tenant_42" in res.blocked_reason


def test_insert_with_multirow_spoofed_tenant_id_is_blocked():
    rewriter = SQLSecurityRewriter(default_limit=100)
    res = rewriter.rewrite_and_harden(
        "INSERT INTO orders (tenant_id, item) VALUES ('tenant_42', 'a'), ('other', 'b')",
        tenant_id="tenant_42",
    )

    assert res.is_safe is False
    assert res.blocked_reason is not None


def test_insert_with_matching_tenant_id_is_allowed_unmodified():
    rewriter = SQLSecurityRewriter(default_limit=100)
    res = rewriter.rewrite_and_harden(
        "INSERT INTO orders (tenant_id, item) VALUES ('tenant_42', 'widget')",
        tenant_id="tenant_42",
    )

    assert res.is_safe is True
    assert res.blocked_reason is None
    assert not res.transformations_applied


def test_insert_missing_tenant_id_column_gets_it_injected():
    rewriter = SQLSecurityRewriter(default_limit=100)
    res = rewriter.rewrite_and_harden(
        "INSERT INTO orders (item) VALUES ('widget')",
        tenant_id="tenant_42",
    )

    assert res.is_safe is True
    assert "tenant_42" in res.rewritten_sql
    assert any("injected_tenant_isolation" in t for t in res.transformations_applied)


def test_insert_positional_without_column_list_is_left_untouched():
    """Documented gap: with no explicit column list we can't map VALUES
    positions to columns without table-schema knowledge, so these are left
    as-is rather than guessed at or blocked."""
    rewriter = SQLSecurityRewriter(default_limit=100)
    query = "INSERT INTO orders VALUES ('widget', 'other_tenant')"
    res = rewriter.rewrite_and_harden(query, tenant_id="tenant_42")

    assert res.is_safe is True
    assert res.rewritten_sql.strip().rstrip(";") == query
    assert not res.transformations_applied


def test_insert_select_is_left_untouched():
    """Documented gap: INSERT...SELECT sources its values from a nested query,
    not a literal VALUES tuple, so there's nothing safe to validate/inject."""
    rewriter = SQLSecurityRewriter(default_limit=100)
    query = "INSERT INTO orders (item) SELECT name FROM staging"
    res = rewriter.rewrite_and_harden(query, tenant_id="tenant_42")

    assert res.is_safe is True
    assert not res.transformations_applied
