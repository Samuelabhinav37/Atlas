"""
Autonomous SQL AST Security Rewriter using sqlglot.
Enforces automatic query safety limits and tenant isolation without breaking syntax.
"""

from dataclasses import dataclass

import sqlglot
from sqlglot import exp


@dataclass
class SQLRewriteResult:
    original_sql: str
    rewritten_sql: str
    transformations_applied: list[str]
    is_safe: bool
    dialect: str
    blocked_reason: str | None = None


class SQLSecurityRewriter:
    """Safely inspects and autonomously transforms SQL query ASTs to enforce guardrails."""

    def __init__(self, default_limit: int = 100):
        self.default_limit = default_limit

    def _harden_insert(
        self, parsed: exp.Insert, tenant_id: str
    ) -> tuple[list[str], str | None]:
        """Validate/inject the tenant_id column on INSERTs whose column list and
        VALUES tuples we can actually introspect (mutates `parsed` in place).

        Positional INSERTs (no explicit column list) and INSERT...SELECT are
        left untouched -- without real table-schema knowledge there is no
        reliable way to locate or verify a tenant_id value in either shape, and
        silently "fixing" them would be a false sense of security. This is a
        documented gap, not an oversight: see README's SQL AST Inspection bullet.
        """
        transformations: list[str] = []

        schema = parsed.this
        values = parsed.expression
        if not isinstance(schema, exp.Schema) or not isinstance(values, exp.Values):
            return transformations, None

        col_names = [ident.name.lower() for ident in schema.expressions]

        if "tenant_id" in col_names:
            idx = col_names.index("tenant_id")
            for tup in values.expressions:
                val = tup.expressions[idx] if idx < len(tup.expressions) else None
                if isinstance(val, exp.Literal) and str(val.this) == tenant_id:
                    continue
                provided = val.sql() if val is not None else "<missing>"
                return transformations, (
                    f"INSERT specifies tenant_id {provided} which does not match "
                    f"caller's own tenant '{tenant_id}'"
                )
            return transformations, None

        # tenant_id column not present at all -- inject it into both the column
        # list and every VALUES tuple, same "inject when missing" pattern used
        # for the WHERE-clause tenant filter on SELECT/UPDATE/DELETE.
        schema.expressions.append(exp.to_identifier("tenant_id"))
        for tup in values.expressions:
            tup.expressions.append(exp.Literal.string(tenant_id))
        transformations.append(f"injected_tenant_isolation('{tenant_id}')")
        return transformations, None

    def rewrite_and_harden(
        self,
        query: str,
        dialect: str = "postgres",
        tenant_id: str | None = None,
    ) -> SQLRewriteResult:
        """Parse query AST and inject safety limits and optional tenant partition filters."""
        if not query or not query.strip():
            return SQLRewriteResult(
                original_sql=query,
                rewritten_sql=query,
                transformations_applied=[],
                is_safe=True,
                dialect=dialect,
            )

        transformations: list[str] = []

        try:
            parsed = sqlglot.parse_one(query, read=dialect)
        except Exception:
            return SQLRewriteResult(
                original_sql=query,
                rewritten_sql=query,
                transformations_applied=["unparseable_syntax"],
                is_safe=False,
                dialect=dialect,
                blocked_reason="SQL query could not be safely rewritten with guardrails "
                "(dialect-specific parse failure)",
            )

        # 1. Enforce LIMIT on SELECT queries
        if isinstance(parsed, exp.Select):
            limit_exp = parsed.args.get("limit")
            if limit_exp is None:
                parsed = parsed.limit(self.default_limit)
                transformations.append(f"injected_limit({self.default_limit})")
            else:
                try:
                    current_limit = int(limit_exp.expression.this)
                    if current_limit > self.default_limit:
                        parsed = parsed.limit(self.default_limit)
                        transformations.append(f"clamped_limit({current_limit}->{self.default_limit})")
                except Exception:
                    pass

        # 2. Inject Tenant Isolation Clause if tenant_id is specified. This must
        # cover mutating statements (UPDATE/DELETE), not just SELECT -- a tenant-
        # scoped agent issuing a bare "DELETE FROM accounts;" with no WHERE clause
        # is exactly the case tenant isolation exists to stop, and previously fell
        # straight through this rewriter untouched because the check lived inside
        # the `isinstance(parsed, exp.Select)` branch above.
        if tenant_id and isinstance(parsed, (exp.Select, exp.Update, exp.Delete)) and parsed.find(exp.Table):
            tenant_condition = exp.EQ(
                this=exp.Column(this=exp.to_identifier("tenant_id")),
                expression=exp.Literal.string(tenant_id),
            )
            existing_where = parsed.args.get("where")
            if existing_where is None:
                parsed = parsed.where(tenant_condition)
            else:
                parsed = parsed.where(tenant_condition, copy=False)
            transformations.append(f"injected_tenant_isolation('{tenant_id}')")

        # 3. Validate/inject tenant_id on INSERTs we can introspect (explicit
        # column list + VALUES). See _harden_insert for what's out of scope.
        if tenant_id and isinstance(parsed, exp.Insert):
            insert_transforms, blocked_reason = self._harden_insert(parsed, tenant_id)
            if blocked_reason:
                return SQLRewriteResult(
                    original_sql=query,
                    rewritten_sql=query,
                    transformations_applied=[],
                    is_safe=False,
                    dialect=dialect,
                    blocked_reason=blocked_reason,
                )
            transformations.extend(insert_transforms)

        rewritten_sql = parsed.sql(dialect=dialect)

        return SQLRewriteResult(
            original_sql=query,
            rewritten_sql=rewritten_sql,
            transformations_applied=transformations,
            is_safe=True,
            dialect=dialect,
        )
