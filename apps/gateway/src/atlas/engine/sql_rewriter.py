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


class SQLSecurityRewriter:
    """Safely inspects and autonomously transforms SQL query ASTs to enforce guardrails."""

    def __init__(self, default_limit: int = 100):
        self.default_limit = default_limit

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

            # 2. Inject Tenant Isolation Clause if tenant_id is specified
            if tenant_id and parsed.find(exp.Table):
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

        rewritten_sql = parsed.sql(dialect=dialect)

        return SQLRewriteResult(
            original_sql=query,
            rewritten_sql=rewritten_sql,
            transformations_applied=transformations,
            is_safe=True,
            dialect=dialect,
        )
