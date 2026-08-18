package atlas.sql

import future.keywords.in

default allow = false

# Allow SQL query if it only contains allowed operations and touches authorized tables
allow {
    input.tool == "sql_query"
    is_safe_statement_type
    not accesses_forbidden_tables
    not contains_destructive_clauses
}

# Only SELECT statements are permitted for read-only agent contexts
is_safe_statement_type {
    input.ast.statement_type in ["SELECT", "EXPLAIN"]
}

# Block access to confidential tables (e.g. credentials, salary, audit_logs)
accesses_forbidden_tables {
    forbidden_tables := ["credentials", "user_secrets", "salary_records", "audit_ledger", "api_keys"]
    table := input.ast.tables[_]
    table in forbidden_tables
}

# Block destructive keywords even if nested
contains_destructive_clauses {
    dangerous_verbs := ["DROP", "TRUNCATE", "DELETE", "ALTER", "GRANT", "REVOKE", "UPDATE", "INSERT"]
    verb := input.ast.operations[_]
    verb in dangerous_verbs
}

violation_meta = {
    "atlas_technique": "AML.T0086",
    "owasp_category": "ASI02",
    "nist_control": "MANAGE-2.4",
    "reason": "Destructive SQL operation or restricted table access detected via AST inspection"
} {
    not allow
}
