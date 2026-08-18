"""
Policy Decision Point (PDP) evaluating Rego policies, AST argument inspectors, and autonomous rewriters.
Includes Active Deception & Honeypot Trap validation.
"""

from typing import Any

import sqlglot
from atlas.detectors.deobfuscator import RecursiveDeobfuscator
from atlas.detectors.honeypots import HoneypotManager
from atlas.engine.shell_inspector import ShellASTInspector
from atlas.engine.sql_rewriter import SQLSecurityRewriter
from atlas.models import (
    AgentIdentity,
    DecisionOutcome,
    PolicyDecision,
    SessionState,
    UserIdentity,
)
from atlas.telemetry.mapper import taxonomy_mapper
from sqlglot import exp


class PolicyEvaluator:
    """Evaluates agent tool requests against authorization policies, AST inspectors, and auto-rewriters."""

    def __init__(self, workspace_root: str = "C:/Users/samue"):
        self.workspace_root = workspace_root
        self.deobfuscator = RecursiveDeobfuscator()
        self.shell_inspector = ShellASTInspector()
        self.sql_rewriter = SQLSecurityRewriter(default_limit=100)
        self.honeypot_manager = HoneypotManager()

    def _parse_sql_ast(self, query: str) -> dict[str, Any]:
        """Extract statement type, tables, and operations from SQL query AST."""
        try:
            parsed = sqlglot.parse_one(query)
            tables = [table.name.lower() for table in parsed.find_all(exp.Table) if table.name]

            operations = []
            if isinstance(parsed, exp.Select):
                stmt_type = "SELECT"
            elif isinstance(parsed, exp.Insert):
                stmt_type = "INSERT"
                operations.append("INSERT")
            elif isinstance(parsed, exp.Update):
                stmt_type = "UPDATE"
                operations.append("UPDATE")
            elif isinstance(parsed, exp.Delete):
                stmt_type = "DELETE"
                operations.append("DELETE")
            elif isinstance(parsed, exp.Drop):
                stmt_type = "DROP"
                operations.append("DROP")
            elif isinstance(parsed, exp.TruncateTable):
                stmt_type = "TRUNCATE"
                operations.append("TRUNCATE")
            elif isinstance(parsed, exp.AlterTable):
                stmt_type = "ALTER"
                operations.append("ALTER")
            else:
                stmt_type = type(parsed).__name__.upper()

            return {
                "valid": True,
                "statement_type": stmt_type,
                "tables": tables,
                "operations": operations,
            }
        except Exception as e:
            return {
                "valid": False,
                "statement_type": "UNKNOWN",
                "tables": [],
                "operations": ["UNPARSEABLE"],
                "error": str(e),
            }

    def evaluate_tool_call(
        self,
        user: UserIdentity,
        agent: AgentIdentity,
        tool: str,
        args: dict[str, Any],
        session: SessionState,
    ) -> PolicyDecision:
        """Run policy decision pipeline against input context with de-obfuscation and AST validation."""
        # 0. Active Deception / Honeypot Tool Trap Check
        hp_res = self.honeypot_manager.check_trigger(tool, args)
        if hp_res.triggered:
            return PolicyDecision(
                outcome=DecisionOutcome.DENY,
                allowed=False,
                policy_name="atlas.deception.honeypot_tool_trap",
                reasons=[hp_res.violation_reason or "Honeypot tool triggered"],
                mapping=hp_res.taxonomy,
            )

        # 1. Check budget & loop limits
        if session.step_count > 15:
            mapping = taxonomy_mapper.enrich(
                atlas_id="AML.T0057",
                owasp_id="ASI08",
                nist_id="MANAGE-2.4",
                reason=f"Session step limit exceeded (step {session.step_count} > 15)",
            )
            return PolicyDecision(
                outcome=DecisionOutcome.DENY,
                allowed=False,
                policy_name="atlas.budget.step_limit",
                reasons=[mapping.reason],
                mapping=mapping,
            )

        # 2. Check explicitly denied tools for the agent
        if tool in agent.denied_tools:
            mapping = taxonomy_mapper.enrich(
                atlas_id="AML.T0086",
                owasp_id="ASI02",
                nist_id="GOVERN-1.2",
                reason=f"Tool '{tool}' is in agent denied list",
            )
            return PolicyDecision(
                outcome=DecisionOutcome.DENY,
                allowed=False,
                policy_name="atlas.authz.denied_tool",
                reasons=[mapping.reason],
                mapping=mapping,
            )

        # 3. Check step-up human-in-the-loop requirement for sensitive tools
        sensitive_tools = [
            "send_email",
            "execute_payment",
            "modify_iam",
            "terminate_instance",
            "drop_db",
        ]
        if tool in sensitive_tools and not session.step_up_approved:
            mapping = taxonomy_mapper.enrich(
                atlas_id="AML.T0086",
                owasp_id="ASI03",
                nist_id="MANAGE-2.4",
                reason=f"Tool '{tool}' requires Step-Up human-in-the-loop approval token",
            )
            return PolicyDecision(
                outcome=DecisionOutcome.STEP_UP_REQUIRED,
                allowed=False,
                policy_name="atlas.authz.require_step_up",
                reasons=[mapping.reason],
                mapping=mapping,
            )

        # 4. User scope delegation check (OAuth Token Exchange / Scope Bounding)
        required_scope = f"{tool}:execute"
        if required_scope not in user.scopes and "admin:all" not in user.scopes:
            mapping = taxonomy_mapper.enrich(
                atlas_id="AML.T0086",
                owasp_id="ASI03",
                nist_id="GOVERN-1.2",
                reason=f"User identity '{user.user_id}' lacks required scope '{required_scope}'",
            )
            return PolicyDecision(
                outcome=DecisionOutcome.DENY,
                allowed=False,
                policy_name="atlas.authz.user_scope_delegation",
                reasons=[mapping.reason],
                mapping=mapping,
            )

        # 5. Specialized Tool AST & Parameter Guards

        # A. Shell Execution Tool (bashlex AST Inspection)
        if tool in ["execute_command", "bash", "shell", "run_terminal", "exec_cmd"]:
            raw_cmd = str(args.get("command", args.get("cmd", "")))
            shell_res = self.shell_inspector.inspect(raw_cmd)

            if not shell_res.is_safe:
                mapping = taxonomy_mapper.enrich(
                    atlas_id="AML.T0086",
                    owasp_id="ASI05",
                    nist_id="MANAGE-2.4",
                    reason=f"Shell AST security violation: {shell_res.violation_reason}",
                )
                return PolicyDecision(
                    outcome=DecisionOutcome.DENY,
                    allowed=False,
                    policy_name="atlas.shell.ast_execution_guard",
                    reasons=[mapping.reason],
                    mapping=mapping,
                )

        # B. SQL Query Tool (AST parsing & Autonomous Hardening Rewriter)
        elif tool == "sql_query":
            raw_query = args.get("query", "")
            deob_query = self.deobfuscator.normalize(raw_query).normalized_text
            ast_info = self._parse_sql_ast(deob_query)

            if not ast_info["valid"]:
                mapping = taxonomy_mapper.enrich(
                    atlas_id="AML.T0086",
                    owasp_id="ASI02",
                    nist_id="MANAGE-2.4",
                    reason=f"Invalid or unparseable SQL syntax: {ast_info.get('error')}",
                )
                return PolicyDecision(
                    outcome=DecisionOutcome.DENY,
                    allowed=False,
                    policy_name="atlas.sql.invalid_syntax",
                    reasons=[mapping.reason],
                    mapping=mapping,
                )

            # Check Decoy Table Honeypot Trigger
            hp_table_res = self.honeypot_manager.check_trigger(
                tool_name="sql_query",
                arguments=args,
                extracted_tables=ast_info["tables"],
            )
            if hp_table_res.triggered:
                return PolicyDecision(
                    outcome=DecisionOutcome.DENY,
                    allowed=False,
                    policy_name="atlas.deception.decoy_table_trap",
                    reasons=[hp_table_res.violation_reason or "Decoy table trap triggered"],
                    mapping=hp_table_res.taxonomy,
                )

            # Restrict analyst role to SELECT queries
            if agent.role == "analyst" and ast_info["statement_type"] != "SELECT":
                mapping = taxonomy_mapper.enrich(
                    atlas_id="AML.T0086",
                    owasp_id="ASI02",
                    nist_id="MANAGE-2.4",
                    reason=f"Analyst agent role cannot execute mutating SQL statements ({ast_info['statement_type']})",
                )
                return PolicyDecision(
                    outcome=DecisionOutcome.DENY,
                    allowed=False,
                    policy_name="atlas.sql.readonly_enforcement",
                    reasons=[mapping.reason],
                    mapping=mapping,
                )

            # Table whitelist / blacklist inspection
            forbidden_tables = {
                "credentials",
                "user_secrets",
                "salary_records",
                "audit_ledger",
                "api_keys",
            }
            accessed_forbidden = forbidden_tables.intersection(set(ast_info["tables"]))
            if accessed_forbidden:
                mapping = taxonomy_mapper.enrich(
                    atlas_id="AML.T0086",
                    owasp_id="ASI02",
                    nist_id="MANAGE-2.4",
                    reason=f"Access to restricted table(s) forbidden: {', '.join(accessed_forbidden)}",
                )
                return PolicyDecision(
                    outcome=DecisionOutcome.DENY,
                    allowed=False,
                    policy_name="atlas.sql.restricted_table",
                    reasons=[mapping.reason],
                    mapping=mapping,
                )

            # Auto-Rewrite Query (Inject safety LIMIT and tenant isolation)
            tenant_filter = user.tenant_id if user.tenant_id != "default" else None
            rewrite_res = self.sql_rewriter.rewrite_and_harden(
                query=deob_query,
                tenant_id=tenant_filter,
            )

            return PolicyDecision(
                outcome=DecisionOutcome.ALLOW,
                allowed=True,
                policy_name="atlas.sql.allow_and_harden",
                reasons=["SQL AST verified and safely rewritten with guardrails"],
                mapping=None,
                modified_args={"query": rewrite_res.rewritten_sql},
            )

        # C. Filesystem Tools (De-obfuscation & Sandbox containment)
        elif tool in ["read_file", "write_file"]:
            raw_path = str(args.get("path", ""))
            deob_path = self.deobfuscator.normalize(raw_path).normalized_text

            # Path traversal check on normalized string
            if ".." in deob_path or "../" in deob_path or "..\\" in deob_path:
                mapping = taxonomy_mapper.enrich(
                    atlas_id="AML.T0086",
                    owasp_id="ASI05",
                    nist_id="MANAGE-2.4",
                    reason=f"Path traversal detected in requested path '{raw_path}'",
                )
                return PolicyDecision(
                    outcome=DecisionOutcome.DENY,
                    allowed=False,
                    policy_name="atlas.fs.path_traversal",
                    reasons=[mapping.reason],
                    mapping=mapping,
                )

            # Sensitive file extensions or patterns
            sensitive_files = [
                ".env",
                "id_rsa",
                "id_ed25519",
                "shadow",
                "passwd",
                ".aws/credentials",
            ]
            for pattern in sensitive_files:
                if pattern in deob_path.lower():
                    mapping = taxonomy_mapper.enrich(
                        atlas_id="AML.T0086",
                        owasp_id="ASI05",
                        nist_id="MANAGE-2.4",
                        reason=f"Access to sensitive file pattern '{pattern}' is forbidden",
                    )
                    return PolicyDecision(
                        outcome=DecisionOutcome.DENY,
                        allowed=False,
                        policy_name="atlas.fs.sensitive_file_block",
                        reasons=[mapping.reason],
                        mapping=mapping,
                    )

        # D. Network Egress Tools
        elif tool in ["http_request", "fetch_url", "send_webhook"]:
            raw_url = str(args.get("url", ""))
            deob_url = self.deobfuscator.normalize(raw_url).normalized_text

            # Cloud Metadata SSRF guard
            metadata_targets = [
                "169.254.169.254",
                "metadata.google.internal",
                "169.254.169.253",
            ]
            for target in metadata_targets:
                if target in deob_url.lower():
                    mapping = taxonomy_mapper.enrich(
                        atlas_id="AML.T0086",
                        owasp_id="ASI02",
                        nist_id="MANAGE-2.4",
                        reason=f"SSRF attempt targeting cloud instance metadata service: {target}",
                    )
                    return PolicyDecision(
                        outcome=DecisionOutcome.DENY,
                        allowed=False,
                        policy_name="atlas.egress.cloud_metadata_block",
                        reasons=[mapping.reason],
                        mapping=mapping,
                    )

        # All checks passed: ALLOW
        return PolicyDecision(
            outcome=DecisionOutcome.ALLOW,
            allowed=True,
            policy_name="atlas.authz.allow_all_passed",
            reasons=["All action authorization checks and AST constraints satisfied"],
            mapping=None,
        )
