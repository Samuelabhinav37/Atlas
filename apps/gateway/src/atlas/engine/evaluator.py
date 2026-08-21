"""
Policy Decision Point (PDP) evaluating tool-call arguments via native Python rules, AST argument
inspectors, and autonomous rewriters. See policies/*.rego for a parallel Rego/OPA reference
implementation of the same rules — it is not loaded or queried by this module.
Includes Active Deception & Honeypot Trap validation.
"""

import ipaddress
import os
import re
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import urlparse

import sqlglot
from atlas.detectors.canary import CanaryTrapEngine
from atlas.detectors.deobfuscator import RecursiveDeobfuscator
from atlas.detectors.honeypots import HoneypotManager
from atlas.detectors.semantic_invariant import SemanticInvariantChecker
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

# All argument key names that might contain file paths
_PATH_ARG_KEYS = {"path", "filepath", "filename", "file", "src", "dest", "destination", "source", "target"}

# All argument key names that might contain URLs
_URL_ARG_KEYS = {"url", "uri", "endpoint", "address", "webhook_url", "callback_url", "target_url"}

# Expanded filesystem tool names
_FS_TOOLS = {"read_file", "write_file", "delete_file", "copy_file", "move_file", "upload_file", "download_file"}

# Expanded network egress tool names
_NET_TOOLS = {"http_request", "fetch_url", "send_webhook", "api_call", "webhook", "post_request", "get_request"}

# Expanded sensitive file patterns
_SENSITIVE_FILE_PATTERNS = [
    ".env",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_ecdsa.pub",
    "shadow",
    "passwd",
    ".aws/credentials",
    "authorized_keys",
    "known_hosts",
    ".ssh/config",
    ".git/config",
    ".gitconfig",
    ".kube/config",
    "kubeconfig",
    ".docker/config.json",
    ".npmrc",
    ".pypirc",
    "master.key",
    "credentials.json",
    "service_account.json",
    ".htpasswd",
    "wp-config.php",
]

# Private / reserved IP networks for SSRF blocking
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("10.0.0.0/8"),          # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),       # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),      # RFC1918
    ipaddress.ip_network("169.254.0.0/16"),      # Link-local (includes cloud metadata)
    ipaddress.ip_network("0.0.0.0/8"),           # "This" network
    ipaddress.ip_network("::1/128"),             # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),            # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),           # IPv6 link-local
]

# Hostnames that should always be blocked (cloud metadata, localhost aliases)
_BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
}

# Hostname regex for cloud metadata IPs even in non-standard forms
_METADATA_IP_RE = re.compile(r"169\.254\.169\.254|169\.254\.169\.253")


def _is_absolute_any_flavor(path_str: str) -> bool:
    """Detect whether a path string is absolute in either POSIX or Windows syntax.

    Deliberately independent of the host OS: a Windows-style path like
    'C:\\Windows\\System32' must be recognized as absolute even when Atlas runs on
    Linux, and a POSIX path like '/etc/passwd' must be recognized as absolute even
    when Atlas runs on Windows. Using the stdlib `os.path.isabs` here would only
    apply the host OS's own rules and let the other flavor slip through.
    """
    return PureWindowsPath(path_str).is_absolute() or PurePosixPath(path_str).is_absolute()


def _is_private_or_reserved(hostname: str) -> bool:
    """Check if a hostname resolves to a private/reserved IP address."""
    # Check blocked hostnames
    if hostname.lower() in _BLOCKED_HOSTNAMES:
        return True

    # Strip IPv6 brackets
    clean_host = hostname.strip("[]")

    # Try parsing as IP address directly
    try:
        addr = ipaddress.ip_address(clean_host)
        return any(addr in network for network in _BLOCKED_NETWORKS)
    except ValueError:
        pass

    # Check metadata IP pattern in the hostname string
    return bool(_METADATA_IP_RE.search(hostname))


class PolicyEvaluator:
    """Evaluates agent tool requests against authorization policies, AST inspectors, and auto-rewriters."""

    def __init__(self, workspace_root: str | None = None):
        # No sensible cross-machine default exists for a sandbox root, so fall back
        # to an explicit env var and then the current working directory rather than
        # hardcoding any one deployment's path.
        self.workspace_root = workspace_root or os.environ.get("ATLAS_WORKSPACE_ROOT") or os.getcwd()
        self.deobfuscator = RecursiveDeobfuscator()
        self.shell_inspector = ShellASTInspector()
        self.sql_rewriter = SQLSecurityRewriter(default_limit=100)
        self.honeypot_manager = HoneypotManager()
        self.canary_engine = CanaryTrapEngine()
        self.semantic_checker = SemanticInvariantChecker()

    def issue_canary(self, session_id: str, label: str = "secret") -> str:
        """Mint a canary token bound to a session; embed it wherever sensitive
        context is loaded (e.g. a retrieved secret, a confidential document)
        so evaluate_tool_call can detect it reappearing in an outbound call."""
        return self.canary_engine.generate_canary(session_id, label=label)

    def set_session_goal(self, session_id: str, goal: str) -> None:
        """Record a session's original objective so evaluate_tool_call can
        detect a later tool call critically diverging from it (goal-hijack /
        AML.T0057). See the "Goal Drift Check" in evaluate_tool_call."""
        self.semantic_checker.set_session_goal(session_id, goal)

    def _is_path_in_sandbox(self, path_str: str) -> bool:
        """Check if a path is contained within the workspace_root sandbox.

        Path "flavor" (POSIX vs Windows) is determined from the string itself,
        not the host OS, so containment decisions are identical whether Atlas
        is deployed on Linux or Windows.
        """
        windows_abs = PureWindowsPath(path_str).is_absolute()
        posix_abs = PurePosixPath(path_str).is_absolute()

        if windows_abs or posix_abs:
            candidates = []
            if windows_abs:
                candidates.append((PureWindowsPath(path_str), PureWindowsPath(self.workspace_root)))
            if posix_abs:
                candidates.append((PurePosixPath(path_str), PurePosixPath(self.workspace_root)))

            for candidate, root in candidates:
                try:
                    candidate.relative_to(root)
                    return True
                except ValueError:
                    continue
            return False

        # Relative path: resolve against workspace root and check containment.
        # Traversal segments ("..") are already rejected by the caller before
        # this is reached, so a plain prefix join is sufficient here.
        try:
            resolved = PurePosixPath(self.workspace_root) / path_str
            resolved.relative_to(PurePosixPath(self.workspace_root))
            return True
        except (ValueError, TypeError):
            return False

    def _extract_path_args(self, args: dict[str, Any]) -> list[str]:
        """Extract all path-like argument values from args dict."""
        paths = []
        for key in _PATH_ARG_KEYS:
            val = args.get(key)
            if val:
                paths.append(str(val))
        return paths

    def _extract_url_args(self, args: dict[str, Any]) -> list[str]:
        """Extract all URL-like argument values from args dict."""
        urls = []
        for key in _URL_ARG_KEYS:
            val = args.get(key)
            if val:
                urls.append(str(val))
        return urls

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
        step_up_verified: bool = False,
    ) -> PolicyDecision:
        """Run policy decision pipeline against input context with de-obfuscation and AST validation.

        `step_up_verified` must only ever be set True by a caller that has itself
        verified a matching, still-APPROVED StepUpChallenge (see proxy/server.py) --
        it must never be derived from anything the client can set directly, since
        that would let a caller self-approve its own sensitive action.
        """
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

        # 0.5 Canary Token Exfiltration Check. Deliberately runs against every
        # argument value, not just tools flagged as network/exfil-risk -- a
        # canary bound to this session_id reappearing in ANY outbound tool
        # call is itself the signal, regardless of which tool carries it.
        canary_leak = self.canary_engine.check_leak(session.session_id, str(args))
        if canary_leak.leaked:
            mapping = taxonomy_mapper.enrich(
                atlas_id="AML.T0053",
                owasp_id="ASI03",
                nist_id="MEASURE-2.7",
                reason=canary_leak.description,
            )
            return PolicyDecision(
                outcome=DecisionOutcome.DENY,
                allowed=False,
                policy_name="atlas.deception.canary_leak_detected",
                reasons=[mapping.reason],
                mapping=mapping,
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

        # 2.5 Goal Drift Check. Only gates on risk_level == "CRITICAL" (a
        # critical verb -- DROP, shutdown, exfiltrate, etc -- appearing in the
        # action but not the session's stated goal), not on the weaker
        # low-cosine-similarity-only signal (MEDIUM/HIGH with no critical verb).
        # SemanticInvariantChecker's similarity scoring is a crude word/n-gram
        # overlap heuristic, not real semantic understanding -- gating on it
        # alone risks denying legitimate calls that simply don't share much
        # vocabulary with the stated goal. The critical-verb signal is far
        # more precise and is what the red-team DFT-01 probe exercises.
        # check_drift() itself is a cheap no-op (dict lookup, has_drifted=False)
        # when no goal has been tracked for this session_id via set_session_goal().
        drift_res = self.semantic_checker.check_drift(session.session_id, tool, args)
        if drift_res.has_drifted and drift_res.risk_level == "CRITICAL":
            return PolicyDecision(
                outcome=DecisionOutcome.DENY,
                allowed=False,
                policy_name="atlas.invariant.goal_drift_critical",
                reasons=[drift_res.violation_reason or "Critical goal drift detected"],
                mapping=drift_res.taxonomy,
            )

        # 3. Check step-up human-in-the-loop requirement for sensitive tools
        sensitive_tools = [
            "send_email",
            "execute_payment",
            "modify_iam",
            "terminate_instance",
            "drop_db",
        ]
        if tool in sensitive_tools and not step_up_verified:
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
        elif tool in ["sql_query", "execute_sql", "db_query", "query_database", "run_sql"] or "sql" in tool:
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

            # Restrict every role except admin to read-only SQL. This must be an
            # allowlist of the one role trusted with mutations, not a denylist of
            # "analyst" -- a denylist means any other role, including a typo'd or
            # unrecognized one, silently got unrestricted DROP/DELETE/UPDATE/INSERT
            # gated only by the small hardcoded forbidden_tables blocklist below.
            if agent.role != "admin" and ast_info["statement_type"] != "SELECT":
                mapping = taxonomy_mapper.enrich(
                    atlas_id="AML.T0086",
                    owasp_id="ASI02",
                    nist_id="MANAGE-2.4",
                    reason=(
                        f"Agent role '{agent.role}' cannot execute mutating SQL statements "
                        f"({ast_info['statement_type']}); only 'admin' may"
                    ),
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

            # rewrite_and_harden can refuse to harden a query for more than one
            # reason -- a dialect-specific parse failure, or (for INSERT) an
            # explicit tenant_id value that doesn't match the caller's own
            # tenant -- so this must DENY with the specific reason it gave
            # rather than ALLOW with a query that was never actually hardened.
            if not rewrite_res.is_safe:
                mapping = taxonomy_mapper.enrich(
                    atlas_id="AML.T0086",
                    owasp_id="ASI02",
                    nist_id="MANAGE-2.4",
                    reason=rewrite_res.blocked_reason
                    or "SQL query could not be safely rewritten with guardrails",
                )
                return PolicyDecision(
                    outcome=DecisionOutcome.DENY,
                    allowed=False,
                    policy_name="atlas.sql.rewrite_failed",
                    reasons=[mapping.reason],
                    mapping=mapping,
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
        elif tool in _FS_TOOLS:
            raw_paths = self._extract_path_args(args)
            if not raw_paths:
                raw_paths = [str(args.get("path", ""))]

            for raw_path in raw_paths:
                if not raw_path:
                    continue
                deob_path = self.deobfuscator.normalize(raw_path).normalized_text

                # Path traversal check on normalized string
                if ".." in deob_path:
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

                # Sandbox containment: absolute paths must be under workspace_root
                if _is_absolute_any_flavor(deob_path) and not self._is_path_in_sandbox(deob_path):
                    mapping = taxonomy_mapper.enrich(
                        atlas_id="AML.T0086",
                        owasp_id="ASI05",
                        nist_id="MANAGE-2.4",
                        reason=f"Path '{raw_path}' is outside sandbox workspace root '{self.workspace_root}'",
                    )
                    return PolicyDecision(
                        outcome=DecisionOutcome.DENY,
                        allowed=False,
                        policy_name="atlas.fs.sandbox_escape",
                        reasons=[mapping.reason],
                        mapping=mapping,
                    )

                # Sensitive file patterns
                for pattern in _SENSITIVE_FILE_PATTERNS:
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

        # D. Network Egress Tools (Hardened SSRF Guard)
        elif tool in _NET_TOOLS:
            raw_urls = self._extract_url_args(args)
            if not raw_urls:
                raw_urls = [str(args.get("url", ""))]

            for raw_url in raw_urls:
                if not raw_url:
                    continue
                deob_url = self.deobfuscator.normalize(raw_url).normalized_text

                # Parse URL to extract hostname
                try:
                    parsed = urlparse(deob_url)
                    hostname = parsed.hostname or ""
                except Exception:
                    hostname = ""

                # Check hostname against private/reserved ranges
                if hostname and _is_private_or_reserved(hostname):
                    mapping = taxonomy_mapper.enrich(
                        atlas_id="AML.T0086",
                        owasp_id="ASI02",
                        nist_id="MANAGE-2.4",
                        reason=f"SSRF attempt targeting private/reserved address: {hostname}",
                    )
                    return PolicyDecision(
                        outcome=DecisionOutcome.DENY,
                        allowed=False,
                        policy_name="atlas.egress.ssrf_private_network_block",
                        reasons=[mapping.reason],
                        mapping=mapping,
                    )

                # Also check raw URL string for metadata IPs (catches non-standard URL formats)
                if _METADATA_IP_RE.search(deob_url):
                    mapping = taxonomy_mapper.enrich(
                        atlas_id="AML.T0086",
                        owasp_id="ASI02",
                        nist_id="MANAGE-2.4",
                        reason="SSRF attempt targeting cloud instance metadata service",
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
