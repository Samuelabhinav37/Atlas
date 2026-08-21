"""
Model Context Protocol (MCP) JSON-RPC Security Interceptor and Gateway.
Enforces runtime least-agency policies (via the Python PDP) and inter-tool scrubbing on MCP tool calls.
"""

import secrets
from typing import Any

from atlas.audit.ledger import AuditLedger
from atlas.detectors.inter_tool_scrubber import InterToolScrubber
from atlas.engine.evaluator import PolicyEvaluator
from atlas.models import (
    AgentIdentity,
    DecisionOutcome,
    SessionState,
    UserIdentity,
)


class MCPProxyInterceptor:
    """Intercepts, evaluates, and audits Model Context Protocol (MCP) JSON-RPC 2.0 messages."""

    def __init__(
        self,
        evaluator: PolicyEvaluator | None = None,
        scrubber: InterToolScrubber | None = None,
        audit_ledger: AuditLedger | None = None,
    ):
        self.evaluator = evaluator or PolicyEvaluator()
        self.scrubber = scrubber or InterToolScrubber()
        self.audit_ledger = audit_ledger or AuditLedger()

    def process_request(
        self,
        json_rpc_msg: dict[str, Any],
        user: UserIdentity | None = None,
        agent: AgentIdentity | None = None,
        session: SessionState | None = None,
    ) -> tuple[bool, dict[str, Any] | None]:
        """
        Intercepts outgoing client requests to the MCP server.
        Returns: (proceed_to_server: bool, blocked_response_if_any: dict | None)
        """
        method = json_rpc_msg.get("method")
        msg_id = json_rpc_msg.get("id")
        params = json_rpc_msg.get("params", {})

        # Default identities if not explicitly supplied
        user = user or UserIdentity(user_id="mcp_client_user", scopes=["sql_query:execute", "read_file:execute"])
        agent = agent or AgentIdentity(agent_id="mcp_agent", role="analyst")
        session = session or SessionState(session_id=f"mcp_sess_{secrets.token_hex(4)}")

        # Only tools/call requires policy authorization
        if method != "tools/call":
            return True, None

        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        trace_id = f"mcp_{secrets.token_hex(6)}"

        decision = self.evaluator.evaluate_tool_call(
            user=user,
            agent=agent,
            tool=tool_name,
            args=arguments,
            session=session,
        )

        # Record receipt in audit ledger
        self.audit_ledger.record_decision(
            trace_id=trace_id,
            user_id=user.user_id,
            tenant_id=user.tenant_id,
            agent_id=agent.agent_id,
            agent_role=agent.role,
            tool_name=tool_name,
            arguments=arguments,
            decision=decision.outcome,
            policy_name=decision.policy_name,
            violation_reasons=decision.reasons,
            taxonomy=decision.mapping,
        )

        if decision.outcome != DecisionOutcome.ALLOW:
            # Construct MCP JSON-RPC 2.0 Error Response
            error_response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32001,
                    "message": f"Atlas Security Control Plane Blocked Action: {', '.join(decision.reasons)}",
                    "data": {
                        "policy": decision.policy_name,
                        "decision": decision.outcome.value,
                        "atlas_technique": decision.mapping.atlas_technique if decision.mapping else None,
                        "owasp_category": decision.mapping.owasp_category if decision.mapping else None,
                        "reasons": decision.reasons,
                    },
                },
            }
            return False, error_response

        # Inject hardened/rewritten arguments back into the JSON-RPC message
        if decision.modified_args:
            json_rpc_msg.setdefault("params", {})["arguments"] = decision.modified_args

        return True, None

    def process_response(
        self,
        tool_name: str,
        response_msg: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Intercepts tool execution results returning from the MCP server.
        Scans and sanitizes output for indirect prompt injections and secrets before returning to LLM.
        """
        result = response_msg.get("result", {})
        content_items = result.get("content", [])

        sanitized_items = []
        for item in content_items:
            if item.get("type") == "text":
                raw_text = item.get("text", "")
                scrub_res = self.scrubber.scrub(tool_name=tool_name, raw_output=raw_text)
                sanitized_items.append(
                    {
                        "type": "text",
                        "text": scrub_res.sanitized_content,
                        "atlas_quarantined": scrub_res.quarantine,
                    }
                )
            else:
                sanitized_items.append(item)

        response_msg["result"]["content"] = sanitized_items
        return response_msg
