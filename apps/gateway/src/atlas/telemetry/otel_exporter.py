"""
OpenTelemetry (OTel) GenAI Semantic Conventions Exporter for Atlas AI Agent Security.
Conforms to open-telemetry/semantic-conventions-genai (2026 specification).
"""

import secrets
import time
from typing import Any

from atlas.models import AuditReceipt, DecisionOutcome, PolicyDecision


class OTelGenAIExporter:
    """Formats security enforcement events into standard OpenTelemetry GenAI spans."""

    @staticmethod
    def create_span(
        trace_id: str,
        user_id: str,
        tenant_id: str,
        agent_id: str,
        agent_role: str,
        tool_name: str,
        arguments: dict[str, Any],
        decision: PolicyDecision,
        receipt: AuditReceipt | None = None,
        duration_ms: float = 2.5,
    ) -> dict[str, Any]:
        """Generate a compliant OpenTelemetry Span object."""
        span_id = f"span_{secrets.token_hex(8)}"
        start_time_ns = int((time.time() - (duration_ms / 1000.0)) * 1e9)
        end_time_ns = int(time.time() * 1e9)

        # OTel GenAI Semantic Attributes
        attributes: dict[str, Any] = {
            "gen_ai.system": "atlas",
            "gen_ai.operation.name": "tool_authorization",
            "gen_ai.agent.id": agent_id,
            "gen_ai.agent.role": agent_role,
            "gen_ai.tool.name": tool_name,
            "gen_ai.user.id": user_id,
            "gen_ai.tenant.id": tenant_id,
            "security.decision.outcome": decision.outcome.value,
            "security.decision.allowed": decision.allowed,
            "security.policy.name": decision.policy_name,
        }

        if decision.mapping:
            if decision.mapping.atlas_technique:
                attributes["security.atlas.technique"] = decision.mapping.atlas_technique
                attributes["security.atlas.name"] = decision.mapping.atlas_name or ""
            if decision.mapping.owasp_category:
                attributes["security.owasp.category"] = decision.mapping.owasp_category
                attributes["security.owasp.name"] = decision.mapping.owasp_name or ""
            if decision.mapping.nist_control:
                attributes["security.nist.control"] = decision.mapping.nist_control

        if receipt:
            attributes["security.audit.receipt_id"] = receipt.receipt_id
            attributes["security.audit.current_hash"] = receipt.current_hash
            attributes["security.audit.prev_hash"] = receipt.prev_hash

        events = []
        if decision.outcome != DecisionOutcome.ALLOW:
            events.append(
                {
                    "name": "security_violation",
                    "timestamp_ns": end_time_ns,
                    "attributes": {
                        "violation.reasons": decision.reasons,
                        "violation.policy": decision.policy_name,
                    },
                }
            )

        return {
            "trace_id": trace_id,
            "span_id": span_id,
            "name": f"atlas.tool_authz.{tool_name}",
            "kind": "SPAN_KIND_INTERNAL",
            "start_time_unix_nano": start_time_ns,
            "end_time_unix_nano": end_time_ns,
            "attributes": attributes,
            "events": events,
            "status": {
                "code": "STATUS_CODE_OK" if decision.allowed else "STATUS_CODE_ERROR",
                "description": ", ".join(decision.reasons) if not decision.allowed else "Authorized",
            },
        }
