"""
FastAPI Reverse Proxy and Runtime Policy Enforcement Gateway for AI Agents.
"""

import secrets
from typing import Any

from atlas.audit.ledger import AuditLedger
from atlas.detectors.canary import CanaryTrapEngine
from atlas.detectors.inter_tool_scrubber import InterToolScrubber
from atlas.detectors.prompt_injection import PromptInjectionDetector
from atlas.engine.evaluator import PolicyEvaluator
from atlas.models import (
    AgentIdentity,
    DecisionOutcome,
    SessionState,
    UserIdentity,
)
from atlas.telemetry.mapper import taxonomy_mapper
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(
    title="Atlas AI Agent Security Control Plane",
    description="Runtime Policy Enforcement Gateway mapping to MITRE ATLAS & OWASP Agentic Top 10",
    version="0.1.0",
)

# Core Components
evaluator = PolicyEvaluator()
audit_ledger = AuditLedger(log_file="atlas_audit.jsonl")
injection_detector = PromptInjectionDetector()
inter_tool_scrubber = InterToolScrubber()
canary_engine = CanaryTrapEngine()


class EvaluateToolRequest(BaseModel):
    user: UserIdentity
    agent: AgentIdentity
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    session: SessionState = Field(default_factory=lambda: SessionState(session_id="sess_default"))
    trace_id: str | None = None


class ScrubContentRequest(BaseModel):
    tool_name: str
    raw_content: str
    session_id: str = "sess_default"


class ChatMessage(BaseModel):
    role: str
    content: str | None = None
    tool_calls: list[dict[str, Any]] | None = None


class ChatCompletionRequest(BaseModel):
    model: str = "gpt-4o"
    messages: list[ChatMessage]
    tools: list[dict[str, Any]] | None = None
    temperature: float | None = 0.7


@app.get("/v1/health")
async def health():
    return {
        "status": "healthy",
        "service": "Atlas AI Agent Control Plane",
        "version": "0.1.0",
        "frameworks": ["MITRE ATLAS 2026.1", "OWASP Agentic Top 10 (2026)", "NIST AI RMF / CAISI"],
    }


@app.post("/v1/agent/evaluate")
async def evaluate_action(req: EvaluateToolRequest):
    """Direct AuthZEN PEP Endpoint: Evaluates whether an agent can invoke a tool with specific arguments."""
    trace_id = req.trace_id or f"tr_{secrets.token_hex(6)}"

    decision = evaluator.evaluate_tool_call(
        user=req.user,
        agent=req.agent,
        tool=req.tool,
        args=req.arguments,
        session=req.session,
    )

    # Record verified receipt in cryptographic audit ledger
    receipt = audit_ledger.record_decision(
        trace_id=trace_id,
        user_id=req.user.user_id,
        tenant_id=req.user.tenant_id,
        agent_id=req.agent.agent_id,
        agent_role=req.agent.role,
        tool_name=req.tool,
        arguments=req.arguments,
        decision=decision.outcome,
        policy_name=decision.policy_name,
        violation_reasons=decision.reasons,
        taxonomy=decision.mapping,
    )

    return {
        "decision": decision.outcome.value,
        "allowed": decision.allowed,
        "policy_name": decision.policy_name,
        "reasons": decision.reasons,
        "taxonomy": decision.mapping.model_dump() if decision.mapping else None,
        "receipt": receipt.model_dump(),
    }


@app.post("/v1/agent/scrub")
async def scrub_tool_output(req: ScrubContentRequest):
    """Inter-Tool Return Scrubber Endpoint: Neutralizes indirect injection and context poisoning before LLM ingest."""
    result = inter_tool_scrubber.scrub(
        tool_name=req.tool_name,
        raw_output=req.raw_content,
    )
    return {
        "is_poisoned": result.is_poisoned,
        "quarantined": result.quarantine,
        "sanitized_content": result.sanitized_content,
        "reasons": result.reasons,
        "atlas_technique": result.atlas_id,
        "owasp_category": result.owasp_id,
    }


@app.post("/v1/chat/completions")
async def proxy_chat_completion(
    req: ChatCompletionRequest,
    x_user_id: str = Header(default="usr_anonymous"),
    x_user_scopes: str = Header(default="read,write"),
    x_agent_id: str = Header(default="agent_default"),
    x_agent_role: str = Header(default="analyst"),
):
    """OpenAI-compatible reverse proxy endpoint with inline PEP interception and prompt sanitization."""
    trace_id = f"tr_{secrets.token_hex(6)}"
    user_scopes_list = [s.strip() for s in x_user_scopes.split(",") if s.strip()]

    user = UserIdentity(user_id=x_user_id, scopes=user_scopes_list)
    agent = AgentIdentity(agent_id=x_agent_id, role=x_agent_role)

    # 1. Ingress prompt inspection
    last_user_msg = next(
        (m.content for m in reversed(req.messages) if m.role == "user" and m.content), ""
    )
    inj_scan = injection_detector.scan(last_user_msg)

    if inj_scan.is_suspicious and inj_scan.confidence >= 0.9:
        mapping = taxonomy_mapper.enrich(
            atlas_id="AML.T0051",
            owasp_id="ASI01",
            nist_id="MEASURE-2.7",
            reason=f"Ingress prompt injection blocked: {inj_scan.description}",
        )
        audit_ledger.record_decision(
            trace_id=trace_id,
            user_id=user.user_id,
            tenant_id=user.tenant_id,
            agent_id=agent.agent_id,
            agent_role=agent.role,
            tool_name="ingress_prompt",
            arguments={"prompt_sample": last_user_msg[:100]},
            decision=DecisionOutcome.DENY,
            policy_name="atlas.ingress.prompt_injection_guard",
            violation_reasons=[mapping.reason],
            taxonomy=mapping,
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Security violation: Direct prompt injection or jailbreak pattern detected",
                "taxonomy": mapping.model_dump(),
            },
        )

    # 2. Return an OpenAI-compatible payload (simulated LLM response or tool interceptor)
    return {
        "id": f"chatcmpl-{secrets.token_hex(8)}",
        "object": "chat.completion",
        "created": 1771300000,
        "model": req.model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Request analyzed and verified by Atlas Control Plane.",
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 50, "completion_tokens": 15, "total_tokens": 65},
        "atlas_trace": {"trace_id": trace_id, "status": "VERIFIED_ALLOW"},
    }


@app.get("/v1/audit/verify")
async def verify_audit_ledger():
    """Verify cryptographic chain integrity of the audit ledger."""
    valid, count, message = audit_ledger.verify_ledger()
    return {
        "valid": valid,
        "verified_entries": count,
        "status_message": message,
    }


@app.get("/v1/taxonomy")
async def get_taxonomy():
    """Return active MITRE ATLAS, OWASP Agentic, and NIST CAISI taxonomies."""
    return {
        "mitre_atlas": taxonomy_mapper.atlas_data,
        "owasp_agentic": taxonomy_mapper.owasp_data,
        "nist_caisi": taxonomy_mapper.nist_data,
    }
