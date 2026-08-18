"""
Core data models for Atlas AI Agent Security Control Plane.
"""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DecisionOutcome(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    STEP_UP_REQUIRED = "STEP_UP_REQUIRED"
    SANITIZE = "SANITIZE"


class UserIdentity(BaseModel):
    user_id: str
    tenant_id: str = "default"
    roles: list[str] = Field(default_factory=lambda: ["user"])
    scopes: list[str] = Field(default_factory=list)
    delegation_token: str | None = None


class AgentIdentity(BaseModel):
    agent_id: str
    role: str = "analyst"
    spiffe_id: str | None = None
    allowed_tools: list[str] = Field(default_factory=list)
    denied_tools: list[str] = Field(default_factory=list)


class SessionState(BaseModel):
    session_id: str
    step_count: int = 1
    total_tokens_consumed: int = 0
    tool_calls_per_minute: int = 0
    step_up_approved: bool = False


class SecurityTaxonomyMapping(BaseModel):
    atlas_technique: str | None = None
    atlas_name: str | None = None
    owasp_category: str | None = None
    owasp_name: str | None = None
    nist_control: str | None = None
    reason: str


class PolicyDecision(BaseModel):
    outcome: DecisionOutcome
    allowed: bool
    policy_name: str
    reasons: list[str] = Field(default_factory=list)
    mapping: SecurityTaxonomyMapping | None = None
    modified_args: dict[str, Any] | None = None


class ToolInvocation(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    tool_call_id: str | None = None


class AuditReceipt(BaseModel):
    receipt_id: str
    trace_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    user_id: str
    tenant_id: str
    agent_id: str
    agent_role: str
    tool_name: str
    arguments: dict[str, Any]
    decision: DecisionOutcome
    policy_name: str
    violation_reasons: list[str] = Field(default_factory=list)
    taxonomy: SecurityTaxonomyMapping | None = None
    prev_hash: str
    current_hash: str
