"""
Inter-Agent Cryptographic Delegation and Swarm Trust Envelope Manager.
Enforces OWASP ASI07 (Insecure Inter-Agent Communication) and ASI08 (Cascading Failures).
"""

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from atlas.models import SecurityTaxonomyMapping
from atlas.telemetry.mapper import taxonomy_mapper


@dataclass
class DelegationVerificationResult:
    is_valid: bool
    allowed_scopes: list[str]
    current_depth: int
    violation_reason: str | None
    taxonomy: SecurityTaxonomyMapping | None = None


class AgentDelegationManager:
    """Manages signed Agent Delegation Tokens (ADT) for multi-agent swarm handoffs."""

    def __init__(self, secret_key: str | None = None, max_cascade_depth: int = 3):
        self.secret_key = (secret_key or secrets.token_hex(32)).encode("utf-8")
        self.max_cascade_depth = max_cascade_depth

    def _sign_payload(self, payload_dict: dict[str, Any]) -> str:
        """Create HMAC-SHA256 signature for canonical delegation payload."""
        canonical = json.dumps(payload_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hmac.new(self.secret_key, canonical, hashlib.sha256).hexdigest()

    def issue_delegation_token(
        self,
        parent_agent_id: str,
        child_agent_id: str,
        human_user_id: str,
        delegated_scopes: list[str],
        current_depth: int = 1,
        ttl_seconds: int = 300,
        metadata: dict[str, Any] | None = None,
        parent_token: str | None = None,
    ) -> str:
        """Create a signed, short-lived Agent Delegation Token (ADT)."""
        # Enforce scope attenuation: child scopes must be subset of parent scopes
        if parent_token:
            try:
                parent_data = json.loads(parent_token)
                parent_scopes = set(parent_data.get("delegated_scopes", []))
                requested_scopes = set(delegated_scopes)
                # admin:all in parent permits any child scope
                if "admin:all" not in parent_scopes:
                    unauthorized = requested_scopes - parent_scopes
                    if unauthorized:
                        raise ValueError(
                            f"Scope escalation denied: {unauthorized} not in parent scopes {parent_scopes}"
                        )
            except json.JSONDecodeError:
                raise ValueError("Invalid parent delegation token format") from None

        now = int(time.time())
        token_data = {
            "token_id": f"adt_{secrets.token_hex(8)}",
            "parent_agent_id": parent_agent_id,
            "child_agent_id": child_agent_id,
            "human_user_id": human_user_id,
            "delegated_scopes": sorted(delegated_scopes),
            "depth": current_depth,
            "issued_at": now,
            "expires_at": now + ttl_seconds,
            "metadata": metadata or {},
        }
        signature = self._sign_payload(token_data)
        token_data["signature"] = signature

        # Return JSON encoded token envelope
        return json.dumps(token_data)

    def verify_delegation(
        self,
        token_str: str,
        target_child_agent_id: str,
        required_scope: str | None = None,
    ) -> DelegationVerificationResult:
        """Verify signature, expiry, depth limits, and scope containment of an ADT."""
        try:
            token_data = json.loads(token_str)
        except Exception:
            mapping = taxonomy_mapper.enrich(
                atlas_id="AML.T0040",
                owasp_id="ASI07",
                nist_id="GOVERN-1.2",
                reason="Malformed or unparseable Agent Delegation Token (ADT)",
            )
            return DelegationVerificationResult(
                is_valid=False,
                allowed_scopes=[],
                current_depth=0,
                violation_reason=mapping.reason,
                taxonomy=mapping,
            )

        signature = token_data.pop("signature", None)
        if not signature:
            mapping = taxonomy_mapper.enrich(
                atlas_id="AML.T0040",
                owasp_id="ASI07",
                nist_id="GOVERN-1.2",
                reason="Unsigned Agent Delegation Token detected",
            )
            return DelegationVerificationResult(
                is_valid=False,
                allowed_scopes=[],
                current_depth=0,
                violation_reason=mapping.reason,
                taxonomy=mapping,
            )

        # 1. Verify HMAC Signature
        expected_sig = self._sign_payload(token_data)
        if not hmac.compare_digest(signature, expected_sig):
            mapping = taxonomy_mapper.enrich(
                atlas_id="AML.T0040",
                owasp_id="ASI07",
                nist_id="GOVERN-1.2",
                reason="Forged or tampered Agent Delegation Token signature",
            )
            return DelegationVerificationResult(
                is_valid=False,
                allowed_scopes=[],
                current_depth=0,
                violation_reason=mapping.reason,
                taxonomy=mapping,
            )

        # 2. Verify Expiration
        now = int(time.time())
        if now > token_data.get("expires_at", 0):
            mapping = taxonomy_mapper.enrich(
                atlas_id="AML.T0040",
                owasp_id="ASI03",
                nist_id="GOVERN-1.2",
                reason="Expired Agent Delegation Token",
            )
            return DelegationVerificationResult(
                is_valid=False,
                allowed_scopes=[],
                current_depth=token_data.get("depth", 1),
                violation_reason=mapping.reason,
                taxonomy=mapping,
            )

        # 3. Verify Cascade Depth (ASI08 Cascading Failure Prevention)
        depth = token_data.get("depth", 1)
        if depth > self.max_cascade_depth:
            mapping = taxonomy_mapper.enrich(
                atlas_id="AML.T0057",
                owasp_id="ASI08",
                nist_id="MANAGE-2.4",
                reason=f"Multi-agent cascade depth limit exceeded ({depth} > {self.max_cascade_depth})",
            )
            return DelegationVerificationResult(
                is_valid=False,
                allowed_scopes=[],
                current_depth=depth,
                violation_reason=mapping.reason,
                taxonomy=mapping,
            )

        # 4. Verify Child Agent Recipient Binding
        expected_child = token_data.get("child_agent_id")
        if expected_child != target_child_agent_id:
            mapping = taxonomy_mapper.enrich(
                atlas_id="AML.T0040",
                owasp_id="ASI07",
                nist_id="GOVERN-1.2",
                reason=f"Agent identity mismatch: token issued for '{expected_child}', used by '{target_child_agent_id}'",
            )
            return DelegationVerificationResult(
                is_valid=False,
                allowed_scopes=[],
                current_depth=depth,
                violation_reason=mapping.reason,
                taxonomy=mapping,
            )

        # 5. Verify Scope Containment
        delegated_scopes = token_data.get("delegated_scopes", [])
        if required_scope and required_scope not in delegated_scopes and "admin:all" not in delegated_scopes:
            mapping = taxonomy_mapper.enrich(
                atlas_id="AML.T0086",
                owasp_id="ASI03",
                nist_id="GOVERN-1.2",
                reason=f"Child agent lacks delegated scope '{required_scope}' from parent agent",
            )
            return DelegationVerificationResult(
                is_valid=False,
                allowed_scopes=delegated_scopes,
                current_depth=depth,
                violation_reason=mapping.reason,
                taxonomy=mapping,
            )

        return DelegationVerificationResult(
            is_valid=True,
            allowed_scopes=delegated_scopes,
            current_depth=depth,
            violation_reason=None,
            taxonomy=None,
        )
