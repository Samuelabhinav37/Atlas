"""
Tamper-evident, hash-chained cryptographic audit ledger for AI agent decisions.
"""

import hashlib
import json
import secrets
from pathlib import Path
from typing import Any

from atlas.models import AuditReceipt, DecisionOutcome, SecurityTaxonomyMapping


class AuditLedger:
    """Maintains a cryptographically verifiable append-only ledger of agent actions and policy decisions."""

    def __init__(self, log_file: Path | str = "atlas_audit.jsonl"):
        self.log_file = Path(log_file)
        self.genesis_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        self._last_hash = self._get_latest_hash()

    def _get_latest_hash(self) -> str:
        """Read the last hash from disk or return genesis hash."""
        if not self.log_file.exists():
            return self.genesis_hash

        last_line = ""
        try:
            with open(self.log_file, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        last_line = line.strip()
            if last_line:
                data = json.loads(last_line)
                return data.get("current_hash", self.genesis_hash)
        except Exception:
            return self.genesis_hash
        return self.genesis_hash

    def _compute_hash(self, prev_hash: str, payload: dict[str, Any]) -> str:
        """Compute SHA-256 hash chaining previous hash with deterministic canonical JSON payload."""
        canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        combined = f"{prev_hash}:{canonical_json}".encode()
        return hashlib.sha256(combined).hexdigest()

    def record_decision(
        self,
        trace_id: str,
        user_id: str,
        tenant_id: str,
        agent_id: str,
        agent_role: str,
        tool_name: str,
        arguments: dict[str, Any],
        decision: DecisionOutcome,
        policy_name: str,
        violation_reasons: list[str] | None = None,
        taxonomy: SecurityTaxonomyMapping | None = None,
    ) -> AuditReceipt:
        """Append a new verified step receipt to the ledger."""
        receipt_id = f"rcpt_{secrets.token_hex(8)}"
        violation_reasons = violation_reasons or []

        payload_for_hashing = {
            "receipt_id": receipt_id,
            "trace_id": trace_id,
            "user_id": user_id,
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "agent_role": agent_role,
            "tool_name": tool_name,
            "arguments": arguments,
            "decision": decision.value,
            "policy_name": policy_name,
            "violation_reasons": violation_reasons,
            "taxonomy": taxonomy.model_dump() if taxonomy else None,
        }

        prev_hash = self._last_hash
        current_hash = self._compute_hash(prev_hash, payload_for_hashing)

        receipt = AuditReceipt(
            receipt_id=receipt_id,
            trace_id=trace_id,
            user_id=user_id,
            tenant_id=tenant_id,
            agent_id=agent_id,
            agent_role=agent_role,
            tool_name=tool_name,
            arguments=arguments,
            decision=decision,
            policy_name=policy_name,
            violation_reasons=violation_reasons,
            taxonomy=taxonomy,
            prev_hash=prev_hash,
            current_hash=current_hash,
        )

        # Write to JSONL
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(receipt.model_dump_json() + "\n")

        self._last_hash = current_hash
        return receipt

    def verify_ledger(self) -> tuple[bool, int, str]:
        """Traverse the log file and verify cryptographic integrity of the entire chain."""
        if not self.log_file.exists():
            return True, 0, "Ledger is empty (valid)"

        expected_prev_hash = self.genesis_hash
        count = 0

        with open(self.log_file, encoding="utf-8") as f:
            for idx, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line.strip())
                except Exception as e:
                    return False, idx, f"Corrupted JSON on line {idx}: {e}"

                # 1. Verify prev_hash link
                actual_prev_hash = entry.get("prev_hash")
                if actual_prev_hash != expected_prev_hash:
                    return (
                        False,
                        idx,
                        f"Hash chain broken at line {idx}! Expected prev_hash {expected_prev_hash[:12]}..., found {actual_prev_hash[:12]}...",
                    )

                # 2. Recompute hash
                payload = {
                    "receipt_id": entry["receipt_id"],
                    "trace_id": entry["trace_id"],
                    "user_id": entry["user_id"],
                    "tenant_id": entry["tenant_id"],
                    "agent_id": entry["agent_id"],
                    "agent_role": entry["agent_role"],
                    "tool_name": entry["tool_name"],
                    "arguments": entry["arguments"],
                    "decision": entry["decision"],
                    "policy_name": entry["policy_name"],
                    "violation_reasons": entry["violation_reasons"],
                    "taxonomy": entry.get("taxonomy"),
                }
                computed_hash = self._compute_hash(actual_prev_hash, payload)
                if computed_hash != entry.get("current_hash"):
                    return (
                        False,
                        idx,
                        f"Tampering detected at line {idx}! Hash mismatch. Payload modified.",
                    )

                expected_prev_hash = entry["current_hash"]
                count += 1

        return True, count, f"Ledger verified successfully ({count} valid receipts, 0 tampered)"
