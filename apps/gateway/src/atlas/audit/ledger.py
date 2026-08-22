"""
Tamper-evident, hash-chained cryptographic audit ledger for AI agent decisions.
"""

import hashlib
import hmac
import json
import os
import secrets
import threading
from pathlib import Path
from typing import Any

from atlas.models import AuditReceipt, DecisionOutcome, SecurityTaxonomyMapping


class AuditLedger:
    """Maintains a cryptographically verifiable append-only ledger of agent actions and policy decisions.

    The forward hash chain alone only proves internal self-consistency of whatever
    lines are currently in the log file -- a file truncated to drop its most recent
    entries is still a perfectly valid chain from genesis to wherever it was cut, so
    truncation is otherwise completely undetectable. A small sidecar checkpoint file
    (last_hash + count, written on every append) closes that gap: verify_ledger()
    cross-checks the log file's actual tail against it. If ATLAS_AUDIT_HMAC_SECRET is
    set, the checkpoint is HMAC-signed, so forging a matching checkpoint requires the
    secret, not just filesystem write access.
    """

    def __init__(self, log_file: Path | str = "atlas_audit.jsonl"):
        self.log_file = Path(log_file)
        self.checkpoint_file = Path(str(self.log_file) + ".checkpoint")
        self.genesis_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        self._hmac_key = os.environ.get("ATLAS_AUDIT_HMAC_SECRET")
        self._last_hash, self._count = self._get_latest_state()
        # record_decision() does blocking file I/O with no `await` inside it, so a single
        # event loop can't interleave two calls mid-write -- but concurrent worker *threads*
        # calling it can race the read-modify-write of _last_hash/_count and fork the chain.
        self._lock = threading.Lock()

    def _get_latest_state(self) -> tuple[str, int]:
        """Read the last hash and total receipt count from disk."""
        if not self.log_file.exists():
            return self.genesis_hash, 0

        last_hash = self.genesis_hash
        count = 0
        try:
            with open(self.log_file, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line.strip())
                        last_hash = data.get("current_hash", last_hash)
                        count += 1
        except Exception:
            return self.genesis_hash, 0
        return last_hash, count

    def _checkpoint_signature(self, last_hash: str, count: int) -> str | None:
        """HMAC-sign the checkpoint state; returns None if no secret is configured."""
        if not self._hmac_key:
            return None
        message = f"{last_hash}:{count}".encode()
        return hmac.new(self._hmac_key.encode(), message, hashlib.sha256).hexdigest()

    def _write_checkpoint(self) -> None:
        """Persist the current (last_hash, count) state, signed if a secret is configured."""
        checkpoint: dict[str, Any] = {"last_hash": self._last_hash, "count": self._count}
        signature = self._checkpoint_signature(self._last_hash, self._count)
        if signature:
            checkpoint["hmac"] = signature

        tmp_path = Path(str(self.checkpoint_file) + ".tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(checkpoint, f)
        tmp_path.replace(self.checkpoint_file)

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

        with self._lock:
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
            self._count += 1
            self._write_checkpoint()
        return receipt

    def _verify_checkpoint(self, final_hash: str, count: int) -> str | None:
        """Cross-check the log file's actual final state against the sidecar checkpoint.

        Returns a violation message if tampering is detected, or None if the
        checkpoint is absent (nothing to check) or matches. This is what catches
        truncation -- the forward hash-chain walk alone cannot, since a truncated
        file is still internally self-consistent from genesis to wherever it was cut.
        """
        if not self.checkpoint_file.exists():
            return None

        try:
            with open(self.checkpoint_file, encoding="utf-8") as f:
                checkpoint = json.load(f)
        except Exception as e:
            return f"Checkpoint file is corrupted or unreadable ({e}) -- cannot rule out tampering"

        checkpoint_hash = checkpoint.get("last_hash")
        checkpoint_count = checkpoint.get("count")

        if self._hmac_key:
            expected_sig = self._checkpoint_signature(checkpoint_hash or "", checkpoint_count or 0)
            if checkpoint.get("hmac") != expected_sig:
                return "Checkpoint signature invalid -- checkpoint does not match ATLAS_AUDIT_HMAC_SECRET"

        if isinstance(checkpoint_count, int) and checkpoint_count > count:
            return (
                f"Ledger tampering detected: checkpoint recorded {checkpoint_count} receipts "
                f"but only {count} are present in the log file -- entries were deleted"
            )
        if checkpoint_hash and checkpoint_hash != final_hash:
            return "Ledger tampering detected: final hash does not match the last known checkpoint"

        return None

    def verify_ledger(self) -> tuple[bool, int, str]:
        """Traverse the log file and verify cryptographic integrity of the entire chain."""
        if not self.log_file.exists():
            checkpoint_violation = self._verify_checkpoint(self.genesis_hash, 0)
            if checkpoint_violation:
                return False, 0, checkpoint_violation
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

        checkpoint_violation = self._verify_checkpoint(expected_prev_hash, count)
        if checkpoint_violation:
            return False, count, checkpoint_violation

        return True, count, f"Ledger verified successfully ({count} valid receipts, 0 tampered)"
