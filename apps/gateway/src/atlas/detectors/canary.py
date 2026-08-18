"""
Canary token generator and trap detection engine for data leak prevention.
"""

import secrets
from dataclasses import dataclass


@dataclass
class CanaryLeakResult:
    leaked: bool
    canary_token: str | None
    description: str


class CanaryTrapEngine:
    """Manages active session canary tokens and checks if agents attempt to leak them."""

    def __init__(self, prefix: str = "ATLAS-CANARY"):
        self.prefix = prefix
        self._active_canaries: dict[str, set[str]] = {}  # session_id -> set of canaries

    def generate_canary(self, session_id: str, label: str = "secret") -> str:
        """Generate and track a unique canary token for a session."""
        random_suffix = secrets.token_hex(6).upper()
        token = f"{self.prefix}-{label.upper()}-{random_suffix}"
        if session_id not in self._active_canaries:
            self._active_canaries[session_id] = set()
        self._active_canaries[session_id].add(token)
        return token

    def check_leak(self, session_id: str, text: str) -> CanaryLeakResult:
        """Inspect outbound text or tool arguments for active canary tokens."""
        if not text or session_id not in self._active_canaries:
            return CanaryLeakResult(
                leaked=False, canary_token=None, description="No canary present"
            )

        for token in self._active_canaries[session_id]:
            if token in text:
                return CanaryLeakResult(
                    leaked=True,
                    canary_token=token,
                    description=f"Canary token '{token}' detected in outbound payload (Exfiltration attempt)",
                )

        return CanaryLeakResult(leaked=False, canary_token=None, description="Clean")

    def clear_session(self, session_id: str):
        """Remove canaries when session ends."""
        self._active_canaries.pop(session_id, None)
