"""
Canary token generator and trap detection engine for data leak prevention.
Hardened with deobfuscation, case-insensitive matching, and fragment detection.
"""

import re
import secrets
from dataclasses import dataclass

from atlas.detectors.deobfuscator import RecursiveDeobfuscator


@dataclass
class CanaryLeakResult:
    leaked: bool
    canary_token: str | None
    description: str


# Characters commonly used to fragment/split tokens for evasion
_FRAGMENT_STRIP_RE = re.compile(r"[\s\u200b\u200c\u200d\ufeff]")


class CanaryTrapEngine:
    """Manages active session canary tokens and checks if agents attempt to leak them."""

    def __init__(self, prefix: str = "ATLAS-CANARY"):
        self.prefix = prefix
        self._active_canaries: dict[str, set[str]] = {}  # session_id -> set of canaries
        self._deobfuscator = RecursiveDeobfuscator()

    def generate_canary(self, session_id: str, label: str = "secret") -> str:
        """Generate and track a unique canary token for a session."""
        random_suffix = secrets.token_hex(6).upper()
        token = f"{self.prefix}-{label.upper()}-{random_suffix}"
        if session_id not in self._active_canaries:
            self._active_canaries[session_id] = set()
        self._active_canaries[session_id].add(token)
        return token

    def check_leak(self, session_id: str, text: str) -> CanaryLeakResult:
        """Inspect outbound text or tool arguments for active canary tokens.

        Applies deobfuscation, case-insensitive matching, and fragment detection
        to catch encoded/split/obfuscated canary exfiltration attempts.
        """
        if not text or session_id not in self._active_canaries:
            return CanaryLeakResult(leaked=False, canary_token=None, description="No canary present")

        # Deobfuscate the outbound text (decode base64, URL encoding, hex, unicode)
        normalized_text = self._deobfuscator.normalize(text).normalized_text

        # Prepare stripped version for fragment detection (remove spaces, zero-width chars)
        stripped_text = _FRAGMENT_STRIP_RE.sub("", normalized_text).upper()

        for token in self._active_canaries[session_id]:
            token_upper = token.upper()
            stripped_token = _FRAGMENT_STRIP_RE.sub("", token_upper)

            # 1. Literal match on original text
            if token in text:
                return CanaryLeakResult(
                    leaked=True,
                    canary_token=token,
                    description=f"Canary token '{token}' detected in outbound payload (Exfiltration attempt)",
                )

            # 2. Case-insensitive match on deobfuscated text
            if token_upper in normalized_text.upper():
                return CanaryLeakResult(
                    leaked=True,
                    canary_token=token,
                    description=f"Canary token '{token}' detected after deobfuscation (Encoded exfiltration attempt)",
                )

            # 3. Fragment detection (stripped of whitespace/zero-width chars)
            if stripped_token in stripped_text:
                return CanaryLeakResult(
                    leaked=True,
                    canary_token=token,
                    description=f"Canary token '{token}' detected as fragmented exfiltration attempt",
                )

        return CanaryLeakResult(leaked=False, canary_token=None, description="Clean")

    def clear_session(self, session_id: str):
        """Remove canaries when session ends."""
        self._active_canaries.pop(session_id, None)
