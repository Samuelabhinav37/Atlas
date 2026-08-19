"""
Inter-tool scrubber that intercepts data returning from tools and RAG before re-entry into LLM context.
Protects against MITRE ATLAS AML.T0054 (Context Poisoning) and OWASP ASI06 (Memory Poisoning).
"""

import re
from dataclasses import dataclass

from atlas.detectors.deobfuscator import RecursiveDeobfuscator
from atlas.detectors.prompt_injection import PromptInjectionDetector
from atlas.detectors.secret_scrubber import SecretScrubber


@dataclass
class ScrubberResult:
    is_poisoned: bool
    quarantine: bool
    sanitized_content: str
    reasons: list[str]
    atlas_id: str | None = None
    owasp_id: str | None = None


class InterToolScrubber:
    """Sanitizes tool and RAG output chunks before they enter the agent's context window."""

    INDIRECT_INJECTION_MARKERS = [
        (r"(?i)important\s*:\s*new\s+system\s+instruction", "indirect_system_instruction"),
        (r"(?i)stop\s+what\s+you\s+are\s+doing\s+and", "indirect_hijack"),
        (r"(?i)assistant\s*:\s*ignore\s+user", "impersonated_turn"),
        (r"(?i)<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>", "embedded_script"),
        (r"(?i)curl\s+https?://[^\s]+\s+-d\s+@", "embedded_exfil_command"),
        (
            r"(?i)send\s+(the\s+)?(contents|secrets|keys)\s+to\s+https?://",
            "exfiltration_instruction",
        ),
    ]

    def __init__(self):
        self.injection_detector = PromptInjectionDetector()
        self.secret_scrubber = SecretScrubber()
        self.deobfuscator = RecursiveDeobfuscator()

    def scrub(self, tool_name: str, raw_output: str) -> ScrubberResult:
        """Inspect and quarantine or sanitize tool return payloads."""
        if not raw_output:
            return ScrubberResult(
                is_poisoned=False,
                quarantine=False,
                sanitized_content=raw_output,
                reasons=[],
            )

        # Coerce non-string inputs to string
        if not isinstance(raw_output, str):
            raw_output = str(raw_output)

        # Deobfuscate content before scanning to catch encoded injection payloads
        deobfuscated = self.deobfuscator.normalize(raw_output)
        scan_text = deobfuscated.normalized_text

        reasons = []
        is_poisoned = False
        quarantine = False

        # 1. Check for indirect injection markers
        for pattern, marker_type in self.INDIRECT_INJECTION_MARKERS:
            if re.search(pattern, scan_text):
                reasons.append(f"Indirect injection signature detected: {marker_type}")
                is_poisoned = True
                quarantine = True

        # 2. Run prompt injection heuristic scanner
        inj_res = self.injection_detector.scan(scan_text)
        if inj_res.is_suspicious and inj_res.confidence >= 0.85:
            reasons.append(f"Adversarial prompt injection in tool output: {inj_res.description}")
            is_poisoned = True
            quarantine = True

        # 3. Redact any raw secrets contained in tool output
        secret_res = self.secret_scrubber.scan_and_redact(scan_text)
        sanitized = secret_res.sanitized_text
        if secret_res.has_secrets:
            reasons.append(f"Redacted sensitive tokens in tool output: {', '.join(secret_res.detected_types)}")

        # If quarantined, strip malicious content entirely — do NOT pass it to LLM
        if quarantine:
            sanitized = f"[ATLAS QUARANTINE: Content from tool '{tool_name}' was blocked. {len(reasons)} threat(s) neutralized: {'; '.join(reasons)}]"

        return ScrubberResult(
            is_poisoned=is_poisoned,
            quarantine=quarantine,
            sanitized_content=sanitized,
            reasons=reasons,
            atlas_id="AML.T0054" if is_poisoned else None,
            owasp_id="ASI06" if is_poisoned else None,
        )
