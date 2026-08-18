"""
Prompt injection and jailbreak detector for agent ingress.
"""

import re
from dataclasses import dataclass


@dataclass
class InjectionScanResult:
    is_suspicious: bool
    confidence: float
    matched_patterns: list[str]
    description: str


class PromptInjectionDetector:
    """Detects direct prompt injection, system prompt overrides, and jailbreak patterns."""

    INJECTION_PATTERNS = [
        (
            r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|directions)",
            "instruction_override",
            0.95,
        ),
        (r"(?i)disregard\s+all\s+(rules|guidelines|safety)", "rule_disregard", 0.95),
        (
            r"(?i)you\s+are\s+now\s+(in|operating\s+as)\s+(DAN|unrestricted|god\s+mode|developer\s+mode)",
            "jailbreak_persona",
            0.9,
        ),
        (r"(?i)system\s+prompt\s+override", "system_override", 0.9),
        (r"(?i)repeat\s+everything\s+(above|before)\s+this\s+line", "prompt_leakage", 0.85),
        (
            r"(?i)output\s+(your\s+)?(full\s+)?(system\s+prompt|initial\s+instructions)",
            "prompt_leakage",
            0.85,
        ),
        (r"(?i)as\s+an\s+AI\s+with\s+no\s+safety\s+restrictions", "jailbreak_bypass", 0.9),
        (r"(?i)base64\s*:\s*[A-Za-z0-9+/=]{20,}", "encoded_payload", 0.75),
    ]

    def scan(self, text: str) -> InjectionScanResult:
        """Scan input text for adversarial injection markers."""
        if not text:
            return InjectionScanResult(
                is_suspicious=False, confidence=0.0, matched_patterns=[], description="Clean"
            )

        matches = []
        max_confidence = 0.0

        for pattern, name, conf in self.INJECTION_PATTERNS:
            if re.search(pattern, text):
                matches.append(name)
                max_confidence = max(max_confidence, conf)

        if matches:
            return InjectionScanResult(
                is_suspicious=True,
                confidence=max_confidence,
                matched_patterns=matches,
                description=f"Prompt injection patterns detected: {', '.join(matches)}",
            )

        return InjectionScanResult(
            is_suspicious=False,
            confidence=0.0,
            matched_patterns=[],
            description="No injection markers detected",
        )
