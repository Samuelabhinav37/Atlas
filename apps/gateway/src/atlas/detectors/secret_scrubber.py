"""
Secret and credential scrubber for tool arguments and LLM responses.
"""

import re
from dataclasses import dataclass


@dataclass
class SecretScanResult:
    has_secrets: bool
    detected_types: list[str]
    sanitized_text: str


class SecretScrubber:
    """Detects and redacts credentials, private keys, API tokens, and PII."""

    SECRET_PATTERNS = [
        ("openai_api_key", r"sk-[a-zA-Z0-9T3BlbkFJ]{20,48}"),
        ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
        ("aws_secret_key", r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        ("jwt_token", r"ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        ("github_token", r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
        ("ssh_private_key", r"-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----"),
        ("generic_bearer", r"(?i)bearer\s+[A-Za-z0-9\-_=]{20,}"),
    ]

    def scan_and_redact(self, text: str) -> SecretScanResult:
        """Find secrets and return sanitized version with [REDACTED:<type>] placeholders."""
        if not text:
            return SecretScanResult(has_secrets=False, detected_types=[], sanitized_text=text)

        sanitized = text
        detected = []

        for name, pattern in self.SECRET_PATTERNS:
            if re.search(pattern, sanitized):
                detected.append(name)
                sanitized = re.sub(pattern, f"[REDACTED:{name.upper()}]", sanitized)

        return SecretScanResult(
            has_secrets=len(detected) > 0,
            detected_types=detected,
            sanitized_text=sanitized,
        )
