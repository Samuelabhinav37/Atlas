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
        # anthropic_api_key must be checked before openai_api_key: both start
        # with "sk-", and openai_api_key's pattern is broad enough to also
        # match "sk-ant-...", so checking it first redacted the secret bytes
        # correctly but mislabeled every Anthropic key as OPENAI_API_KEY in
        # detected_types/the redaction placeholder -- not a leak (the value
        # is still redacted either way), but wrong telemetry/incident data.
        ("anthropic_api_key", r"sk-ant-[a-zA-Z0-9_-]{20,200}"),
        ("openai_api_key", r"sk-(?:proj-|admin-|svcacct-)?[a-zA-Z0-9_-]{20,200}"),
        ("aws_access_key", r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
        ("aws_secret_key", r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        ("gcp_api_key", r"AIza[0-9A-Za-z_-]{35}"),
        ("jwt_token", r"ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        ("github_token", r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
        ("github_fine_grained", r"github_pat_[A-Za-z0-9_]{22,255}"),
        ("slack_token", r"xox[bpas]-[0-9A-Za-z-]{10,255}"),
        ("ssh_private_key", r"(?s)-----BEGIN (?:RSA |OPENSSH |DSA |EC |ED25519 |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |OPENSSH |DSA |EC |ED25519 |ENCRYPTED )?PRIVATE KEY-----"),
        ("database_url", r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+"),
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
