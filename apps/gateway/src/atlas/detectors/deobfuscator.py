"""
Recursive de-obfuscation and normalization engine for adversarial tool argument inspection.
"""

import base64
import binascii
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass


@dataclass
class DeobfuscationResult:
    original_text: str
    normalized_text: str
    unpacked_layers: list[str]
    is_obfuscated: bool


class RecursiveDeobfuscator:
    """Recursively extracts and decodes obfuscated payloads (URL, Base64, Hex, Unicode)."""

    BASE64_CANDIDATE_REGEX = re.compile(r"(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")

    def normalize(self, text: str, max_depth: int = 5) -> DeobfuscationResult:
        """Recursively normalize and decode text until fixed point or max depth reached."""
        if not text:
            return DeobfuscationResult(
                original_text=text,
                normalized_text=text,
                unpacked_layers=[],
                is_obfuscated=False,
            )

        current = text
        unpacked_layers = []

        for _ in range(max_depth):
            changed = False

            # 1. Unicode Normalization (NFKC)
            nfkc_normalized = unicodedata.normalize("NFKC", current)
            if nfkc_normalized != current:
                current = nfkc_normalized
                unpacked_layers.append("unicode_nfkc")
                changed = True

            # 1.5 Strip invisible Unicode format characters (category "Cf"):
            # zero-width space (U+200B), zero-width non-joiner/joiner
            # (U+200C/D), zero-width no-break space / BOM (U+FEFF), word
            # joiner (U+2060), soft hyphen (U+00AD), directional marks, etc.
            # NFKC does not remove these. They're invisible to a human but
            # split a word into separate regex tokens character-by-character
            # -- "i​gnore all previous instructions" reads as "ignore
            # all previous instructions" but \bignore\b never matches it, and
            # Python's \s does not match Cf characters either, so this evaded
            # every downstream detector's word-boundary and spacing checks.
            stripped = "".join(ch for ch in current if unicodedata.category(ch) != "Cf")
            if stripped != current:
                current = stripped
                unpacked_layers.append("invisible_char_strip")
                changed = True

            # 2. URL Decoding
            url_decoded = urllib.parse.unquote(current)
            if url_decoded != current:
                current = url_decoded
                unpacked_layers.append("url_decode")
                changed = True

            # 3. Base64 Decoding
            # Every regex match is attempted regardless of padding or nearby keywords --
            # gating on `match.endswith("=")` missed any payload whose byte length is a
            # multiple of 3 (no padding needed), and gating on a "base64"/"b64"/"decode"
            # keyword is trivial for an attacker to simply not include. Precision instead
            # comes from the content-validity filter below: decoding arbitrary non-base64
            # text as base64 overwhelmingly produces non-printable garbage, which is
            # rejected before the replacement is ever applied.
            b64_matches = self.BASE64_CANDIDATE_REGEX.findall(current)

            for match in b64_matches:
                try:
                    decoded_bytes = base64.b64decode(match, validate=True)
                    decoded_str = decoded_bytes.decode("utf-8")
                    # Must be printable ASCII text
                    if (
                        len(decoded_str) >= 3
                        and all(c.isprintable() or c in "\n\r\t" for c in decoded_str)
                        and any(c.isalpha() for c in decoded_str)
                    ):
                        current = current.replace(match, decoded_str, 1)
                        unpacked_layers.append(f"base64_decode({match[:8]}...)")
                        changed = True
                except (binascii.Error, UnicodeDecodeError):
                    pass

            # 4. Hex Escaped Decoding (e.g. \x2e\x2e\x2f -> ../)
            if "\\x" in current or "\\X" in current:
                try:
                    hex_decoded = re.sub(
                        r"\\[xX]([0-9a-fA-F]{2})",
                        lambda m: chr(int(m.group(1), 16)),
                        current,
                    )
                    if hex_decoded != current:
                        current = hex_decoded
                        unpacked_layers.append("hex_unescape")
                        changed = True
                except Exception:
                    pass

            if not changed:
                break

        return DeobfuscationResult(
            original_text=text,
            normalized_text=current,
            unpacked_layers=unpacked_layers,
            is_obfuscated=len(unpacked_layers) > 0,
        )
