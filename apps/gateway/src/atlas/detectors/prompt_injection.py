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


# Pre-compiled pattern tuples: (compiled_regex, name, confidence)
_RAW_PATTERNS: list[tuple[str, str, float]] = [
    # === Instruction Override (original + synonyms) ===
    (
        r"(?i)(ignore|forget|disregard|override|bypass|skip|abandon|dismiss|neglect|drop)\s+(all\s+)?(previous|prior|above|earlier|original|initial|existing|old)\s+(instructions|prompts|directions|rules|guidelines|constraints|commands|programming)",
        "instruction_override",
        0.95,
    ),
    (r"(?i)disregard\s+all\s+(rules|guidelines|safety|restrictions|limitations)", "rule_disregard", 0.95),
    (r"(?i)do\s+not\s+follow\s+(your|any|the)\s+(previous|original|initial)\s+(instructions|rules|programming)", "instruction_override", 0.95),
    (r"(?i)stop\s+being\s+(an?\s+)?(helpful|safe|responsible|aligned)\s+(assistant|AI|model)", "instruction_override", 0.90),

    # === Jailbreak Persona / Role Play ===
    (
        r"(?i)you\s+are\s+now\s+(in|operating\s+as)\s+(DAN|unrestricted|god\s+mode|developer\s+mode|jailbroken|unfiltered)",
        "jailbreak_persona",
        0.9,
    ),
    (r"(?i)pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(AI\s+)?(with\s+no|without\s+any|unrestricted|unfiltered|uncensored)", "jailbreak_roleplay", 0.90),
    (r"(?i)act\s+as\s+if\s+you\s+(have\s+no|are\s+not\s+bound|are\s+free\s+from)\s+(safety|restrictions|rules|guidelines|limitations)", "jailbreak_roleplay", 0.90),
    (r"(?i)imagine\s+you\s+are\s+(unrestricted|unfiltered|uncensored|a\s+hacker|evil)", "jailbreak_roleplay", 0.85),
    (r"(?i)respond\s+as\s+(DAN|an?\s+unrestricted|an?\s+evil|an?\s+unfiltered)", "jailbreak_persona", 0.90),
    (r"(?i)as\s+an\s+AI\s+with\s+no\s+safety\s+restrictions", "jailbreak_bypass", 0.9),
    (r"(?i)enter\s+(DAN|developer|jailbreak|unrestricted|god)\s+mode", "jailbreak_persona", 0.90),

    # === System Prompt Leakage / Override ===
    (r"(?i)system\s+prompt\s+override", "system_override", 0.9),
    (r"(?i)repeat\s+everything\s+(above|before)\s+this\s+line", "prompt_leakage", 0.85),
    (
        r"(?i)output\s+(your\s+)?(full\s+)?(system\s+prompt|initial\s+instructions|hidden\s+instructions|original\s+prompt)",
        "prompt_leakage",
        0.85,
    ),
    (r"(?i)(show|reveal|print|display|dump|leak)\s+(your\s+)?(system\s+prompt|initial\s+instructions|hidden\s+prompt|secret\s+instructions)", "prompt_leakage", 0.85),
    (r"(?i)what\s+(is|are)\s+your\s+(system\s+prompt|initial\s+instructions|hidden\s+instructions|secret\s+rules)", "prompt_leakage", 0.75),

    # === Delimiter Injection ===
    (r"(?i)(###|---|\*\*\*)\s*(SYSTEM|INSTRUCTION|ADMIN|OVERRIDE|NEW\s+PROMPT)", "delimiter_injection", 0.85),
    (r"(?i)<\|im_sep\|>", "delimiter_injection", 0.90),
    (r"(?i)\[SYSTEM\]|\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>", "delimiter_injection", 0.90),
    (r"(?i)<\|system\|>|<\|user\|>|<\|assistant\|>", "delimiter_injection", 0.85),

    # === Encoded Payload ===
    (r"(?i)base64\s*:\s*[A-Za-z0-9+/=]{20,}", "encoded_payload", 0.75),
    (r"(?i)\beval\s*\(", "code_execution", 0.70),
    (r"(?i)\bexec\s*\(", "code_execution", 0.70),
    (r"(?i)__import__\s*\(", "code_execution", 0.80),

    # === Social Engineering ===
    (r"(?i)this\s+is\s+(just\s+)?a\s+test\s+(of\s+your|to\s+see|to\s+check)", "social_engineering", 0.50),
    (r"(?i)for\s+(educational|research|testing|academic)\s+purposes\s+only", "social_engineering", 0.50),
    (r"(?i)my\s+(grandmother|grandma|mother|mom)\s+(used\s+to|always|would)\s+(tell|read|say)", "social_engineering", 0.55),
    (r"(?i)hypothetically\s+(speaking|if|what\s+if)", "social_engineering", 0.45),

    # === Context Manipulation ===
    (r"(?i)(new\s+conversation|reset\s+context|start\s+fresh|forget\s+everything|clear\s+(your\s+)?memory|wipe\s+(your\s+)?memory)", "context_manipulation", 0.80),
    (r"(?i)from\s+now\s+on\s+(you\s+)?(will|must|should|are)\s+(ignore|bypass|disregard|forget)", "context_manipulation", 0.85),
    (r"(?i)the\s+above\s+(instructions?|rules?|text)\s+(are|is|were)\s+(fake|wrong|a\s+test|not\s+real)", "context_manipulation", 0.85),

    # === Multi-Language ===
    (r"(?i)ignorar\s+(todas?\s+)?(las\s+)?instrucciones\s+(anteriores|previas)", "multilang_injection", 0.85),
    (r"(?i)ignorer\s+(toutes?\s+)?(les\s+)?instructions\s+(pr[eé]c[eé]dentes|ant[eé]rieures)", "multilang_injection", 0.85),
    (r"指示を無視", "multilang_injection", 0.85),
    (r"忽略之前的指令", "multilang_injection", 0.85),
    (r"(?i)ignoriere\s+(alle\s+)?(vorherigen?\s+)?Anweisungen", "multilang_injection", 0.85),

    # === Prompt Injection via Tool Output (indirect) ===
    (r"(?i)IMPORTANT\s*:\s*(NEW\s+)?SYSTEM\s+(INSTRUCTION|PROMPT|OVERRIDE|COMMAND)", "indirect_injection", 0.90),
    (r"(?i)ATTENTION\s*:\s*(ADMIN|SYSTEM|DEVELOPER)\s+(OVERRIDE|INSTRUCTION|NOTE)", "indirect_injection", 0.85),
]

# Pre-compile all patterns at module load time
COMPILED_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    (re.compile(pat), name, conf) for pat, name, conf in _RAW_PATTERNS
]

# Regex to detect character-spaced evasion: single chars separated by spaces/underscores/dots
_SPACING_PATTERN = re.compile(r"(?<!\w)(\w[\s_.\-]){3,}\w(?!\w)")


def _collapse_spacing(text: str) -> str:
    """Collapse character-spaced evasion like 'i g n o r e' → 'ignore' or 'i_g_n_o_r_e' → 'ignore'."""
    def _replacer(match: re.Match[str]) -> str:
        return re.sub(r"[\s_.\-]", "", match.group(0))
    return _SPACING_PATTERN.sub(_replacer, text)


class PromptInjectionDetector:
    """Detects direct prompt injection, system prompt overrides, and jailbreak patterns."""

    def scan(self, text: str) -> InjectionScanResult:
        """Scan input text for adversarial injection markers with multi-signal aggregation."""
        if not text:
            return InjectionScanResult(is_suspicious=False, confidence=0.0, matched_patterns=[], description="Clean")

        # Normalize spacing evasion before scanning
        normalized = _collapse_spacing(text)

        matches: list[str] = []
        confidences: list[float] = []

        for compiled_pat, name, conf in COMPILED_PATTERNS:
            # Check both original and spacing-normalized text
            if (compiled_pat.search(text) or compiled_pat.search(normalized)) and name not in matches:
                matches.append(name)
                confidences.append(conf)

        if matches:
            # Multi-signal confidence aggregation:
            # If multiple weak signals match, boost confidence
            max_conf = max(confidences)
            if len(matches) >= 3:
                aggregated = min(sum(confidences) * 0.7, 0.99)
                final_confidence = max(max_conf, aggregated)
            elif len(matches) >= 2:
                aggregated = min(sum(confidences) * 0.6, 0.95)
                final_confidence = max(max_conf, aggregated)
            else:
                final_confidence = max_conf

            return InjectionScanResult(
                is_suspicious=True,
                confidence=final_confidence,
                matched_patterns=matches,
                description=f"Prompt injection patterns detected: {', '.join(matches)}",
            )

        return InjectionScanResult(
            is_suspicious=False,
            confidence=0.0,
            matched_patterns=[],
            description="No injection markers detected",
        )
