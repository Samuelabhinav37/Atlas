"""
Dynamic Semantic Invariant and Goal Drift Detection Engine.
Detects MITRE ATLAS AML.T0057 (Agentic Goal Hijacking) and OWASP ASI01/ASI10 (Rogue Agents).
"""

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

from atlas.models import SecurityTaxonomyMapping
from atlas.telemetry.mapper import taxonomy_mapper


@dataclass
class GoalDriftResult:
    has_drifted: bool
    similarity_score: float
    original_goal: str
    action_summary: str
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    taxonomy: SecurityTaxonomyMapping | None = None
    violation_reason: str | None = None


# Critical verbs that signal destructive administrative actions
_CRITICAL_VERBS = [
    "drop",
    "truncate",
    "delete",
    "shutdown",
    "reboot",
    "exfiltrate",
    "destroy",
    "wipe",
    "purge",
]

# Pre-compile word-boundary patterns for each critical verb
_CRITICAL_VERB_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (verb, re.compile(rf"\b{re.escape(verb)}\b", re.IGNORECASE)) for verb in _CRITICAL_VERBS
]

# SQL statement prefixes that indicate a query value (where critical verbs are meaningful)
_SQL_PREFIXES = re.compile(
    r"^\s*(SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|GRANT|REVOKE)\b",
    re.IGNORECASE,
)

# Generic SQL/prose filler words excluded when comparing goal vs. action target
# tokens, so two unrelated statements don't look "contextually related" just
# because they both happen to contain e.g. "FROM" or "WHERE".
_TARGET_STOPWORDS = {
    "from", "where", "into", "table", "select", "values", "with",
    "join", "will", "that", "this", "then", "have", "when",
}


class SemanticInvariantChecker:
    """
    Evaluates semantic divergence between an agent's initial user objective
    and downstream intermediate tool action proposals.
    """

    def __init__(self, drift_threshold: float = 0.15):
        self.drift_threshold = drift_threshold
        self._session_goals: dict[str, str] = {}

    def _tokenize_and_vectorize(self, text: str) -> Counter:
        """Extract character and word n-grams for fast cosine vector similarity."""
        words = re.findall(r"\b[a-zA-Z0-9_]+\b", text.lower())
        # Combine word tokens with 3-char sub-word ngrams for semantic robustness
        tokens = list(words)
        for word in words:
            if len(word) >= 3:
                tokens.extend([word[i : i + 3] for i in range(len(word) - 2)])
        return Counter(tokens)

    def _cosine_similarity(self, vec1: Counter, vec2: Counter) -> float:
        """Compute cosine similarity between two token frequency vectors."""
        intersection = set(vec1) & set(vec2)
        numerator = sum(vec1[x] * vec2[x] for x in intersection)

        sum1 = sum(vec1[x] ** 2 for x in vec1)
        sum2 = sum(vec2[x] ** 2 for x in vec2)
        denominator = math.sqrt(sum1) * math.sqrt(sum2)

        if not denominator:
            return 0.0
        return float(numerator) / denominator

    def _check_critical_verbs(
        self, tool_name: str, tool_args: dict[str, Any], original_goal: str
    ) -> bool:
        """Check for critical verb divergence using word-boundary matching.

        Only flags when:
        1. A critical verb appears in the tool_name itself, OR
        2. A critical verb appears in argument values that look like SQL statements
        AND the verb is not both (a) present in the original goal AND (b) applied
        to a target the goal actually mentioned.

        Verb presence in the goal alone is deliberately NOT sufficient to exempt
        a verb for the rest of check: original_goal is fixed for the lifetime of
        a session (set once via set_session_goal), so if a goal mentioning
        "delete" once -- e.g. "delete the old /tmp/cache files" -- permanently
        exempted the verb "delete" regardless of target, a later "DELETE FROM
        customer_accounts;" against a completely different, unrelated target
        would silently bypass detection for the rest of the session. Requiring
        a shared non-verb target token (e.g. a table/file/resource name) closes
        that gap while still recognizing genuinely goal-aligned actions.
        """
        goal_has_verb = {
            verb for verb, pattern in _CRITICAL_VERB_PATTERNS if pattern.search(original_goal)
        }
        goal_target_tokens = (
            set(re.findall(r"\b[a-zA-Z0-9_]{4,}\b", original_goal.lower()))
            - set(_CRITICAL_VERBS)
            - _TARGET_STOPWORDS
        )

        def _is_flagged(text: str) -> bool:
            text_tokens = (
                set(re.findall(r"\b[a-zA-Z0-9_]{4,}\b", text.lower()))
                - set(_CRITICAL_VERBS)
                - _TARGET_STOPWORDS
            )
            shares_target = bool(text_tokens & goal_target_tokens)
            for verb, pattern in _CRITICAL_VERB_PATTERNS:
                if not pattern.search(text):
                    continue
                if verb in goal_has_verb and shares_target:
                    continue
                return True
            return False

        if _is_flagged(tool_name):
            return True

        # Check argument values — but ONLY values that look like SQL statements
        for _key, value in tool_args.items():
            str_val = str(value)
            if not _SQL_PREFIXES.match(str_val):
                continue
            if _is_flagged(str_val):
                return True

        return False

    def set_session_goal(self, session_id: str, goal_prompt: str):
        """Record the initial user prompt / objective for a session."""
        self._session_goals[session_id] = goal_prompt

    def check_drift(
        self,
        session_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
    ) -> GoalDriftResult:
        """Assert that the proposed tool action aligns with the original session goal."""
        original_goal = self._session_goals.get(session_id)
        if not original_goal:
            # If no goal tracked, assume no drift
            return GoalDriftResult(
                has_drifted=False,
                similarity_score=1.0,
                original_goal="[Untracked Goal]",
                action_summary=f"{tool_name}({tool_args})",
                risk_level="LOW",
                taxonomy=None,
                violation_reason=None,
            )

        # Build action semantic string
        args_str = " ".join(f"{k} {v}" for k, v in tool_args.items())
        action_text = f"{tool_name} {args_str}"

        vec_goal = self._tokenize_and_vectorize(original_goal)
        vec_action = self._tokenize_and_vectorize(action_text)

        sim = self._cosine_similarity(vec_goal, vec_action)

        # Use word-boundary matching with context-aware verb detection
        has_critical_divergence = self._check_critical_verbs(tool_name, tool_args, original_goal)

        has_drifted = (sim < self.drift_threshold) or has_critical_divergence

        risk_level = "LOW"
        if has_critical_divergence:
            risk_level = "CRITICAL"
        elif sim < 0.05:
            risk_level = "HIGH"
        elif sim < self.drift_threshold:
            risk_level = "MEDIUM"

        taxonomy = None
        violation_reason = None
        if has_drifted:
            mapping = taxonomy_mapper.enrich(
                atlas_id="AML.T0057",
                owasp_id="ASI01",
                nist_id="MANAGE-2.4",
                reason=(
                    f"Agent Goal Hijacking / Semantic Drift detected: Action '{tool_name}' "
                    f"diverged from initial objective '{original_goal[:50]}...' (similarity: {sim:.2f})"
                ),
            )
            taxonomy = mapping
            violation_reason = mapping.reason

        return GoalDriftResult(
            has_drifted=has_drifted,
            similarity_score=sim,
            original_goal=original_goal,
            action_summary=action_text,
            risk_level=risk_level,
            taxonomy=taxonomy,
            violation_reason=violation_reason,
        )
