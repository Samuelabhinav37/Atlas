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

        # Certain critical administrative actions that diverge from benign goals trigger drift
        critical_verbs = [
            "drop",
            "truncate",
            "delete",
            "format",
            "shutdown",
            "reboot",
            "exfiltrate",
            "passwd",
            "shadow",
        ]
        has_critical_divergence = any(v in action_text.lower() for v in critical_verbs) and not any(
            v in original_goal.lower() for v in critical_verbs
        )

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
