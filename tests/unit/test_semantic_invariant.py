"""
Unit tests for the Semantic Invariant and Goal Drift Engine.
"""

from atlas.detectors.semantic_invariant import SemanticInvariantChecker


def test_benign_aligned_action():
    checker = SemanticInvariantChecker()
    checker.set_session_goal("s1", "Generate quarterly financial revenue summary for Q3")

    res = checker.check_drift(
        session_id="s1",
        tool_name="sql_query",
        tool_args={"query": "SELECT revenue, quarter FROM financial_reports WHERE quarter = 'Q3';"},
    )

    assert res.has_drifted is False
    assert res.similarity_score > 0.15
    assert res.risk_level == "LOW"


def test_goal_drift_critical_divergence():
    checker = SemanticInvariantChecker()
    checker.set_session_goal("s2", "Help me find recipe ideas for dinner")

    # Agent suddenly proposes DROP TABLE or administrative destruction
    res = checker.check_drift(
        session_id="s2",
        tool_name="sql_query",
        tool_args={"query": "DROP TABLE recipes;"},
    )

    assert res.has_drifted is True
    assert res.risk_level == "CRITICAL"
    assert res.taxonomy.atlas_technique == "AML.T0057"
    assert res.taxonomy.owasp_category == "ASI01"


def test_untracked_session_passthrough():
    checker = SemanticInvariantChecker()
    res = checker.check_drift(
        session_id="untracked_session",
        tool_name="sql_query",
        tool_args={"query": "SELECT 1"},
    )
    assert res.has_drifted is False
