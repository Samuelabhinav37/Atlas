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


def test_no_false_positive_format_json():
    """Phase 1.6: 'format' in arg value must NOT trigger CRITICAL drift."""
    checker = SemanticInvariantChecker()
    checker.set_session_goal("s3", "Format report data for the quarterly review")

    res = checker.check_drift(
        session_id="s3",
        tool_name="generate_report",
        tool_args={"output": "json", "format": "json"},
    )

    # Should NOT be CRITICAL just because 'format' appears
    assert res.risk_level != "CRITICAL"


def test_no_false_positive_delete_after_days():
    """Phase 1.6: 'delete_after_days' in arg value must NOT trigger CRITICAL drift."""
    checker = SemanticInvariantChecker()
    checker.set_session_goal("s4", "Configure data retention policy for compliance")

    res = checker.check_drift(
        session_id="s4",
        tool_name="set_policy",
        tool_args={"delete_after_days": "30", "retention": "standard"},
    )

    # Should NOT be CRITICAL just because 'delete' is a substring of 'delete_after_days'
    assert res.risk_level != "CRITICAL"


def test_real_drop_still_caught():
    """Phase 1.6: Actual DROP TABLE in SQL arg must still be CRITICAL."""
    checker = SemanticInvariantChecker()
    checker.set_session_goal("s5", "Help me find recipe ideas for dinner")

    res = checker.check_drift(
        session_id="s5",
        tool_name="sql_query",
        tool_args={"query": "DROP TABLE recipes;"},
    )

    assert res.has_drifted is True
    assert res.risk_level == "CRITICAL"
