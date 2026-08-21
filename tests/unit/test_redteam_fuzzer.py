"""
Unit tests for the Automated Adversarial Red-Team Fuzzer.
"""

from atlas.redteam.fuzzer import RedTeamFuzzer


def test_redteam_fuzzer_execution():
    fuzzer = RedTeamFuzzer()
    assessment = fuzzer.run_assessment()

    assert assessment.total_probes >= 15
    assert assessment.total_blocked == assessment.total_probes
    assert assessment.total_bypassed == 0
    assert assessment.security_posture_score == 100.0
    assert "SQL Safety & Least Agency" in assessment.category_scores
    assert "Shell AST & RCE Containment" in assessment.category_scores


def test_goal_drift_probe_is_advisory_not_folded_into_score():
    """Regression: the goal-drift probe (DFT-01) exercises
    SemanticInvariantChecker directly, not the live /v1/agent/evaluate path,
    so it must not count toward total_probes/security_posture_score/
    category_scores alongside probes that DO exercise live enforcement --
    otherwise the headline score implies protection the running gateway
    doesn't actually provide."""
    fuzzer = RedTeamFuzzer()
    assessment = fuzzer.run_assessment()

    advisory_ids = {p.probe_id for p in assessment.advisory_probes}
    assert "DFT-01" in advisory_ids
    assert all(not p.enforced for p in assessment.advisory_probes)

    enforced_ids = {p.probe_id for p in assessment.probe_results if p.enforced}
    assert "DFT-01" not in enforced_ids
    assert not any("Goal Drift" in cat for cat in assessment.category_scores)
