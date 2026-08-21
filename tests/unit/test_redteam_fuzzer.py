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


def test_goal_drift_probe_is_now_enforced_via_real_evaluator():
    """Goal drift is now wired into PolicyEvaluator.evaluate_tool_call() (the
    critical-verb-divergence case), so DFT-01 goes through the real evaluator
    like every other probe and correctly counts toward the enforced score --
    it is no longer advisory-only."""
    fuzzer = RedTeamFuzzer()
    assessment = fuzzer.run_assessment()

    dft_probe = next(p for p in assessment.probe_results if p.probe_id == "DFT-01")
    assert dft_probe.enforced is True
    assert dft_probe.blocked is True

    advisory_ids = {p.probe_id for p in assessment.advisory_probes}
    assert "DFT-01" not in advisory_ids

    enforced_ids = {p.probe_id for p in assessment.probe_results if p.enforced}
    assert "DFT-01" in enforced_ids
    assert "Semantic Invariant & Goal Drift" in assessment.category_scores
