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
