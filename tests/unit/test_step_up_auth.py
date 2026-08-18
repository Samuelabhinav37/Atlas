"""
Unit tests for Step-Up Human-In-The-Loop (HITL) challenge manager.
"""

from atlas.auth.step_up import ChallengeStatus, StepUpAuthManager


def test_create_and_approve_challenge():
    manager = StepUpAuthManager()
    challenge = manager.create_challenge(
        trace_id="tr_101",
        user_id="user_finance",
        agent_id="payroll_bot",
        tool_name="execute_payment",
        arguments={"amount": 25000},
    )

    assert challenge.status == ChallengeStatus.PENDING
    assert len(manager.get_pending_challenges()) == 1

    # Human approves
    success = manager.approve_challenge(challenge.challenge_id, approver_id="security_lead")
    assert success is True
    assert challenge.status == ChallengeStatus.APPROVED
    assert challenge.resolved_by == "security_lead"
    assert len(manager.get_pending_challenges()) == 0


def test_reject_challenge():
    manager = StepUpAuthManager()
    challenge = manager.create_challenge(
        trace_id="tr_102",
        user_id="user_finance",
        agent_id="payroll_bot",
        tool_name="modify_iam",
        arguments={"role": "root"},
    )

    success = manager.reject_challenge(challenge.challenge_id, approver_id="security_lead")
    assert success is True
    assert challenge.status == ChallengeStatus.REJECTED
    assert len(manager.get_pending_challenges()) == 0
