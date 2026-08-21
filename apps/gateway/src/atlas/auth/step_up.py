"""
Step-Up Human-In-The-Loop (HITL) Approval and Challenge Manager.
Enforces OWASP ASI03 (Identity & Privilege Abuse) and ASI09 (Human-Agent Trust).
"""

import secrets
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ChallengeStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CONSUMED = "CONSUMED"


@dataclass
class StepUpChallenge:
    challenge_id: str
    trace_id: str
    user_id: str
    agent_id: str
    tool_name: str
    arguments: dict[str, Any]
    status: ChallengeStatus = ChallengeStatus.PENDING
    created_at: int = field(default_factory=lambda: int(time.time()))
    expires_at: int = field(default_factory=lambda: int(time.time()) + 600)  # 10 min TTL
    resolved_by: str | None = None


class StepUpAuthManager:
    """Tracks and resolves asynchronous human-in-the-loop approval challenges for sensitive agent actions."""

    def __init__(self):
        self._challenges: dict[str, StepUpChallenge] = {}

    def create_challenge(
        self,
        trace_id: str,
        user_id: str,
        agent_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        ttl_seconds: int = 600,
    ) -> StepUpChallenge:
        """Create a new pending human approval challenge."""
        now = int(time.time())
        challenge_id = f"chl_{secrets.token_hex(6)}"

        challenge = StepUpChallenge(
            challenge_id=challenge_id,
            trace_id=trace_id,
            user_id=user_id,
            agent_id=agent_id,
            tool_name=tool_name,
            arguments=arguments,
            status=ChallengeStatus.PENDING,
            created_at=now,
            expires_at=now + ttl_seconds,
            resolved_by=None,
        )
        self._challenges[challenge_id] = challenge
        return challenge

    def get_challenge(self, challenge_id: str) -> StepUpChallenge | None:
        """Retrieve challenge and update status if expired."""
        challenge = self._challenges.get(challenge_id)
        if not challenge:
            return None

        if challenge.status == ChallengeStatus.PENDING and int(time.time()) > challenge.expires_at:
            challenge.status = ChallengeStatus.EXPIRED

        return challenge

    def approve_challenge(self, challenge_id: str, approver_id: str) -> bool:
        """Approve a pending human-in-the-loop challenge."""
        challenge = self.get_challenge(challenge_id)
        if not challenge or challenge.status != ChallengeStatus.PENDING:
            return False

        challenge.status = ChallengeStatus.APPROVED
        challenge.resolved_by = approver_id
        return True

    def reject_challenge(self, challenge_id: str, approver_id: str) -> bool:
        """Reject a pending human-in-the-loop challenge."""
        challenge = self.get_challenge(challenge_id)
        if not challenge or challenge.status != ChallengeStatus.PENDING:
            return False

        challenge.status = ChallengeStatus.REJECTED
        challenge.resolved_by = approver_id
        return True

    def consume_challenge(self, challenge_id: str) -> bool:
        """Atomically transition an APPROVED challenge to CONSUMED.

        Must be called exactly once, at the moment a challenge's approval is actually
        relied on to authorize an action -- this ensures a single human approval can
        authorize exactly one action rather than being replayable across many.
        """
        challenge = self.get_challenge(challenge_id)
        if not challenge or challenge.status != ChallengeStatus.APPROVED:
            return False
        challenge.status = ChallengeStatus.CONSUMED
        return True

    def get_pending_challenges(self) -> list[StepUpChallenge]:
        """Return all active pending challenges that have not expired."""
        now = int(time.time())
        pending = []
        for challenge in self._challenges.values():
            if challenge.status == ChallengeStatus.PENDING:
                if now > challenge.expires_at:
                    challenge.status = ChallengeStatus.EXPIRED
                else:
                    pending.append(challenge)
        return sorted(pending, key=lambda c: c.created_at, reverse=True)
