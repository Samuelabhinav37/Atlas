"""
Atlas: AI Agent Security Control Plane & Runtime Policy Enforcement Gateway.
"""

from atlas.engine.evaluator import PolicyEvaluator
from atlas.sdk import AtlasGuard, SecurityViolationError

__version__ = "0.1.0"
__all__ = ["AtlasGuard", "PolicyEvaluator", "SecurityViolationError"]
