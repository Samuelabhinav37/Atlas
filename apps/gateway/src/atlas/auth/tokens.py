"""
Signed identity tokens for authenticating callers of the Atlas gateway.

/v1/agent/evaluate and the step-up approval endpoints must not derive a caller's
identity or scopes from the request body -- that lets any caller self-grant
arbitrary privileges (e.g. POST {"user": {"scopes": ["admin:all"]}}). Callers
instead present a Bearer JWT, and the gateway derives the verified UserIdentity
from its signed claims via verify_user_token.
"""

import os
import time

import jwt
from atlas.models import UserIdentity

_ALGORITHM = "HS256"
_ENV_VAR = "ATLAS_JWT_SECRET"


class InvalidTokenError(Exception):
    """Raised when a bearer token is missing, malformed, expired, or has a bad signature."""


def _signing_key() -> str:
    key = os.environ.get(_ENV_VAR)
    if not key:
        raise RuntimeError(
            f"{_ENV_VAR} is not set. Atlas will not start an identity-verifying endpoint "
            "with a default or generated signing key -- that would make every previously "
            "issued token invalid on restart and invites accidentally shipping a weak "
            f"default. Set {_ENV_VAR} to a long random secret before starting the gateway."
        )
    return key


def issue_user_token(
    user_id: str,
    scopes: list[str],
    tenant_id: str = "default",
    roles: list[str] | None = None,
    ttl_seconds: int = 3600,
) -> str:
    """Issue a signed JWT asserting the given identity and scopes.

    This is the only place scopes are allowed to be granted -- whoever holds the
    signing key controls authorization. In production, tokens should be minted by
    the deploying org's own identity provider using the same secret/algorithm, not
    by calling this function from an untrusted request path.
    """
    now = int(time.time())
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "roles": roles or ["user"],
        "scopes": scopes,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    return jwt.encode(payload, _signing_key(), algorithm=_ALGORITHM)


def verify_user_token(token: str) -> UserIdentity:
    """Verify a bearer token's signature and expiry, returning the identity it asserts."""
    try:
        payload = jwt.decode(token, _signing_key(), algorithms=[_ALGORITHM])
    except jwt.PyJWTError as e:
        raise InvalidTokenError(str(e)) from e

    sub = payload.get("sub")
    if not sub:
        raise InvalidTokenError("Token is missing required 'sub' claim")

    return UserIdentity(
        user_id=sub,
        tenant_id=payload.get("tenant_id", "default"),
        roles=payload.get("roles", ["user"]),
        scopes=payload.get("scopes", []),
    )
