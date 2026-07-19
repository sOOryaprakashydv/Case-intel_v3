"""
Minimal shared-secret auth for write endpoints (upload, notes, outcomes).

This is intentionally simple — a single API key checked via header — not
a full user/role system. For a real law-enforcement deployment handling
actual case data, replace this with proper per-analyst authentication
(e.g. OAuth/SSO tied to department accounts) before going beyond a
pilot. This exists so the API isn't wide open by default; it is not a
substitute for real access control.
"""
import os
import hmac
from fastapi import Header, HTTPException

API_KEY = os.getenv("CASEINTEL_API_KEY", "")


def require_api_key(x_api_key: str = Header(default="")):
    if not API_KEY:
        # No key configured — fail closed in production, but don't block
        # local dev where operators haven't set one up yet.
        if os.getenv("ENV", "development") == "production":
            raise HTTPException(500, "Server misconfigured: CASEINTEL_API_KEY not set")
        return True
    if not hmac.compare_digest(x_api_key, API_KEY):
        raise HTTPException(401, "Missing or invalid API key")
    return True
