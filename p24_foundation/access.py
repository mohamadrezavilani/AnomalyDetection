"""Verify externally issued, short-lived investigation credentials.

This module verifies claims; it does not authenticate people or issue tokens.
The trusted issuer must bind the subject and roles to a real operator identity.
"""
from __future__ import annotations

import base64
import json
import re
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import FoundationError
from .privacy import canonical

POLICY_VERSION = "p24-access.4"
ISSUER = "p24-foundation-local"
AUDIENCE = "p24-evidence-inspection"
MAX_TOKEN_BYTES = 4096
MAX_LIFETIME_SECONDS = 8 * 60 * 60
ROLE_ACTIONS = {
    "investigator": frozenset({"read_run", "read_publication", "read_request", "read_requests", "read_session", "read_candidates", "read_evidence", "read_workflows", "read_incidents"}),
    "incident_reviewer": frozenset({"read_incidents", "review_incidents"}),
    "preservation_officer": frozenset({"place_hold"}),
    "audit_reviewer": frozenset({"read_access_audit"}),
    "sensitive_evidence_reader": frozenset({"read_sensitive_archive"}),
}
ALL_ROLES = frozenset(ROLE_ACTIONS)


def _b64decode(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def read_public_key(path: str | Path) -> Ed25519PublicKey:
    try:
        raw = Path(path).read_bytes()
        if len(raw) == 32:
            return Ed25519PublicKey.from_public_bytes(raw)
        key = serialization.load_pem_public_key(raw)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError
        return key
    except Exception:
        raise FoundationError("access_public_key_invalid") from None


@dataclass(frozen=True)
class VerifiedPrincipal:
    subject: str
    roles: frozenset[str]
    token_id: str
    policy_version: str = POLICY_VERSION


class AccessPolicy:
    """Validate a signed credential and map roles to a narrow read/action set."""

    def __init__(self, public_key: Ed25519PublicKey, namespace: str, *, issuer=ISSUER, audience=AUDIENCE, clock=time.time):
        if not isinstance(public_key, Ed25519PublicKey):
            raise FoundationError("access_public_key_invalid")
        if not isinstance(namespace, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", namespace):
            raise FoundationError("invalid_namespace")
        self.public_key = public_key
        self.namespace = namespace
        self.issuer = issuer
        self.audience = audience
        self.clock = clock

    def verify(self, token: str) -> VerifiedPrincipal:
        try:
            if not isinstance(token, str) or len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
                raise ValueError("invalid_credential")
            encoded, signature_text = token.split(".")
            body, signature = _b64decode(encoded), _b64decode(signature_text)
            claims = json.loads(body.decode("utf-8"))
            if canonical(claims) != body:
                raise ValueError("invalid_credential")
            self.public_key.verify(signature, body)
            expected = {"version", "iss", "aud", "namespace", "subject", "roles", "iat", "exp", "jti"}
            if not isinstance(claims, dict) or set(claims) != expected or claims["version"] != 1:
                raise ValueError("invalid_credential")
            if claims["iss"] != self.issuer or claims["aud"] != self.audience:
                raise ValueError("invalid_credential")
            if claims["namespace"] != self.namespace:
                raise ValueError("access_namespace_mismatch")
            subject, roles = claims["subject"], claims["roles"]
            if not isinstance(subject, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", subject):
                raise ValueError("invalid_credential")
            if not isinstance(roles, list) or not roles or len(roles) != len(set(roles)) or any(r not in ALL_ROLES for r in roles):
                raise ValueError("invalid_credential")
            issued, expires = claims["iat"], claims["exp"]
            if isinstance(issued, bool) or not isinstance(issued, int) or isinstance(expires, bool) or not isinstance(expires, int):
                raise ValueError("invalid_credential")
            now = int(self.clock())
            if expires <= issued or expires - issued > MAX_LIFETIME_SECONDS or issued > now + 30:
                raise ValueError("invalid_credential")
            if expires <= now:
                raise ValueError("access_credential_expired")
            token_id = str(uuid.UUID(claims["jti"]))
            if token_id != claims["jti"]:
                raise ValueError("invalid_credential")
            return VerifiedPrincipal(subject, frozenset(roles), token_id)
        except ValueError as exc:
            code = str(exc) if str(exc) in {"access_namespace_mismatch", "access_credential_expired"} else "access_credential_invalid"
            raise FoundationError(code) from None
        except Exception:
            raise FoundationError("access_credential_invalid") from None

    def authorize(self, token: str, action: str) -> VerifiedPrincipal:
        principal = self.verify(token)
        if not isinstance(action, str) or not any(action in ROLE_ACTIONS[role] for role in principal.roles):
            raise FoundationError("access_role_insufficient")
        return principal
