"""Password hashing and signed access-token helpers for PRIORIS."""
from datetime import datetime, timedelta, timezone
import hashlib
import jwt
from jwt import InvalidTokenError
from pwdlib import PasswordHash

from app.config import get_settings

_password_hash = PasswordHash.recommended()
ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return _password_hash.hash(password)


def verify_password(password: str, password_digest: str) -> bool:
    try:
        return _password_hash.verify(password, password_digest)
    except Exception:
        return False


def hash_invitation_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _secret() -> str:
    secret = get_settings().auth_secret_key
    if not secret or len(secret) < 32:
        raise RuntimeError("AUTH_SECRET_KEY must be configured with at least 32 characters")
    return secret


def create_access_token(user_id: str) -> tuple[str, int]:
    lifetime = get_settings().access_token_expire_minutes
    expires_in = lifetime * 60
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "iat": now,
        "exp": now + timedelta(seconds=expires_in),
        "iss": "prioris-api",
        "aud": "prioris-client",
    }
    return jwt.encode(payload, _secret(), algorithm=ALGORITHM), expires_in


def decode_access_token(token: str) -> str | None:
    try:
        payload = jwt.decode(
            token,
            _secret(),
            algorithms=[ALGORITHM],
            audience="prioris-client",
            issuer="prioris-api",
            options={"require": ["sub", "exp", "iat"]},
        )
        subject = payload.get("sub")
        return subject if isinstance(subject, str) else None
    except (InvalidTokenError, RuntimeError):
        return None
