from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import uuid

import jwt

_PRIVATE_KEY: str | None = None
_PUBLIC_KEY: str | None = None


def initialize_keys(config: dict) -> None:
    global _PRIVATE_KEY, _PUBLIC_KEY

    private_path = config.get("JWT_PRIVATE_KEY_PATH", "")
    public_path = config.get("JWT_PUBLIC_KEY_PATH", "")

    if not private_path:
        raise RuntimeError("Missing JWT_PRIVATE_KEY_PATH configuration.")
    if not public_path:
        raise RuntimeError("Missing JWT_PUBLIC_KEY_PATH configuration.")

    private_file = Path(private_path)
    public_file = Path(public_path)

    if not private_file.exists():
        raise RuntimeError(f"JWT private key not found: {private_file}")
    if not public_file.exists():
        raise RuntimeError(f"JWT public key not found: {public_file}")

    _PRIVATE_KEY = private_file.read_text(encoding="utf-8").strip()
    _PUBLIC_KEY = public_file.read_text(encoding="utf-8").strip()

    if not _PRIVATE_KEY:
        raise RuntimeError("JWT private key file is empty.")
    if not _PUBLIC_KEY:
        raise RuntimeError("JWT public key file is empty.")


def issue_token(*, user_id: int, token_type: str, context_claims: dict, config: dict) -> tuple[str, dict]:
    if _PRIVATE_KEY is None:
        raise RuntimeError("JWT keys are not initialized.")

    now = datetime.now(timezone.utc)
    if token_type == "access":
        ttl_minutes = config["ACCESS_TOKEN_TTL_MINUTES"]
    elif token_type == "refresh":
        ttl_minutes = config["REFRESH_TOKEN_TTL_MINUTES"]
    else:
        raise ValueError("token_type must be 'access' or 'refresh'.")

    exp = now + timedelta(minutes=ttl_minutes)

    claims = {
        "sub": str(user_id),
        "jti": uuid.uuid4().hex,
        "type": token_type,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "iss": config["JWT_ISSUER"],
        "aud": config["JWT_AUDIENCE"],
        **context_claims,
    }

    token = jwt.encode(claims, _PRIVATE_KEY, algorithm="RS256")
    return token, claims


def decode_and_verify_token(token: str, config: dict) -> dict:
    if _PUBLIC_KEY is None:
        raise RuntimeError("JWT keys are not initialized.")

    return jwt.decode(
        token,
        _PUBLIC_KEY,
        algorithms=["RS256"],
        audience=config["JWT_AUDIENCE"],
        issuer=config["JWT_ISSUER"],
    )
