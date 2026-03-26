from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request

from app.extensions import db
from app.models import AuthContext, User
from app.reputation.service import ensure_profile
from app.security.context import context_from_request, normalize_text
from app.security.tokens import issue_token


auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def _validate_payload(payload: dict) -> tuple[bool, str | None]:
    required = ["email", "password"]
    for field in required:
        value = payload.get(field)
        if not isinstance(value, str) or not normalize_text(value):
            return False, f"Missing or invalid field: {field}"
    return True, None


def _build_context_claims(payload: dict) -> dict:
    device_fingerprint = normalize_text(request.headers.get("X-Device-Fingerprint", ""))
    if not device_fingerprint:
        raise ValueError("Missing required header: X-Device-Fingerprint")

    ctx = context_from_request(
        request,
        trust_proxy_headers=current_app.config["TRUST_PROXY_HEADERS"],
        device_fingerprint=device_fingerprint,
    )

    return {
        "ip": ctx.ip,
        "ip_prefix": ctx.ip_prefix,
        "fp_hash": ctx.fp_hash,
        "ua_hash": ctx.ua_hash,
        "platform": normalize_text(payload.get("platform", "")) or "web",
        "app_version": normalize_text(payload.get("app_version", "")) or "1.0.0",
    }


def _persist_auth_context(user_id: int, claims: dict) -> None:
    auth_ctx = AuthContext(
        user_id=user_id,
        jti=claims["jti"],
        token_type=claims["type"],
        ip=claims["ip"],
        ip_prefix=claims["ip_prefix"],
        fp_hash=claims["fp_hash"],
        ua_hash=claims["ua_hash"],
        platform=claims["platform"],
        app_version=claims["app_version"],
        issued_at=datetime.fromtimestamp(claims["iat"], tz=timezone.utc).replace(tzinfo=None),
        expires_at=datetime.fromtimestamp(claims["exp"], tz=timezone.utc).replace(tzinfo=None),
    )
    db.session.add(auth_ctx)


def _issue_and_store_tokens(user_id: int, context_claims: dict) -> dict:
    access_token, access_claims = issue_token(
        user_id=user_id,
        token_type="access",
        context_claims=context_claims,
        config=current_app.config,
    )
    refresh_token, refresh_claims = issue_token(
        user_id=user_id,
        token_type="refresh",
        context_claims=context_claims,
        config=current_app.config,
    )

    _persist_auth_context(user_id, access_claims)
    _persist_auth_context(user_id, refresh_claims)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "access_expires_at": datetime.fromtimestamp(access_claims["exp"], tz=timezone.utc).isoformat(),
        "refresh_expires_at": datetime.fromtimestamp(refresh_claims["exp"], tz=timezone.utc).isoformat(),
    }


@auth_bp.post("/register")
def register():
    payload = request.get_json(silent=True) or {}
    is_valid, error_message = _validate_payload(payload)
    if not is_valid:
        return jsonify({"error": "invalid_payload", "message": error_message}), 400

    email = normalize_text(payload["email"]).lower()
    if User.query.filter_by(email=email).first() is not None:
        return jsonify({"error": "email_exists", "message": "Email is already registered"}), 409

    try:
        context_claims = _build_context_claims(payload)
    except ValueError as exc:
        return jsonify({"error": "invalid_request", "message": str(exc)}), 400

    user = User(email=email)
    user.set_password(payload["password"])
    db.session.add(user)
    db.session.flush()
    ensure_profile(user.id)

    token_payload = _issue_and_store_tokens(user.id, context_claims)
    db.session.commit()

    return (
        jsonify(
            {
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "created_at": user.created_at.replace(tzinfo=timezone.utc).isoformat(),
                },
                **token_payload,
            }
        ),
        201,
    )


@auth_bp.post("/login")
def login():
    payload = request.get_json(silent=True) or {}
    is_valid, error_message = _validate_payload(payload)
    if not is_valid:
        return jsonify({"error": "invalid_payload", "message": error_message}), 400

    email = normalize_text(payload["email"]).lower()
    user = User.query.filter_by(email=email).first()
    if user is None or not user.check_password(payload["password"]):
        return jsonify({"error": "invalid_credentials", "message": "Invalid email or password"}), 401
    ensure_profile(user.id)

    try:
        context_claims = _build_context_claims(payload)
    except ValueError as exc:
        return jsonify({"error": "invalid_request", "message": str(exc)}), 400

    token_payload = _issue_and_store_tokens(user.id, context_claims)
    db.session.commit()

    return jsonify(token_payload), 200
