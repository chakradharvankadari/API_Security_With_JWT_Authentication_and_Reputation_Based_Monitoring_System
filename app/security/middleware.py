from __future__ import annotations

from functools import wraps
import time

from flask import current_app, g, jsonify, request

from app.extensions import db
from app.reputation.service import ensure_profile, update_reputation_for_request
from app.security.context import context_from_request, normalize_text, validate_token_context
from app.security.tokens import decode_and_verify_token


def _extract_bearer_token() -> str | None:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header[7:].strip()
    return token or None


def require_enhanced_auth(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        start = time.perf_counter()
        token = _extract_bearer_token()
        if token is None:
            return jsonify({"error": "unauthorized", "message": "Missing or invalid Bearer token"}), 401

        device_fingerprint = normalize_text(request.headers.get("X-Device-Fingerprint", ""))
        if not device_fingerprint:
            return jsonify({"error": "invalid_request", "message": "Missing required header: X-Device-Fingerprint"}), 400

        try:
            claims = decode_and_verify_token(token, current_app.config)
        except Exception:
            return jsonify({"error": "unauthorized", "message": "Invalid or expired token"}), 401

        if claims.get("type") != "access":
            return jsonify({"error": "unauthorized", "message": "Access token required"}), 401

        current_ctx = context_from_request(
            request,
            trust_proxy_headers=current_app.config["TRUST_PROXY_HEADERS"],
            device_fingerprint=device_fingerprint,
        )
        is_valid, reasons = validate_token_context(
            claims,
            current_ip=current_ctx.ip,
            current_fp_hash=current_ctx.fp_hash,
            current_ua_hash=current_ctx.ua_hash,
        )
        if not is_valid:
            return (
                jsonify(
                    {
                        "error": "context_mismatch",
                        "message": "Request context changed. Please login again.",
                        "reasons": reasons,
                    }
                ),
                403,
            )

        g.auth_claims = claims
        g.user_id = int(claims["sub"])

        profile = ensure_profile(g.user_id)
        if profile.is_blocked:
            return jsonify({"error": "forbidden", "message": "User is blocked by reputation policy"}), 403

        result = view_func(*args, **kwargs)
        response = current_app.make_response(result)

        elapsed_ms = max(0.0, (time.perf_counter() - start) * 1000.0)
        decision = update_reputation_for_request(
            user_id=g.user_id,
            endpoint=request.path,
            method=request.method,
            response_status=response.status_code,
            response_time_ms=elapsed_ms,
        )
        db.session.commit()

        response.headers["X-Reputation-Score"] = f"{decision.score:.2f}"
        response.headers["X-Reputation-Risk"] = decision.risk_level
        if decision.blocked:
            response.headers["X-Reputation-Blocked"] = "true"

        return response

    return wrapped
