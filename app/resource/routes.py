from __future__ import annotations

import time

from flask import Blueprint, g, jsonify, request

from app.reputation.service import ensure_profile
from app.security.middleware import require_enhanced_auth


resource_bp = Blueprint("resource", __name__, url_prefix="/api")


@resource_bp.post("/process")
@require_enhanced_auth
def process_request():
    payload = request.get_json(silent=True) or {}
    seconds = payload.get("seconds", 1)

    if not isinstance(seconds, (int, float)):
        return jsonify({"error": "invalid_payload", "message": "seconds must be a number"}), 400
    if seconds < 0 or seconds > 30:
        return jsonify({"error": "invalid_payload", "message": "seconds must be between 0 and 30"}), 400

    start = time.perf_counter()
    time.sleep(seconds)
    elapsed_ms = int((time.perf_counter() - start) * 1000)

    return (
        jsonify(
            {
                "message": "Request processed",
                "requested_seconds": seconds,
                "response_time_ms": elapsed_ms,
                "status_code": 200,
            }
        ),
        200,
    )


@resource_bp.get("/reputation/me")
@require_enhanced_auth
def my_reputation():
    profile = ensure_profile(g.user_id)
    return (
        jsonify(
            {
                "user_id": profile.user_id,
                "reputation_score": round(profile.reputation_score, 2),
                "risk_level": profile.risk_level,
                "is_blocked": profile.is_blocked,
                "stats": {
                    "total_requests": profile.total_requests,
                    "success_count": profile.success_count,
                    "failure_count": profile.failure_count,
                    "attack_count": profile.attack_count,
                    "avg_anomaly_score": round(profile.avg_anomaly_score, 4),
                    "avg_response_time_ms": round(profile.avg_response_time, 2),
                },
            }
        ),
        200,
    )
