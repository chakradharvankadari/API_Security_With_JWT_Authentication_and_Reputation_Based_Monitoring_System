from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from app.extensions import db
from app.models import ReputationEvent, ReputationProfile


admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def _require_admin_key():
    configured_key = current_app.config.get("ADMIN_API_KEY", "")
    if not configured_key:
        return jsonify({"error": "admin_unavailable", "message": "ADMIN_API_KEY is not configured"}), 503

    provided_key = request.headers.get("X-Admin-Key", "")
    if provided_key != configured_key:
        return jsonify({"error": "forbidden", "message": "Invalid admin key"}), 403
    return None


@admin_bp.get("/reputation/blocked-users")
def blocked_users():
    auth_error = _require_admin_key()
    if auth_error is not None:
        return auth_error

    rows = (
        ReputationProfile.query.filter_by(is_blocked=True)
        .order_by(ReputationProfile.updated_at.desc())
        .limit(200)
        .all()
    )
    return (
        jsonify(
            {
                "count": len(rows),
                "users": [
                    {
                        "user_id": row.user_id,
                        "reputation_score": round(row.reputation_score, 2),
                        "risk_level": row.risk_level,
                        "blocked_at": row.blocked_at.isoformat() if row.blocked_at else None,
                        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
                    }
                    for row in rows
                ],
            }
        ),
        200,
    )


@admin_bp.get("/reputation/events")
def reputation_events():
    auth_error = _require_admin_key()
    if auth_error is not None:
        return auth_error

    limit = request.args.get("limit", default=50, type=int)
    if limit is None or limit <= 0 or limit > 500:
        return jsonify({"error": "invalid_request", "message": "limit must be between 1 and 500"}), 400

    user_id = request.args.get("user_id", default=None, type=int)

    query = ReputationEvent.query.order_by(ReputationEvent.created_at.desc())
    if user_id is not None:
        query = query.filter_by(user_id=user_id)
    rows = query.limit(limit).all()

    return (
        jsonify(
            {
                "count": len(rows),
                "events": [
                    {
                        "id": row.id,
                        "user_id": row.user_id,
                        "endpoint": row.endpoint,
                        "method": row.method,
                        "response_status": row.response_status,
                        "response_time_ms": row.response_time_ms,
                        "anomaly_score": row.anomaly_score,
                        "predicted_risk": row.predicted_risk,
                        "reputation_score": row.reputation_score,
                        "created_at": row.created_at.isoformat() if row.created_at else None,
                    }
                    for row in rows
                ],
            }
        ),
        200,
    )


@admin_bp.post("/reputation/users/<int:user_id>/unblock")
def unblock_user(user_id: int):
    auth_error = _require_admin_key()
    if auth_error is not None:
        return auth_error

    profile = ReputationProfile.query.filter_by(user_id=user_id).first()
    if profile is None:
        return jsonify({"error": "not_found", "message": "Reputation profile not found"}), 404

    profile.is_blocked = False
    if profile.risk_level == "Malicious":
        profile.risk_level = "Suspicious"
    db.session.commit()

    return (
        jsonify(
            {
                "message": "User unblocked",
                "user_id": profile.user_id,
                "reputation_score": round(profile.reputation_score, 2),
                "risk_level": profile.risk_level,
                "is_blocked": profile.is_blocked,
            }
        ),
        200,
    )


@admin_bp.get("/reputation/summary")
def reputation_summary():
    auth_error = _require_admin_key()
    if auth_error is not None:
        return auth_error

    all_rows = ReputationProfile.query.all()
    counts = {"Trusted": 0, "Normal": 0, "Suspicious": 0, "Malicious": 0}
    blocked_count = 0
    score_total = 0.0

    for row in all_rows:
        if row.risk_level in counts:
            counts[row.risk_level] += 1
        if row.is_blocked:
            blocked_count += 1
        score_total += row.reputation_score

    recent_blocks = (
        ReputationProfile.query.filter_by(is_blocked=True)
        .order_by(ReputationProfile.blocked_at.desc())
        .limit(10)
        .all()
    )
    average_score = (score_total / len(all_rows)) if all_rows else 0.0

    return (
        jsonify(
            {
                "total_profiles": len(all_rows),
                "blocked_users": blocked_count,
                "average_reputation_score": round(average_score, 2),
                "risk_level_counts": counts,
                "recent_blocks": [
                    {
                        "user_id": row.user_id,
                        "reputation_score": round(row.reputation_score, 2),
                        "risk_level": row.risk_level,
                        "blocked_at": row.blocked_at.isoformat() if row.blocked_at else None,
                    }
                    for row in recent_blocks
                ],
            }
        ),
        200,
    )
