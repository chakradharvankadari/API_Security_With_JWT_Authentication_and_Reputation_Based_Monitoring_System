from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from app.extensions import db
from app.models import ReputationEvent, ReputationProfile, User


@dataclass
class ReputationDecision:
    score: float
    risk_level: str
    blocked: bool
    anomaly_score: float


def classify_user(score: float) -> str:
    if score >= 80:
        return "Trusted"
    if score >= 50:
        return "Normal"
    if score >= 30:
        return "Suspicious"
    return "Malicious"


_RISK_ORDER = {
    "Trusted": 0,
    "Normal": 1,
    "Suspicious": 2,
    "Malicious": 3,
}


@lru_cache(maxsize=1)
def _load_model_bundle() -> dict | None:
    try:
        import joblib
    except Exception:
        return None

    project_root = Path(__file__).resolve().parents[2]
    bundle_path = project_root / "models" / "reputation_model_bundle.joblib"
    if not bundle_path.exists():
        return None
    try:
        return joblib.load(bundle_path)
    except Exception:
        return None


def _predict_risk_from_model(profile: ReputationProfile, fallback_risk: str) -> str:
    bundle = _load_model_bundle()
    if bundle is None:
        return fallback_risk

    model = bundle.get("model")
    label_encoder = bundle.get("label_encoder")
    feature_order = bundle.get("feature_order", [])
    if model is None or label_encoder is None or not feature_order:
        return fallback_risk

    feature_values = {
        "initial_trust_score": profile.initial_trust_score,
        "success_count": profile.success_count,
        "failure_count": profile.failure_count,
        "total_requests": profile.total_requests,
        "avg_response_time": profile.avg_response_time,
        "account_age_days": profile.account_age_days,
        "is_verified": profile.is_verified,
        "attack_count": profile.attack_count,
        "avg_anomaly_score": profile.avg_anomaly_score,
        "failed_requests": profile.failed_requests,
        "avg_api_uniqueness": profile.avg_api_uniqueness,
        "avg_sequence_length": profile.avg_sequence_length,
        "total_sessions": profile.total_sessions,
        "avg_unique_apis": profile.avg_unique_apis,
    }

    try:
        try:
            import pandas as pd

            row = pd.DataFrame([{name: float(feature_values.get(name, 0.0)) for name in feature_order}])
        except Exception:
            row = [[float(feature_values.get(name, 0.0)) for name in feature_order]]
        prediction = model.predict(row)
        return str(label_encoder.inverse_transform(prediction)[0])
    except Exception:
        return fallback_risk


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def calculate_reputation(profile: ReputationProfile) -> float:
    score = profile.initial_trust_score
    score += profile.success_count * 0.3
    score -= profile.failure_count * 0.6
    score -= profile.attack_count * 12
    score -= profile.avg_anomaly_score * 15
    if profile.is_verified == 1:
        score += 5
    return max(0.0, min(100.0, score))


def ensure_profile(user_id: int) -> ReputationProfile:
    profile = ReputationProfile.query.filter_by(user_id=user_id).first()
    if profile is None:
        user = db.session.get(User, user_id)
        if user is None:
            raise ValueError(f"User not found: {user_id}")
        profile = ReputationProfile(
            user_id=user_id,
            initial_trust_score=50.0,
            reputation_score=50.0,
            risk_level="Normal",
            account_age_days=max(0.0, (_utcnow_naive() - user.created_at).total_seconds() / 86400.0),
        )
        db.session.add(profile)
        db.session.flush()
    return profile


def _rolling_average(previous_avg: float, current_count: int, new_value: float) -> float:
    if current_count <= 0:
        return float(new_value)
    return ((previous_avg * current_count) + new_value) / (current_count + 1)


def _estimate_anomaly_score(*, response_status: int, response_time_ms: float) -> float:
    time_component = min(1.0, response_time_ms / 5000.0)
    status_component = 1.0 if response_status >= 500 else (0.6 if response_status >= 400 else 0.0)
    score = (0.6 * time_component) + (0.4 * status_component)
    return max(0.0, min(1.0, score))


def update_reputation_for_request(
    *,
    user_id: int,
    endpoint: str,
    method: str,
    response_status: int,
    response_time_ms: float,
) -> ReputationDecision:
    profile = ensure_profile(user_id)

    profile.account_age_days = max(0.0, (_utcnow_naive() - profile.user.created_at).total_seconds() / 86400.0)
    profile.total_requests += 1
    profile.total_sessions = max(1, profile.total_sessions)

    if response_status >= 400:
        profile.failure_count += 1
        profile.failed_requests += 1
    else:
        profile.success_count += 1

    anomaly_score = _estimate_anomaly_score(response_status=response_status, response_time_ms=response_time_ms)
    if anomaly_score >= 0.85:
        profile.attack_count += 1

    prior_total = max(0, profile.total_requests - 1)
    profile.avg_response_time = _rolling_average(profile.avg_response_time, prior_total, response_time_ms)
    profile.avg_anomaly_score = _rolling_average(profile.avg_anomaly_score, prior_total, anomaly_score)

    score = calculate_reputation(profile)
    rule_based_risk = classify_user(score)
    model_risk = _predict_risk_from_model(profile, fallback_risk=rule_based_risk)
    risk_level = model_risk
    if _RISK_ORDER.get(rule_based_risk, 0) > _RISK_ORDER.get(model_risk, 0):
        risk_level = rule_based_risk
    blocked = risk_level == "Malicious"

    profile.reputation_score = score
    profile.risk_level = risk_level
    profile.is_blocked = blocked
    if blocked and profile.blocked_at is None:
        profile.blocked_at = _utcnow_naive()

    event = ReputationEvent(
        profile_id=profile.id,
        user_id=user_id,
        endpoint=endpoint,
        method=method,
        response_status=int(response_status),
        response_time_ms=float(response_time_ms),
        anomaly_score=anomaly_score,
        predicted_risk=risk_level,
        reputation_score=score,
    )
    db.session.add(event)

    return ReputationDecision(score=score, risk_level=risk_level, blocked=blocked, anomaly_score=anomaly_score)
