from __future__ import annotations

from datetime import datetime, timezone

from app.extensions import db
from app.security.passwords import hash_password, verify_password


def utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow_naive)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow_naive, onupdate=utcnow_naive)

    auth_contexts = db.relationship("AuthContext", back_populates="user", lazy="dynamic")

    def set_password(self, password: str) -> None:
        self.password_hash = hash_password(password)

    def check_password(self, password: str) -> bool:
        return verify_password(password, self.password_hash)


class AuthContext(db.Model):
    __tablename__ = "auth_contexts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    jti = db.Column(db.String(64), nullable=False, index=True)
    token_type = db.Column(db.String(16), nullable=False)

    ip = db.Column(db.String(64), nullable=False)
    ip_prefix = db.Column(db.String(64), nullable=False)
    fp_hash = db.Column(db.String(128), nullable=False)
    ua_hash = db.Column(db.String(128), nullable=False)
    platform = db.Column(db.String(64), nullable=False)
    app_version = db.Column(db.String(64), nullable=False)

    issued_at = db.Column(db.DateTime, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow_naive)

    user = db.relationship("User", back_populates="auth_contexts")


class ReputationProfile(db.Model):
    __tablename__ = "reputation_profiles"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, unique=True, index=True)

    initial_trust_score = db.Column(db.Float, nullable=False, default=50.0)
    reputation_score = db.Column(db.Float, nullable=False, default=50.0)
    risk_level = db.Column(db.String(32), nullable=False, default="Normal")
    is_blocked = db.Column(db.Boolean, nullable=False, default=False)

    success_count = db.Column(db.Integer, nullable=False, default=0)
    failure_count = db.Column(db.Integer, nullable=False, default=0)
    total_requests = db.Column(db.Integer, nullable=False, default=0)
    failed_requests = db.Column(db.Integer, nullable=False, default=0)
    attack_count = db.Column(db.Integer, nullable=False, default=0)

    avg_anomaly_score = db.Column(db.Float, nullable=False, default=0.0)
    avg_response_time = db.Column(db.Float, nullable=False, default=0.0)
    account_age_days = db.Column(db.Float, nullable=False, default=0.0)
    is_verified = db.Column(db.Integer, nullable=False, default=0)

    avg_api_uniqueness = db.Column(db.Float, nullable=False, default=0.0)
    avg_sequence_length = db.Column(db.Float, nullable=False, default=0.0)
    total_sessions = db.Column(db.Integer, nullable=False, default=0)
    avg_unique_apis = db.Column(db.Float, nullable=False, default=0.0)

    created_at = db.Column(db.DateTime, nullable=False, default=utcnow_naive)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow_naive, onupdate=utcnow_naive)
    blocked_at = db.Column(db.DateTime, nullable=True)

    user = db.relationship("User")
    events = db.relationship("ReputationEvent", back_populates="profile", lazy="dynamic")


class ReputationEvent(db.Model):
    __tablename__ = "reputation_events"

    id = db.Column(db.Integer, primary_key=True)
    profile_id = db.Column(db.Integer, db.ForeignKey("reputation_profiles.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    endpoint = db.Column(db.String(255), nullable=False)
    method = db.Column(db.String(16), nullable=False)
    response_status = db.Column(db.Integer, nullable=False)
    response_time_ms = db.Column(db.Float, nullable=False)
    anomaly_score = db.Column(db.Float, nullable=False)
    predicted_risk = db.Column(db.String(32), nullable=False)
    reputation_score = db.Column(db.Float, nullable=False)

    created_at = db.Column(db.DateTime, nullable=False, default=utcnow_naive)

    profile = db.relationship("ReputationProfile", back_populates="events")
