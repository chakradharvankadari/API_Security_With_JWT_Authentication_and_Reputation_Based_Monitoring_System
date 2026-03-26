from app.extensions import db
from app.models import ReputationEvent, ReputationProfile


def _headers(ip: str = "10.20.30.40", fp: str = "device-abc-123") -> dict:
    return {
        "X-Device-Fingerprint": fp,
        "User-Agent": "pytest-agent/1.0",
        "X-Forwarded-For": ip,
    }


def _payload(email: str = "alice@example.com", password: str = "StrongPassword#123") -> dict:
    return {
        "email": email,
        "password": password,
        "platform": "web",
        "app_version": "1.0.0",
    }


def _register_and_get_access_token(client) -> str:
    res = client.post("/auth/register", json=_payload(), headers=_headers())
    return res.get_json()["access_token"]


def test_process_success_with_enhanced_auth(client):
    access_token = _register_and_get_access_token(client)
    headers = {
        **_headers(),
        "Authorization": f"Bearer {access_token}",
    }
    res = client.post("/api/process", json={"seconds": 0}, headers=headers)
    body = res.get_json()

    assert res.status_code == 200
    assert body["requested_seconds"] == 0
    assert body["status_code"] == 200
    assert isinstance(body["response_time_ms"], int)
    assert "X-Reputation-Score" in res.headers
    assert "X-Reputation-Risk" in res.headers


def test_process_requires_bearer_token(client):
    res = client.post("/api/process", json={"seconds": 0}, headers=_headers())
    assert res.status_code == 401


def test_process_blocks_context_mismatch(client):
    access_token = _register_and_get_access_token(client)
    mismatched_headers = {
        **_headers(fp="another-device"),
        "Authorization": f"Bearer {access_token}",
    }
    res = client.post("/api/process", json={"seconds": 0}, headers=mismatched_headers)
    body = res.get_json()

    assert res.status_code == 403
    assert body["error"] == "context_mismatch"
    assert "fingerprint_mismatch" in body["reasons"]


def test_reputation_event_is_stored(client, app):
    access_token = _register_and_get_access_token(client)
    headers = {**_headers(), "Authorization": f"Bearer {access_token}"}
    client.post("/api/process", json={"seconds": 0}, headers=headers)

    with app.app_context():
        profile = ReputationProfile.query.first()
        assert profile is not None
        assert profile.total_requests >= 1
        events = ReputationEvent.query.filter_by(user_id=profile.user_id).all()
        assert len(events) >= 1


def test_blocked_user_cannot_access_protected_api(client, app):
    access_token = _register_and_get_access_token(client)
    headers = {**_headers(), "Authorization": f"Bearer {access_token}"}

    with app.app_context():
        profile = ReputationProfile.query.first()
        profile.is_blocked = True
        profile.risk_level = "Malicious"
        db.session.commit()

    res = client.post("/api/process", json={"seconds": 0}, headers=headers)
    assert res.status_code == 403


def test_get_my_reputation(client):
    access_token = _register_and_get_access_token(client)
    headers = {**_headers(), "Authorization": f"Bearer {access_token}"}
    res = client.get("/api/reputation/me", headers=headers)
    body = res.get_json()

    assert res.status_code == 200
    assert "reputation_score" in body
    assert "risk_level" in body
