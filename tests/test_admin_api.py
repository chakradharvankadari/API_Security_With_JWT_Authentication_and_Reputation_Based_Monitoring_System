from app.extensions import db
from app.models import ReputationProfile


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


def test_admin_endpoints_require_key(client, app):
    app.config["ADMIN_API_KEY"] = "admin-secret"
    res = client.get("/admin/reputation/blocked-users")
    assert res.status_code == 403


def test_admin_list_events_and_unblock(client, app):
    app.config["ADMIN_API_KEY"] = "admin-secret"
    access_token = _register_and_get_access_token(client)
    request_headers = {**_headers(), "Authorization": f"Bearer {access_token}"}

    client.post("/api/process", json={"seconds": 0}, headers=request_headers)

    with app.app_context():
        profile = ReputationProfile.query.first()
        profile.is_blocked = True
        profile.risk_level = "Malicious"
        db.session.commit()
        user_id = profile.user_id

    admin_headers = {"X-Admin-Key": "admin-secret"}

    blocked_res = client.get("/admin/reputation/blocked-users", headers=admin_headers)
    assert blocked_res.status_code == 200
    assert blocked_res.get_json()["count"] >= 1

    events_res = client.get("/admin/reputation/events?limit=10", headers=admin_headers)
    assert events_res.status_code == 200
    assert events_res.get_json()["count"] >= 1

    unblock_res = client.post(f"/admin/reputation/users/{user_id}/unblock", headers=admin_headers)
    body = unblock_res.get_json()
    assert unblock_res.status_code == 200
    assert body["is_blocked"] is False


def test_admin_summary(client, app):
    app.config["ADMIN_API_KEY"] = "admin-secret"
    access_token = _register_and_get_access_token(client)
    request_headers = {**_headers(), "Authorization": f"Bearer {access_token}"}

    client.post("/api/process", json={"seconds": 0}, headers=request_headers)

    admin_headers = {"X-Admin-Key": "admin-secret"}
    res = client.get("/admin/reputation/summary", headers=admin_headers)
    body = res.get_json()

    assert res.status_code == 200
    assert "total_profiles" in body
    assert "risk_level_counts" in body
    assert "average_reputation_score" in body
