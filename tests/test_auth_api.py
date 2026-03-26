from datetime import datetime, timezone

from app.models import AuthContext, User
from app.security.tokens import decode_and_verify_token


def _headers(ip: str = "10.20.30.40") -> dict:
    return {
        "X-Device-Fingerprint": "device-abc-123",
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


def _minimal_payload(email: str = "min@example.com", password: str = "StrongPassword#123") -> dict:
    return {
        "email": email,
        "password": password,
    }


def test_register_success(client, app):
    res = client.post("/auth/register", json=_payload(), headers=_headers())
    body = res.get_json()

    assert res.status_code == 201
    assert "user" in body
    assert "access_token" in body and "refresh_token" in body

    with app.app_context():
        user = User.query.filter_by(email="alice@example.com").first()
        assert user is not None
        assert user.password_hash != "StrongPassword#123"

        contexts = AuthContext.query.filter_by(user_id=user.id).all()
        assert len(contexts) == 2
        assert all(ctx.fp_hash != "device-abc-123" for ctx in contexts)


def test_register_duplicate_email(client):
    client.post("/auth/register", json=_payload(), headers=_headers())
    res = client.post("/auth/register", json=_payload(), headers=_headers())

    assert res.status_code == 409


def test_register_missing_fingerprint(client):
    headers = _headers()
    headers.pop("X-Device-Fingerprint")
    res = client.post("/auth/register", json=_payload(), headers=headers)

    assert res.status_code == 400


def test_login_success(client):
    client.post("/auth/register", json=_payload(), headers=_headers())
    res = client.post("/auth/login", json=_payload(), headers=_headers("10.20.30.99"))
    body = res.get_json()

    assert res.status_code == 200
    assert "access_token" in body
    assert "refresh_token" in body


def test_login_wrong_password(client):
    client.post("/auth/register", json=_payload(), headers=_headers())
    bad = _payload(password="bad-pass")
    res = client.post("/auth/login", json=bad, headers=_headers())

    assert res.status_code == 401


def test_token_claims_and_timestamps(client, app):
    res = client.post("/auth/register", json=_payload(), headers=_headers("10.20.30.40"))
    body = res.get_json()

    with app.app_context():
        claims = decode_and_verify_token(body["access_token"], app.config)

    assert claims["type"] == "access"
    assert claims["ip"] == "10.20.30.40"
    assert claims["ip_prefix"] == "10.20.30.0/24"
    assert claims["platform"] == "web"
    assert claims["app_version"] == "1.0.0"

    issued = datetime.fromtimestamp(claims["iat"], tz=timezone.utc)
    expires = datetime.fromtimestamp(claims["exp"], tz=timezone.utc)
    assert expires > issued


def test_register_with_minimal_payload(client):
    res = client.post("/auth/register", json=_minimal_payload(), headers=_headers())
    body = res.get_json()

    assert res.status_code == 201
    assert "access_token" in body


def test_login_with_minimal_payload(client):
    client.post("/auth/register", json=_minimal_payload(), headers=_headers())
    res = client.post("/auth/login", json=_minimal_payload(), headers=_headers())
    body = res.get_json()

    assert res.status_code == 200
    assert "access_token" in body
