from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app import create_app


def _write_rsa_keypair(target_dir: Path) -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path = target_dir / "private.pem"
    public_path = target_dir / "public.pem"

    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)

    return str(private_path), str(public_path)


@pytest.fixture()
def app(tmp_path: Path):
    private_path, public_path = _write_rsa_keypair(tmp_path)
    db_path = tmp_path / "test.db"

    flask_app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_path}",
            "JWT_PRIVATE_KEY_PATH": private_path,
            "JWT_PUBLIC_KEY_PATH": public_path,
            "JWT_ISSUER": "test-issuer",
            "JWT_AUDIENCE": "test-audience",
            "ACCESS_TOKEN_TTL_MINUTES": 15,
            "REFRESH_TOKEN_TTL_MINUTES": 60,
            "TRUST_PROXY_HEADERS": True,
        }
    )

    yield flask_app


@pytest.fixture()
def client(app):
    return app.test_client()
