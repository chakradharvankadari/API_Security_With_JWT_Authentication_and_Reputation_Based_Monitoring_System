import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///app.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_ISSUER = os.getenv("JWT_ISSUER", "major-api")
    JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "major-clients")

    ACCESS_TOKEN_TTL_MINUTES = int(os.getenv("ACCESS_TOKEN_TTL_MINUTES", "15"))
    REFRESH_TOKEN_TTL_MINUTES = int(os.getenv("REFRESH_TOKEN_TTL_MINUTES", "10080"))

    TRUST_PROXY_HEADERS = _as_bool(os.getenv("TRUST_PROXY_HEADERS"), default=True)

    JWT_PRIVATE_KEY_PATH = str(Path(os.getenv("JWT_PRIVATE_KEY_PATH", "")))
    JWT_PUBLIC_KEY_PATH = str(Path(os.getenv("JWT_PUBLIC_KEY_PATH", "")))
    ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")
