from passlib.context import CryptContext


_password_ctx = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return _password_ctx.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return _password_ctx.verify(password, hashed_password)
