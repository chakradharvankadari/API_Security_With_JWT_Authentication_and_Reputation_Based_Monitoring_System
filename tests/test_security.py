from app.security.context import hash_value, ip_matches_policy
from app.security.passwords import hash_password, verify_password


def test_password_hash_and_verify():
    password = "S3curePass!"
    hashed = hash_password(password)

    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("wrong-pass", hashed) is False


def test_hash_value_deterministic():
    value = "fingerprint-value"
    assert hash_value(value) == hash_value(value)
    assert hash_value(value) != hash_value("another")


def test_ipv4_soft_bind_policy():
    assert ip_matches_policy("10.10.10.21", "10.10.10.0/24", "10.10.10.200") is True
    assert ip_matches_policy("10.10.10.21", "10.10.10.0/24", "10.10.11.8") is False


def test_ipv6_exact_policy():
    assert ip_matches_policy("2001:db8::1", "2001:db8::1", "2001:db8::1") is True
    assert ip_matches_policy("2001:db8::1", "2001:db8::1", "2001:db8::2") is False
