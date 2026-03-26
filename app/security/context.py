from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress

from flask import Request


@dataclass(frozen=True)
class ClientContext:
    ip: str
    ip_prefix: str
    fp_hash: str
    ua_hash: str


def normalize_text(value: str | None) -> str:
    if not value:
        return ""
    return " ".join(value.strip().split())


def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def get_client_ip(request: Request, trust_proxy_headers: bool) -> str:
    if trust_proxy_headers:
        forwarded_for = request.headers.get("X-Forwarded-For", "")
        if forwarded_for.strip():
            first = forwarded_for.split(",")[0].strip()
            if first:
                return first
    return request.remote_addr or "0.0.0.0"


def ip_prefix_from_ip(ip_value: str) -> str:
    try:
        parsed = ipaddress.ip_address(ip_value)
    except ValueError:
        return ip_value

    if parsed.version == 4:
        network = ipaddress.ip_network(f"{parsed}/24", strict=False)
        return str(network)

    return str(parsed)


def context_from_request(request: Request, trust_proxy_headers: bool, device_fingerprint: str) -> ClientContext:
    ip = get_client_ip(request, trust_proxy_headers)
    ua_raw = normalize_text(request.headers.get("User-Agent", ""))
    fp_raw = normalize_text(device_fingerprint)

    return ClientContext(
        ip=ip,
        ip_prefix=ip_prefix_from_ip(ip),
        fp_hash=hash_value(fp_raw),
        ua_hash=hash_value(ua_raw),
    )


def ip_matches_policy(token_ip: str, token_ip_prefix: str, current_ip: str) -> bool:
    try:
        token_parsed = ipaddress.ip_address(token_ip)
        current_parsed = ipaddress.ip_address(current_ip)
    except ValueError:
        return token_ip == current_ip

    if token_parsed.version != current_parsed.version:
        return False

    if token_parsed.version == 4:
        try:
            network = ipaddress.ip_network(token_ip_prefix, strict=False)
        except ValueError:
            return token_ip == current_ip
        return current_parsed in network

    return token_ip == current_ip


def validate_token_context(
    claims: dict,
    *,
    current_ip: str,
    current_fp_hash: str,
    current_ua_hash: str,
) -> tuple[bool, list[str]]:
    reasons: list[str] = []

    if claims.get("fp_hash") != current_fp_hash:
        reasons.append("fingerprint_mismatch")

    if claims.get("ua_hash") != current_ua_hash:
        reasons.append("user_agent_mismatch")

    token_ip = claims.get("ip", "")
    token_ip_prefix = claims.get("ip_prefix", token_ip)
    if not ip_matches_policy(token_ip, token_ip_prefix, current_ip):
        reasons.append("ip_mismatch")

    return (len(reasons) == 0, reasons)
