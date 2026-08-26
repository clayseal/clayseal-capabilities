"""Safe outbound HTTP for operator-configured URLs (SSRF defense).

Every layer that fetches OIDC discovery documents, JWKS, CIMD client metadata,
exporter endpoints, or SCRAPI transparency services should route through these
helpers so production deployments get a consistent posture:

- HTTPS only (unless ``allow_http`` for tests)
- No redirects
- DNS resolution with rejection of private/link-local/loopback/metadata addresses
- Optional host allowlist (``AGENTAUTH_HTTP_ALLOWED_HOSTS``)
- In production, an allowlist is required before any fetch proceeds
- Connections pin to the first resolved global IP (DNS rebinding defense)
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import urllib.request
from typing import Any
from urllib.parse import urlsplit, urlunsplit

_BLOCKED_HOSTNAMES = frozenset(
    {"localhost", "localhost.localdomain", "ip6-localhost", "metadata.google.internal"}
)
_METADATA_IPV4 = ipaddress.ip_address("169.254.169.254")
_ALLOWED_HOSTS_ENV = "AGENTAUTH_HTTP_ALLOWED_HOSTS"
_ALLOW_SUBDOMAINS_ENV = "AGENTAUTH_HTTP_ALLOW_SUBDOMAINS"
_PRODUCTION_ENVS = frozenset({"production", "prod"})
_LOG = logging.getLogger(__name__)


class SafeHttpError(ValueError):
    """Outbound URL rejected by the safe-fetch policy."""


def _deployment_is_production() -> bool:
    for name in ("AGENTAUTH_ENV", "AGENT_RECEIPTS_ENV"):
        if os.environ.get(name, "").strip().lower() in _PRODUCTION_ENVS:
            return True
    return False


def allowed_hosts_from_env() -> list[str]:
    raw = os.environ.get(_ALLOWED_HOSTS_ENV, "").strip()
    if not raw:
        return []
    return [item.strip().lower().rstrip(".") for item in raw.split(",") if item.strip()]


def _allow_subdomains() -> bool:
    raw = os.environ.get(_ALLOW_SUBDOMAINS_ENV, "").strip().lower()
    if raw in {"0", "false", "no", "off"}:
        return False
    if raw in {"1", "true", "yes", "on"}:
        return True
    # Safer default in production: exact host matches only.
    return not _deployment_is_production()


def _host_matches_allowlist(host: str, allowed_hosts: list[str]) -> bool:
    normalized = host.lower().rstrip(".")
    for item in allowed_hosts:
        candidate = item.lower().rstrip(".")
        if normalized == candidate:
            return True
        if _allow_subdomains() and normalized.endswith(f".{candidate}"):
            return True
    return False


def _is_global_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_reserved
        and not address.is_multicast
        and address != _METADATA_IPV4
    )


def _resolve_host_ips(hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SafeHttpError(f"DNS resolution failed for host {hostname!r}") from exc
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for _family, _type, _proto, _canonname, sockaddr in infos:
        ip_text = sockaddr[0]
        try:
            addresses.append(ipaddress.ip_address(ip_text))
        except ValueError:
            continue
    if not addresses:
        raise SafeHttpError(f"DNS resolution returned no addresses for host {hostname!r}")
    return addresses


def _pinned_target(
    validated_url: str,
    *,
    resolve_dns: bool = True,
) -> tuple[str, str, int | None]:
    """Return ``(connect_host, host_header, port)`` for a pinned outbound request."""
    parts = urlsplit(validated_url)
    host = (parts.hostname or "").strip().lower().rstrip(".")
    port = parts.port
    default_port = 443 if parts.scheme == "https" else 80
    if port is None:
        port = default_port

    try:
        literal = ipaddress.ip_address(host)
        if not _is_global_ip(literal):
            raise SafeHttpError(f"outbound host {host!r} is not a globally routable address")
        connect_host = host
    except ValueError:
        if resolve_dns:
            # Re-check this resolution: it is a second lookup, and a rebinding
            # DNS server may answer differently than it did during validation.
            ips = [ip for ip in _resolve_host_ips(host) if _is_global_ip(ip)]
            if not ips:
                raise SafeHttpError(
                    f"outbound host {host!r} resolves to no globally routable address"
                ) from None
            connect_host = str(ips[0])
        else:
            connect_host = host

    host_header = host if port in (80, 443) else f"{host}:{port}"
    return connect_host, host_header, port


def validate_outbound_url(
    url: str,
    *,
    allowed_hosts: list[str] | None = None,
    require_https: bool = True,
    resolve_dns: bool = True,
) -> str:
    """Validate ``url`` for outbound fetch; return normalized URL or raise."""
    parts = urlsplit(url)
    if parts.username or parts.password:
        raise SafeHttpError("outbound URL must not embed credentials")
    if parts.fragment:
        raise SafeHttpError("outbound URL must not carry a fragment")
    if require_https and parts.scheme != "https":
        raise SafeHttpError(f"outbound URL must use https (got {parts.scheme!r})")
    if parts.scheme not in {"https", "http"}:
        raise SafeHttpError(f"unsupported URL scheme {parts.scheme!r}")

    host = (parts.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise SafeHttpError("outbound URL must include a host")

    if host in _BLOCKED_HOSTNAMES:
        raise SafeHttpError(f"outbound host {host!r} is blocked")

    allowlist = list(allowed_hosts if allowed_hosts is not None else allowed_hosts_from_env())
    if _deployment_is_production() and not allowlist:
        raise SafeHttpError(
            f"{_ALLOWED_HOSTS_ENV} must be set in production before outbound HTTP fetches "
            "are permitted (SSRF defense)"
        )
    if allowlist and not _host_matches_allowlist(host, allowlist):
        raise SafeHttpError(f"outbound host {host!r} is not in the HTTP allowlist")

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        if not _is_global_ip(literal):
            raise SafeHttpError(f"outbound host {host!r} is not a globally routable address")
    elif resolve_dns:
        for address in _resolve_host_ips(host):
            if not _is_global_ip(address):
                raise SafeHttpError(
                    f"outbound host {host!r} resolves to non-global address {address!r}"
                )

    # Rebuild without credentials/fragment (defense in depth).
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


def _httpx_request(
    method: str,
    url: str,
    *,
    timeout: float = 10.0,
    headers: dict[str, str] | None = None,
    allowed_hosts: list[str] | None = None,
    require_https: bool = True,
    content: bytes | None = None,
) -> bytes:
    validated = validate_outbound_url(url, allowed_hosts=allowed_hosts, require_https=require_https)
    connect_host, host_header, port = _pinned_target(validated)
    parts = urlsplit(validated)
    scheme = parts.scheme
    default_port = 443 if scheme == "https" else 80
    netloc = connect_host if port == default_port else f"{connect_host}:{port}"
    request_url = urlunsplit((scheme, netloc, parts.path, parts.query, ""))

    merged_headers = dict(headers or {})
    if connect_host != (parts.hostname or ""):
        merged_headers["Host"] = host_header

    import httpx

    extensions: dict[str, Any] = {}
    if scheme == "https":
        extensions["sni_hostname"] = parts.hostname or host_header.split(":")[0]

    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        response = client.request(
            method,
            request_url,
            headers=merged_headers,
            content=content,
            extensions=extensions,
        )
        response.raise_for_status()
        return response.content


def safe_http_get(
    url: str,
    *,
    timeout: float = 10.0,
    headers: dict[str, str] | None = None,
    allowed_hosts: list[str] | None = None,
    require_https: bool = True,
) -> bytes:
    """GET ``url`` with SSRF checks; return response body bytes."""
    return _httpx_request(
        "GET",
        url,
        timeout=timeout,
        headers=headers,
        allowed_hosts=allowed_hosts,
        require_https=require_https,
    )


def safe_http_post(
    url: str,
    *,
    body: bytes,
    timeout: float = 10.0,
    headers: dict[str, str] | None = None,
    allowed_hosts: list[str] | None = None,
    require_https: bool = True,
) -> bytes:
    """POST ``url`` with SSRF checks; return response body bytes."""
    return _httpx_request(
        "POST",
        url,
        timeout=timeout,
        headers=headers,
        allowed_hosts=allowed_hosts,
        require_https=require_https,
        content=body,
    )


def safe_http_get_json(
    url: str,
    *,
    timeout: float = 10.0,
    headers: dict[str, str] | None = None,
    allowed_hosts: list[str] | None = None,
    require_https: bool = True,
) -> Any:
    payload = safe_http_get(
        url,
        timeout=timeout,
        headers={"Accept": "application/json", **(headers or {})},
        allowed_hosts=allowed_hosts,
        require_https=require_https,
    )
    return json.loads(payload.decode("utf-8"))


def safe_urlopen(
    url: str,
    *,
    timeout: float = 10.0,
    headers: dict[str, str] | None = None,
    allowed_hosts: list[str] | None = None,
    require_https: bool = True,
    method: str = "GET",
    data: bytes | None = None,
) -> bytes:
    """Safe HTTP via pinned httpx transport (urllib-compatible signature)."""
    if method.upper() == "GET" and not data:
        return safe_http_get(
            url,
            timeout=timeout,
            headers=headers,
            allowed_hosts=allowed_hosts,
            require_https=require_https,
        )
    return safe_http_post(
        url,
        body=data or b"",
        timeout=timeout,
        headers=headers,
        allowed_hosts=allowed_hosts,
        require_https=require_https,
    )


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SafeHttpError("outbound redirects are not permitted")
