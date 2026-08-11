"""Outbound-URL safety checks (SSRF guard).

Several endpoints accept a URL from a customer and later have the *server*
fetch it: outbound webhooks, Slack/Teams incoming webhooks, and the OIDC
issuer. Without a check, any self-registered admin can aim those at the
compose network (`http://postgres:5432`, `http://temporal:8233`) or at the
cloud metadata endpoint.

Every hostname is resolved and every resulting address must be globally
routable. Note the residual DNS-rebinding window: a name that resolves public
here could resolve private a moment later at connect time. Closing that fully
means pinning the validated IP into the connection, which httpx does not do
out of the box — this check removes the trivial attack, not the exotic one.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# Carve-outs beyond ipaddress's own is_global (which already covers loopback,
# link-local, and RFC1918). Listed explicitly so the intent is greppable.
_BLOCKED_NETWORKS = (
    ipaddress.ip_network("169.254.0.0/16"),   # link-local — cloud metadata
    ipaddress.ip_network("fd00::/8"),         # unique local
    ipaddress.ip_network("::1/128"),          # loopback v6
)


class UnsafeUrlError(ValueError):
    """Raised when a URL is not safe for the server to fetch."""


def _addresses_for(host: str) -> list[str] | None:
    """Resolved addresses, or None when the name does not resolve.

    A name that does not resolve cannot be an SSRF target — no connection is
    made — so it is not treated as unsafe. Rejecting it would mean a transient
    DNS failure blocks saving a perfectly good webhook URL. Rebinding (resolves
    public now, private later) is covered by the fetch-time checks in
    processors/outbound.py and routes/sso.py.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return None
    return sorted({i[4][0] for i in infos})


def assert_safe_outbound_url(url: str, *, require_https: bool = True) -> None:
    """Raise UnsafeUrlError unless the server may safely fetch this URL.

    Rejects non-http(s) schemes, missing hosts, and any hostname that resolves
    to a private, loopback, link-local, or otherwise non-global address.
    """
    parsed = urlparse(url)

    allowed = ("https",) if require_https else ("http", "https")
    if parsed.scheme not in allowed:
        raise UnsafeUrlError(f"URL scheme must be {' or '.join(allowed)}")
    if not parsed.hostname:
        raise UnsafeUrlError("URL has no host")

    for addr in _addresses_for(parsed.hostname) or []:
        ip = ipaddress.ip_address(addr)
        if any(ip in net for net in _BLOCKED_NETWORKS) or not ip.is_global:
            raise UnsafeUrlError(
                f"URL resolves to a non-public address ({addr}); "
                "it must be reachable on the public internet"
            )
