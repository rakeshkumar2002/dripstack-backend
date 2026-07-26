"""Crypto utilities (port of packages/shared/src/crypto.ts).

HMAC verification here must stay byte-compatible with scripts/fire-demo-event.sh
(`openssl dgst -sha256 -hmac` → hex) and the outbound webhook signer.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def canonical_json(value: Any) -> str:
    """Stable canonical JSON (sorted keys, compact) so equal payloads hash equally."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hmac_sha256_hex(secret: str, body: str) -> str:
    return hmac.new(secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()


def safe_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def verify_hmac_signature(secret: str, raw_body: str, signature_header: str | None) -> bool:
    """Verify a generic inbound webhook signature.

    Accepts a raw hex HMAC or a `sha256=<hex>` prefixed form (GitHub/Sentry style).
    """
    if not signature_header:
        return False
    provided = signature_header[len("sha256=") :] if signature_header.startswith("sha256=") else signature_header
    return safe_equal(hmac_sha256_hex(secret, raw_body), provided)


# ── Signed tracked links (action/log URLs) ───────────────────────────────────
# token = hex(hmac(secret, f"{run_id}:{scope}:{ref}"))[:32]. Stateless, tamper-proof.


def sign_link_token(secret: str, run_id: str, scope: str, ref: str, extra: str = "") -> str:
    """HMAC token over (run_id, scope, ref[, extra]).

    `extra` binds an additional value into the signature — used for redirect
    links to bind the destination URL so it cannot be swapped (open-redirect).
    Omitted (empty) for action/log/pixel tokens, keeping them unchanged.
    """
    base = f"{run_id}:{scope}:{ref}"
    if extra:
        base = f"{base}:{extra}"
    return hmac_sha256_hex(secret, base)[:32]


def verify_link_token(secret: str, run_id: str, scope: str, ref: str, token: str, extra: str = "") -> bool:
    return safe_equal(sign_link_token(secret, run_id, scope, ref, extra), token)
