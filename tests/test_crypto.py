import hashlib
import hmac

from dripstack.shared.crypto import (
    hmac_sha256_hex,
    sign_link_token,
    verify_hmac_signature,
    verify_link_token,
)


def test_hmac_matches_openssl_style_hex():
    secret = "whsec_demo_secret"
    body = '{"hello":"world"}'
    expected = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    assert hmac_sha256_hex(secret, body) == expected


def test_verify_hmac_signature_accepts_prefixed_and_raw():
    secret = "s3cr3t"
    body = "payload-bytes"
    sig = hmac_sha256_hex(secret, body)
    assert verify_hmac_signature(secret, body, f"sha256={sig}") is True
    assert verify_hmac_signature(secret, body, sig) is True
    assert verify_hmac_signature(secret, body, "sha256=deadbeef") is False
    assert verify_hmac_signature(secret, body, None) is False


def test_link_token_round_trip():
    tok = sign_link_token("link-secret", "run-1", "action", "resolve")
    assert len(tok) == 32
    assert verify_link_token("link-secret", "run-1", "action", "resolve", tok) is True
    # Tamper: different ref / scope / run must fail.
    assert verify_link_token("link-secret", "run-1", "action", "escalate", tok) is False
    assert verify_link_token("link-secret", "run-2", "action", "resolve", tok) is False
    assert verify_link_token("other-secret", "run-1", "action", "resolve", tok) is False
