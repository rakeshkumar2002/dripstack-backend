"""Signed, tracked link builder (port of packages/core/src/links.ts).

Every link is stateless and tamper-proof: the token is an HMAC over
(run_id, scope, ref), verified by the API tracking routes before acting.
"""

from __future__ import annotations

from urllib.parse import quote

from .config import settings
from .shared.crypto import sign_link_token


class LinkBuilderImpl:
    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.base = settings().APP_BASE_URL.rstrip("/")
        self.secret = settings().LINK_SIGNING_SECRET

    def action_url(self, action: str) -> str:
        token = sign_link_token(self.secret, self.run_id, "action", action)
        return f"{self.base}/r/{self.run_id}/action/{action}?token={token}"

    def block_url(self, block_id: str) -> str:
        token = sign_link_token(self.secret, self.run_id, "log", block_id)
        return f"{self.base}/r/{self.run_id}/log/{block_id}?token={token}"

    def pixel_url(self) -> str:
        token = sign_link_token(self.secret, self.run_id, "pixel", "open")
        return f"{self.base}/r/{self.run_id}/pixel.gif?token={token}"

    def track_link(self, url: str, ref: str) -> str:
        # Bind the destination URL into the token so it can't be swapped (open-redirect).
        token = sign_link_token(self.secret, self.run_id, "link", ref, extra=url)
        return f"{self.base}/r/{self.run_id}/link/{ref}?token={token}&u={quote(url, safe='')}"


def make_link_builder(run_id: str) -> LinkBuilderImpl:
    return LinkBuilderImpl(run_id)
