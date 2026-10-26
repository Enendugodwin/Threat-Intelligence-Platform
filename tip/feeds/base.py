"""Base feed class."""
from __future__ import annotations

import os
import pathlib

from ..models import IOC

# abuse.ch retired the keyless CSV / JSON export URLs in 2026 (they now return
# HTTP 410 Gone). All three of their feeds require a free Auth-Key obtained at
# https://auth.abuse.ch/ and passed via this environment variable.
AUTH_KEY_ENV = "ABUSECH_AUTH_KEY"
AUTH_KEY_HELP = (
    "abuse.ch now requires a free Auth-Key (keyless exports return HTTP 410); "
    f"set {AUTH_KEY_ENV} or add it to .env - create one at https://auth.abuse.ch/"
)


class FeedError(RuntimeError):
    """Raised when a feed cannot be fetched or parsed."""


class SkipFeed(FeedError):
    """Raised when a feed is disabled by missing configuration.

    This is *not* a failure: the feed is intentionally left out of the run
    because it cannot work without user-supplied settings (e.g. an API key).
    """


class Feed:
    """Base class for a threat intel feed.

    Subclasses set ``name``/``url`` and implement :meth:`parse`. Tests and
    offline runs can set the ``local_file`` option to read from disk instead.

    Feeds that need the abuse.ch Auth-Key set ``requires_auth = True``; the key
    is taken from the feed options (``auth_key``) or the ``ABUSECH_AUTH_KEY``
    environment variable. A ``{auth_key}`` placeholder in ``url`` is expanded
    with the key.
    """

    name = "feed"
    url: str | None = None
    method = "GET"
    headers: dict[str, str] = {}
    requires_auth = False
    # Optional request payloads for POST feeds (dicts are sent as JSON/form).
    json_body: dict | None = None
    form_body: dict | None = None

    def __init__(self, options: dict | None = None):
        self.options = options or {}

    def auth_key(self) -> str | None:
        return self.options.get("auth_key") or os.environ.get(AUTH_KEY_ENV) or None

    def _resolve_request(self) -> tuple[str, dict[str, str], dict]:
        if not self.url:
            raise FeedError(f"{self.name}: no url configured")

        url = self.url
        headers = {k: v for k, v in self.headers.items()}

        if self.requires_auth or "{auth_key}" in url:
            key = self.auth_key()
            if not key:
                raise SkipFeed(f"{AUTH_KEY_ENV} not set. {AUTH_KEY_HELP}")
            url = url.replace("{auth_key}", key)
            headers.setdefault("Auth-Key", key)

        kwargs: dict = {"timeout": 90}
        if headers:
            kwargs["headers"] = headers
        if self.json_body is not None:
            kwargs["json"] = self.json_body
        elif self.form_body is not None:
            kwargs["data"] = self.form_body
        return url, headers, kwargs

    def fetch(self, session) -> list[IOC]:
        raw = self._load(session)
        return self.parse(raw)

    def _load(self, session) -> bytes | str:
        local = self.options.get("local_file")
        if local:
            path = pathlib.Path(local)
            if not path.is_file():
                raise FeedError(f"{self.name}: local_file not found: {local}")
            return path.read_bytes()

        url, _headers, kwargs = self._resolve_request()
        if session is None:  # pragma: no cover - defensive
            raise FeedError(f"{self.name}: no HTTP session available")
        if self.method == "GET":
            response = session.get(url, **kwargs)
        else:
            response = session.request(self.method, url, **kwargs)
        response.raise_for_status()
        return response.content

    def parse(self, raw: bytes | str) -> list[IOC]:
        raise NotImplementedError
