"""Base feed class."""
from __future__ import annotations

import pathlib

from ..models import IOC


class FeedError(RuntimeError):
    """Raised when a feed cannot be fetched or parsed."""


class Feed:
    """Base class for a threat intel feed.

    Subclasses set ``name``/``url`` and implement :meth:`parse`. Tests and
    offline runs can set the ``local_file`` option to read from disk instead.
    """

    name = "feed"
    url: str | None = None

    def __init__(self, options: dict | None = None):
        self.options = options or {}

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
        if not self.url:
            raise FeedError(f"{self.name}: no url configured")
        response = session.get(self.url, timeout=90)
        response.raise_for_status()
        return response.content

    def parse(self, raw: bytes | str) -> list[IOC]:
        raise NotImplementedError
