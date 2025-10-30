"""Password breach checker leveraging haveibeenpwned k-anonymity API."""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Optional

import requests

logger = logging.getLogger(__name__)

HIBP_API_PREFIX = "https://api.pwnedpasswords.com/range/"


@dataclass
class BreachResult:
    found: bool
    count: int


class BreachChecker:
    """Check if a password appears in the haveibeenpwned database."""

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def check_password(self, password: str) -> BreachResult:
        if not password:
            return BreachResult(found=False, count=0)

        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]

        try:
            response = self.session.get(
                f"{HIBP_API_PREFIX}{prefix}", timeout=5, headers={"Add-Padding": "true"}
            )
            response.raise_for_status()
        except requests.RequestException as exc:  # pragma: no cover - network failure
            logger.warning("HIBP request failed: %s", exc)
            return BreachResult(found=False, count=0)

        for line in response.text.splitlines():
            hash_suffix, _, count = line.partition(":")
            if hash_suffix.upper() == suffix:
                return BreachResult(found=True, count=int(count))

        return BreachResult(found=False, count=0)


__all__ = ["BreachChecker", "BreachResult"]
