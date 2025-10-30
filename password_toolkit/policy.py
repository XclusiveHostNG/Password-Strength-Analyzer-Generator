"""Password policy validation utilities."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List


@dataclass
class Policy:
    min_length: int = 12
    max_length: int | None = None
    require_lowercase: bool = True
    require_uppercase: bool = True
    require_digits: bool = True
    require_symbols: bool = True
    disallow_common_passwords: bool = True
    disallow_repeated: bool = True
    disallow_sequences: bool = True


class PolicyValidator:
    """Validate passwords against a configurable policy."""

    SYMBOL_REGEX = re.compile(r"[^A-Za-z0-9]")
    REPEAT_REGEX = re.compile(r"(.)\1{2,}")
    SEQUENCE_REGEXES = [
        re.compile(r"0123"),
        re.compile(r"1234"),
        re.compile(r"abcd", re.IGNORECASE),
        re.compile(r"qwer", re.IGNORECASE),
    ]

    COMMON_PASSWORDS = {
        "password",
        "123456",
        "qwerty",
        "letmein",
        "admin",
        "welcome",
    }

    def __init__(self, policy: Policy | None = None) -> None:
        self.policy = policy or Policy()

    def validate(self, password: str) -> Dict[str, bool]:
        checks: Dict[str, bool] = {}
        policy = self.policy

        checks["min_length"] = len(password) >= policy.min_length
        if policy.max_length is not None:
            checks["max_length"] = len(password) <= policy.max_length

        if policy.require_lowercase:
            checks["lowercase"] = any(c.islower() for c in password)
        if policy.require_uppercase:
            checks["uppercase"] = any(c.isupper() for c in password)
        if policy.require_digits:
            checks["digits"] = any(c.isdigit() for c in password)
        if policy.require_symbols:
            checks["symbols"] = bool(self.SYMBOL_REGEX.search(password))

        if policy.disallow_common_passwords:
            checks["common_password"] = password.lower() not in self.COMMON_PASSWORDS
        if policy.disallow_repeated:
            checks["repeated_chars"] = not self.REPEAT_REGEX.search(password)
        if policy.disallow_sequences:
            checks["sequences"] = not any(regex.search(password) for regex in self.SEQUENCE_REGEXES)

        return checks

    def is_valid(self, password: str) -> bool:
        checks = self.validate(password)
        return all(checks.values())


__all__ = ["Policy", "PolicyValidator"]
