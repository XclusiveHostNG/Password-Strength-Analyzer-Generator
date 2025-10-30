"""Secure password generator with customizable rules."""
from __future__ import annotations

import secrets
import string
from dataclasses import dataclass


def build_charset(
    use_lowercase: bool = True,
    use_uppercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    extra_chars: str | None = None,
) -> str:
    """Return a character set based on the provided flags."""
    charset = ""
    if use_lowercase:
        charset += string.ascii_lowercase
    if use_uppercase:
        charset += string.ascii_uppercase
    if use_digits:
        charset += string.digits
    if use_symbols:
        charset += "!@#$%^&*()-_=+[]{}|;:,.<>?/"
    if extra_chars:
        charset += extra_chars
    return charset


@dataclass
class GenerationOptions:
    length: int = 16
    use_lowercase: bool = True
    use_uppercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    require_each_category: bool = True


class PasswordGenerator:
    """Generate secure passwords according to configurable rules."""

    def __init__(self, options: GenerationOptions | None = None) -> None:
        self.options = options or GenerationOptions()

    def generate(self) -> str:
        opts = self.options
        if opts.length < 4:
            raise ValueError("Password length must be at least 4 characters.")

        charset = build_charset(
            use_lowercase=opts.use_lowercase,
            use_uppercase=opts.use_uppercase,
            use_digits=opts.use_digits,
            use_symbols=opts.use_symbols,
        )

        if not charset:
            raise ValueError("At least one character type must be enabled.")

        password = self._generate_password(charset, opts.length)

        if opts.require_each_category:
            password = self._enforce_categories(password)

        return password

    def _generate_password(self, charset: str, length: int) -> str:
        return "".join(secrets.choice(charset) for _ in range(length))

    def _enforce_categories(self, password: str) -> str:
        """Ensure the password contains at least one char from each enabled category."""
        opts = self.options
        categories = []
        if opts.use_lowercase:
            categories.append(string.ascii_lowercase)
        if opts.use_uppercase:
            categories.append(string.ascii_uppercase)
        if opts.use_digits:
            categories.append(string.digits)
        if opts.use_symbols:
            categories.append("!@#$%^&*()-_=+[]{}|;:,.<>?/")

        password_chars = list(password)

        for category in categories:
            if not any(c in category for c in password_chars):
                password_chars[secrets.randbelow(len(password_chars))] = secrets.choice(
                    category
                )

        secrets.SystemRandom().shuffle(password_chars)
        return "".join(password_chars)


__all__ = ["PasswordGenerator", "GenerationOptions", "build_charset"]
