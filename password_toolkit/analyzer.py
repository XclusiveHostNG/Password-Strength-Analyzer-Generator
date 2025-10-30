"""Password strength analyzer using entropy and pattern detection."""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import List

COMMON_PASSWORDS = {
    "password",
    "123456",
    "123456789",
    "qwerty",
    "abc123",
    "letmein",
    "111111",
    "123123",
    "welcome",
    "admin",
}

SEQUENTIAL_PATTERNS = [
    "0123456789",
    "abcdefghijklmnopqrstuvwxyz",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]


@dataclass
class PatternFinding:
    """Details for detected password patterns."""

    description: str
    severity: str


@dataclass
class StrengthReport:
    """Comprehensive password strength report."""

    password: str
    entropy: float
    complexity: str
    length: int
    char_space: int
    issues: List[PatternFinding]
    suggestions: List[str]
    score: int


class PasswordStrengthAnalyzer:
    """Analyze password strength using entropy and heuristic checks."""

    ENTROPY_THRESHOLDS = {
        "Very Weak": 0,
        "Weak": 28,
        "Moderate": 36,
        "Strong": 60,
        "Very Strong": 100,
    }

    def analyze(self, password: str) -> StrengthReport:
        """Return a detailed strength report for ``password``."""

        entropy, char_space = self._calculate_entropy(password)
        complexity = self._classify_entropy(entropy)
        issues = self._find_issues(password)
        suggestions = self._generate_suggestions(password, issues)
        score = self._score_password(entropy, issues)

        return StrengthReport(
            password=password,
            entropy=round(entropy, 2),
            complexity=complexity,
            length=len(password),
            char_space=char_space,
            issues=issues,
            suggestions=suggestions,
            score=score,
        )

    def _calculate_entropy(self, password: str) -> (float, int):
        if not password:
            return 0.0, 0

        char_space = 0
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digits = any(c.isdigit() for c in password)
        has_symbols = any(not c.isalnum() for c in password)

        if has_lower:
            char_space += 26
        if has_upper:
            char_space += 26
        if has_digits:
            char_space += 10
        if has_symbols:
            char_space += 33  # rough estimate of printable symbols

        entropy = len(password) * math.log2(char_space or 1)
        return entropy, char_space

    def _classify_entropy(self, entropy: float) -> str:
        last_label = "Very Weak"
        for label, threshold in self.ENTROPY_THRESHOLDS.items():
            if entropy >= threshold:
                last_label = label
            else:
                break
        return last_label

    def _find_issues(self, password: str) -> List[PatternFinding]:
        issues: List[PatternFinding] = []

        if not password:
            issues.append(
                PatternFinding(
                    description="Password cannot be empty.", severity="high"
                )
            )
            return issues

        if password.lower() in COMMON_PASSWORDS:
            issues.append(
                PatternFinding(
                    description="Password found in common password list.",
                    severity="high",
                )
            )

        if len(password) < 12:
            issues.append(
                PatternFinding(
                    description="Password shorter than 12 characters.",
                    severity="medium",
                )
            )

        if re.search(r"(.)\1{2,}", password):
            issues.append(
                PatternFinding(
                    description="Contains repeated characters (aaa, 111).",
                    severity="medium",
                )
            )

        if self._has_sequences(password):
            issues.append(
                PatternFinding(
                    description="Contains sequential keyboard or alphabetical patterns.",
                    severity="medium",
                )
            )

        if password.isdigit():
            issues.append(
                PatternFinding(
                    description="Password contains only numbers.", severity="high"
                )
            )
        elif password.isalpha():
            issues.append(
                PatternFinding(
                    description="Password contains only letters.", severity="medium"
                )
            )

        if not any(c.islower() for c in password):
            issues.append(
                PatternFinding(
                    description="Add lowercase letters for better diversity.",
                    severity="low",
                )
            )
        if not any(c.isupper() for c in password):
            issues.append(
                PatternFinding(
                    description="Add uppercase letters for better diversity.",
                    severity="low",
                )
            )
        if not any(c.isdigit() for c in password):
            issues.append(
                PatternFinding(
                    description="Include digits to increase complexity.",
                    severity="low",
                )
            )
        if not any(not c.isalnum() for c in password):
            issues.append(
                PatternFinding(
                    description="Add special characters to resist brute force.",
                    severity="low",
                )
            )

        return issues

    def _generate_suggestions(
        self, password: str, issues: List[PatternFinding]
    ) -> List[str]:
        suggestions = {
            "Password shorter than 12 characters.": "Increase password length to at least 14 characters for improved resistance to guessing attacks.",
            "Contains repeated characters (aaa, 111).": "Avoid repeating characters or predictable patterns.",
            "Contains sequential keyboard or alphabetical patterns.": "Mix characters and avoid sequences like 'abcd' or '1234'.",
            "Password contains only numbers.": "Combine numbers with letters and symbols.",
            "Password contains only letters.": "Mix letters with numbers and symbols to diversify the character set.",
            "Add lowercase letters for better diversity.": "Include lowercase characters to broaden the character set.",
            "Add uppercase letters for better diversity.": "Include uppercase characters to broaden the character set.",
            "Include digits to increase complexity.": "Add digits to increase the password's search space.",
            "Add special characters to resist brute force.": "Symbols significantly increase the search space and slow brute force attacks.",
            "Password found in common password list.": "Avoid using known compromised passwords.",
            "Password cannot be empty.": "Use a passphrase consisting of multiple random words.",
        }

        return [suggestions.get(issue.description, "Review password composition.") for issue in issues]

    def _score_password(self, entropy: float, issues: List[PatternFinding]) -> int:
        score = min(int(entropy / 1.5), 100)
        severity_penalty = {"low": 3, "medium": 7, "high": 15}
        for issue in issues:
            score -= severity_penalty.get(issue.severity, 5)
        return max(score, 0)

    def _has_sequences(self, password: str) -> bool:
        lower_password = password.lower()
        for pattern in SEQUENTIAL_PATTERNS:
            for i in range(len(pattern) - 2):
                seq = pattern[i : i + 3]
                if seq in lower_password or seq[::-1] in lower_password:
                    return True
        return False


__all__ = ["PasswordStrengthAnalyzer", "StrengthReport", "PatternFinding"]
