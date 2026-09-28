"""Password Strength Analyzer engine.

Privacy-first, pure-Python heuristic analyzer.

Privacy guarantees:
    - No database, file, log, print, or network access in this module.
    - No hashing of the password (to avoid implying storage).
    - The password only exists as a function argument for the duration
      of :func:`analyze_password` and is never persisted or returned.

Scoring is a transparent 0-100 heuristic, NOT a cracking-time estimate.
"""

from __future__ import annotations

import re
from typing import Any

# Match 3+ identical characters in a row, e.g. "aaa", "111".
_REPEATED_RE = re.compile(r"(.)\1{2,}")

# Well-known weak passwords checked offline (case-insensitive exact match).
# Kept intentionally small and dependency-free; no external API is used.
COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "123456",
        "123456789",
        "12345678",
        "1234567",
        "12345",
        "1234",
        "1234567890",
        "000000",
        "111111",
        "qwerty",
        "qwerty123",
        "password",
        "password1",
        "password123",
        "123123",
        "admin",
        "admin123",
        "letmein",
        "welcome",
        "welcome123",
        "monkey",
        "dragon",
        "football",
        "iloveyou",
        "abc123",
        "abcd1234",
        "qazwsx",
        "1qaz2wsx",
        "sunshine",
        "princess",
        "master",
        "shadow",
        "superman",
        "michael",
        "jesus",
        "trustno1",
        "starwars",
        "whatever",
        "freedom",
        "passw0rd",
        "p@ssw0rd",
        "changeme",
        "test123",
        "guest",
        "login",
    }
)

# Keyboard / layout patterns (lowercase substring search).
KEYBOARD_PATTERNS: tuple[str, ...] = (
    "qwerty",
    "qwertyuiop",
    "asdf",
    "asdfgh",
    "zxcv",
    "zxcvbn",
    "1qaz",
    "qazwsx",
    "1q2w3e",
)

MAX_PASSWORD_LENGTH: int = 1024


def _strength_label(score: int) -> str:
    """Map a 0-100 score to a human-readable strength label."""
    if score <= 19:
        return "Very Weak"
    if score <= 39:
        return "Weak"
    if score <= 59:
        return "Moderate"
    if score <= 79:
        return "Strong"
    return "Very Strong"


def _has_repeated_chars(password: str) -> bool:
    """Return True if 3+ identical characters appear consecutively."""
    return _REPEATED_RE.search(password) is not None


def _has_excessive_repetition(password: str) -> bool:
    """Return True when character diversity is abnormally low.

    Heuristic: for passwords of length >= 8, fewer than 40% unique
    characters indicates excessive repetition (e.g. "aaabbb111!!!").
    """
    if len(password) < 8:
        return False
    if len(password) == 0:
        return False
    ratio: float = len(set(password)) / len(password)
    return ratio < 0.40


def _has_whitespace_issue(password: str) -> bool:
    """Return True for leading/trailing/embedded whitespace or control chars."""
    if password != password.strip():
        return True
    for ch in password:
        if ch.isspace():
            return True
        if ord(ch) < 32 or ord(ch) == 127:
            return True
    return False


def _find_sequential_pattern(password: str) -> bool:
    """Detect sequential or keyboard patterns.

    Covers:
        - Ascending/descending runs of 3+ letters or 3+ digits
          (e.g. "abc", "cba", "123", "321").
        - Common keyboard rows (e.g. "qwerty", "asdf", "zxcv").

    Only pure alpha or pure digit windows are considered for ordinal
    sequences so symbols do not cause false positives.
    """
    lowered: str = password.lower()

    for token in KEYBOARD_PATTERNS:
        if token in lowered:
            return True

    # Ordinal runs over windows of 3.
    for i in range(len(lowered) - 2):
        window: str = lowered[i : i + 3]
        if window.isalpha() or window.isdigit():
            a, b, c = ord(window[0]), ord(window[1]), ord(window[2])
            if b == a + 1 and c == b + 1:
                return True
            if b == a - 1 and c == b - 1:
                return True
    return False


def _is_common_password(password: str) -> bool:
    """Case-insensitive exact match against the local weak-password set."""
    return password.lower() in COMMON_PASSWORDS


def analyze_password(password: str) -> dict[str, Any]:
    """Analyze a password and return ONLY analysis metadata.

    Args:
        password: The plaintext password to evaluate. It is examined
            in memory only and never stored, logged, or returned.

    Returns:
        Dict with keys ``score`` (0-100 int), ``strength`` (label),
        ``checks`` (dict of booleans/ints), ``warnings`` and
        ``suggestions`` (lists of strings). The password itself is
        never included in the result.

    Raises:
        TypeError: If ``password`` is not a string.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    length: int = len(password)

    has_upper: bool = any(ch.isupper() for ch in password)
    has_lower: bool = any(ch.islower() for ch in password)
    has_digit: bool = any(ch.isdigit() for ch in password)
    # Special = visible symbol that is neither alphanumeric nor whitespace.
    # This counts ASCII punctuation ("!", "@", "_") as well as Unicode
    # symbols/emoji, while ignoring spaces (handled separately).
    has_special: bool = any((not ch.isalnum() and not ch.isspace()) for ch in password)

    is_empty: bool = length == 0
    is_common: bool = _is_common_password(password) if not is_empty else False
    has_sequential: bool = _find_sequential_pattern(password) if length >= 3 else False
    has_repeated: bool = _has_repeated_chars(password)
    has_excessive: bool = _has_excessive_repetition(password)
    has_whitespace: bool = _has_whitespace_issue(password)

    min_8: bool = length >= 8
    min_12: bool = length >= 12

    checks: dict[str, Any] = {
        "length": length,
        "min_length_8": min_8,
        "min_length_12": min_12,
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_digit": has_digit,
        "has_special": has_special,
        "no_common_password": not is_common,
        "no_sequential_pattern": not has_sequential,
        "no_repeated_chars": not has_repeated,
        "no_excessive_repetition": not has_excessive,
        "no_whitespace_issue": not has_whitespace,
    }

    warnings: list[str] = []
    suggestions: list[str] = []

    if is_empty:
        warnings.append("Password is empty.")
        suggestions.append("Enter a password of at least 12 characters.")
        return {
            "score": 0,
            "strength": "Very Weak",
            "checks": checks,
            "warnings": warnings,
            "suggestions": suggestions,
        }

    # ---- Transparent heuristic scoring ----
    score: int = 0

    # Length contributes up to 45 points.
    if length >= 8:
        score += 20
    if length >= 12:
        score += 15
    if length >= 16:
        score += 10

    # Character variety contributes up to 40 points.
    if has_upper:
        score += 10
    if has_lower:
        score += 10
    if has_digit:
        score += 10
    if has_special:
        score += 10

    # Diversity bonuses (up to +15).
    classes_present: int = sum([has_upper, has_lower, has_digit, has_special])
    if length >= 12 and classes_present == 4:
        score += 10
    unique_ratio: float = len(set(password)) / length if length else 0.0
    if unique_ratio > 0.70:
        score += 5

    # Deductions for detectable weaknesses.
    if has_sequential:
        score -= 20
        warnings.append("Sequential or keyboard pattern detected (e.g. abc, 123, qwerty).")
        suggestions.append("Avoid sequences and keyboard patterns; use random placement.")
    if has_repeated:
        score -= 15
        warnings.append("Repeated characters detected (e.g. aaa, 111).")
        suggestions.append("Avoid repeating the same character 3 or more times in a row.")
    if has_excessive:
        score -= 15
        warnings.append("Excessive repetition / low character diversity detected.")
        suggestions.append("Increase character diversity; avoid reusing a small set of characters.")
    if has_whitespace:
        score -= 5
        warnings.append("Leading, trailing, or embedded whitespace / control character detected.")
        suggestions.append("Remove accidental spaces at the start/end; avoid spaces inside passwords.")
    if classes_present <= 1 and length >= 4:
        score -= 20
        warnings.append("Password uses only a single character class.")
        suggestions.append("Combine uppercase, lowercase, digits, and special characters.")
    if is_common:
        warnings.append("Password is a commonly used / weak password.")
        suggestions.append("Choose a unique password not found in common-password lists.")

    # Caps for structurally weak passwords.
    if length < 8:
        warnings.append("Password is too short (minimum 8 characters recommended).")
        suggestions.append("Use at least 12 characters; 16+ is better.")
        score = min(score, 30)
    if is_common:
        score = min(score, 10)

    # Missing-class suggestions (only when relevant, no password echo).
    if not has_upper:
        suggestions.append("Add uppercase letters (A-Z).")
    if not has_lower:
        suggestions.append("Add lowercase letters (a-z).")
    if not has_digit:
        suggestions.append("Add digits (0-9).")
    if not has_special:
        suggestions.append("Add special characters (e.g. ! @ # $ %).")
    if not min_12:
        suggestions.append("Use at least 12 characters; longer passwords are stronger.")

    if not warnings:
        warnings.append("No major weaknesses detected.")
    if not suggestions or (len(warnings) == 1 and warnings[0] == "No major weaknesses detected."):
        # Keep a positive closing note when everything passes; otherwise
        # suggestions above already guide the user.
        if score >= 80:
            suggestions.append("Your password meets the recommended criteria.")

    score = max(0, min(100, score))

    return {
        "score": score,
        "strength": _strength_label(score),
        "checks": checks,
        "warnings": warnings,
        "suggestions": suggestions,
    }
