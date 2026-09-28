"""Engine tests for analyze_password()."""

from __future__ import annotations

import pytest

from analyzer import analyze_password


def _strength_in(score: int, label: str) -> bool:
    """Mirror the 0-100 -> label mapping for boundary assertions."""
    bands = {
        "Very Weak": range(0, 20),
        "Weak": range(20, 40),
        "Moderate": range(40, 60),
        "Strong": range(60, 80),
        "Very Strong": range(80, 101),
    }
    return score in bands[label]


def test_empty_password() -> None:
    """Empty input scores 0 / Very Weak."""
    result = analyze_password("")
    assert result["score"] == 0
    assert result["strength"] == "Very Weak"
    assert result["checks"]["length"] == 0


def test_short_password() -> None:
    """Short passwords are capped regardless of complexity."""
    result = analyze_password("Ab1!")
    assert result["score"] <= 30
    assert result["strength"] in ("Very Weak", "Weak")
    assert result["checks"]["min_length_8"] is False


def test_weak_password() -> None:
    """Common lowercase-only password is Very Weak."""
    result = analyze_password("password")
    assert result["score"] <= 19
    assert result["strength"] == "Very Weak"
    assert result["checks"]["no_common_password"] is False


def test_moderate_password() -> None:
    """10-char 3-class password with no pattern lands Moderate."""
    result = analyze_password("Sunshine12")
    assert 40 <= result["score"] <= 59
    assert result["strength"] == "Moderate"


def test_strong_password() -> None:
    """11-char all-class password lands Strong (60-79)."""
    result = analyze_password("Sunshine12!")
    assert 60 <= result["score"] <= 79
    assert result["strength"] == "Strong"
    assert _strength_in(result["score"], result["strength"])


def test_very_strong_password() -> None:
    """14-char diverse all-class password lands Very Strong."""
    result = analyze_password("A9$kQ7!mV2@xP4z")
    assert 80 <= result["score"] <= 100
    assert result["strength"] == "Very Strong"


def test_missing_uppercase() -> None:
    """Passwords without uppercase are flagged."""
    result = analyze_password("sunshine12!#")
    assert result["checks"]["has_upper"] is False
    assert any("uppercase" in s.lower() for s in result["suggestions"])


def test_missing_lowercase() -> None:
    """Passwords without lowercase are flagged."""
    result = analyze_password("SUNSHINE12!#")
    assert result["checks"]["has_lower"] is False


def test_missing_digit() -> None:
    """Passwords without digits are flagged."""
    result = analyze_password("Sunshine!!##")
    assert result["checks"]["has_digit"] is False


def test_missing_special() -> None:
    """Passwords without special chars are flagged (no sequence interference)."""
    result = analyze_password("Sunshine4297")
    assert result["checks"]["has_special"] is False


@pytest.mark.parametrize("common", ["password", "123456", "qwerty", "letmein", "ADMIN123"])
def test_common_password(common: str) -> None:
    """Common passwords are capped at 10 and flagged."""
    result = analyze_password(common)
    assert result["checks"]["no_common_password"] is False
    assert result["score"] <= 10
    assert result["strength"] == "Very Weak"


@pytest.mark.parametrize(
    "value",
    ["abc123XYZ", "qwerty123!", "Abcdef12!", "Test1234!!", "321cbaXYZ!"],
)
def test_sequential_pattern(value: str) -> None:
    """Sequential / keyboard patterns are detected."""
    result = analyze_password(value)
    assert result["checks"]["no_sequential_pattern"] is False


def test_repeated_characters() -> None:
    """Three identical chars in a row are flagged."""
    result = analyze_password("aaabBB12!@")
    assert result["checks"]["no_repeated_chars"] is False


def test_excessive_repetition() -> None:
    """Low-diversity passwords trigger the excessive-repetition check."""
    result = analyze_password("aaabbb111!!!")
    assert result["checks"]["no_excessive_repetition"] is False


@pytest.mark.parametrize(
    "value",
    [" password123!A", "password123!A ", "pass word123!A"],
)
def test_whitespace_issue(value: str) -> None:
    """Leading/trailing/embedded whitespace is flagged."""
    result = analyze_password(value)
    assert result["checks"]["no_whitespace_issue"] is False


def test_unicode_input() -> None:
    """Unicode input must not crash and counts classes correctly."""
    result = analyze_password("Pässwörd🔒429!A")
    assert result["checks"]["has_upper"] is True
    assert result["checks"]["has_lower"] is True
    assert result["checks"]["has_digit"] is True
    assert result["checks"]["has_special"] is True
    assert 0 <= result["score"] <= 100


def test_very_long_password_analyzer() -> None:
    """Engine handles oversized input safely (API rejects it separately)."""
    result = analyze_password("A" * 2000)
    assert 0 <= result["score"] <= 100
    assert result["checks"]["length"] == 2000


def test_non_string_raises() -> None:
    """Non-string input raises TypeError."""
    with pytest.raises(TypeError):
        analyze_password(None)  # type: ignore[arg-type]


def test_result_never_contains_password() -> None:
    """Engine result must never include the plaintext."""
    sentinel = "Sup3rUniqSentinel!9Z"
    result = analyze_password(sentinel)
    assert "password" not in result
    assert sentinel not in str(result)


def test_score_strength_consistency() -> None:
    """Score and label must always agree across representative inputs."""
    for value in ["", "a", "password", "Sunshine12", "Sunshine12!", "A9$kQ7!mV2@xP4z"]:
        result = analyze_password(value)
        assert _strength_in(result["score"], result["strength"])
