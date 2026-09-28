"""API request validation.

All validators use generic error messages and never echo the submitted
password back in errors.
"""

from __future__ import annotations

from typing import Any


def validate_analyze_payload(
    payload: Any, max_length: int = 1024
) -> tuple[str | None, tuple[dict[str, str], int] | None]:
    """Validate the JSON payload for POST /api/analyze.

    Args:
        payload: Decoded JSON body (expected dict with ``password``).
        max_length: Maximum allowed password length.

    Returns:
        Tuple ``(password, error)`` where exactly one element is None.
        ``password`` is the validated string on success; ``error`` is a
        ``(body, status)`` pair on failure with a generic message.
    """
    if not isinstance(payload, dict):
        return None, ({"error": "Request must be a JSON object."}, 400)
    if "password" not in payload:
        return None, ({"error": "Missing 'password' field."}, 400)

    password = payload["password"]
    if not isinstance(password, str):
        return None, ({"error": "Field 'password' must be a string."}, 400)
    if len(password) > max_length:
        return (
            None,
            ({"error": "Password exceeds maximum length of 1024 characters."}, 413),
        )
    return password, None
