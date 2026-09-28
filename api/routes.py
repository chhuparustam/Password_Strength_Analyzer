"""Flask API routes for the Password Strength Analyzer.

Privacy notes:
    - The password is held in a local variable only for the duration of
      the request and is never logged, printed, hashed, persisted, or
      included in any response.
    - Error messages are generic and never reflect the submitted value.
"""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from analyzer import analyze_password
from api.validation import validate_analyze_payload

api_bp = Blueprint("api", __name__)


@api_bp.route("/api/analyze", methods=["POST"])
def analyze() -> tuple[object, int]:
    """Analyze a password supplied as JSON ``{"password": "..."}``."""
    if not request.is_json:
        return jsonify({"error": "Request must be JSON."}), 400

    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Malformed JSON request."}), 400

    max_length: int = current_app.config.get("MAX_PASSWORD_LENGTH", 1024)
    password, error = validate_analyze_payload(payload, max_length=max_length)
    if error is not None:
        body, status = error
        return jsonify(body), status

    # Password lives only in this local scope for scoring.
    assert password is not None
    result = analyze_password(password)
    return jsonify(result), 200


@api_bp.route("/api/health", methods=["GET"])
def health() -> tuple[object, int]:
    """Liveness probe (contains no password data)."""
    return jsonify({"status": "ok"}), 200
