"""Flask application factory and entrypoint.

Phase 2: ``GET /`` serves the cybersecurity dashboard UI.
The ``POST /api/analyze`` contract from Phase 1 is unchanged.
"""

from __future__ import annotations

from flask import Flask, jsonify, render_template

from api.routes import api_bp
from config import BaseConfig


def create_app(config_object: type[BaseConfig] | None = None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_object(config_object or BaseConfig)
    # Enforce request body cap from config.
    app.config.setdefault("MAX_CONTENT_LENGTH", 16 * 1024)

    app.register_blueprint(api_bp)

    @app.route("/", methods=["GET"])
    def index() -> object:
        """Serve the Phase 2 dashboard UI."""
        return render_template("index.html")

    @app.after_request
    def _security_headers(response):  # type: ignore[no-untyped-def]
        """Attach privacy/security headers to every response."""
        response.headers["Cache-Control"] = "no-store, no-cache"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.errorhandler(400)
    def _bad_request(_e):  # type: ignore[no-untyped-def]
        return jsonify({"error": "Bad request."}), 400

    @app.errorhandler(404)
    def _not_found(_e):  # type: ignore[no-untyped-def]
        return jsonify({"error": "Not found."}), 404

    @app.errorhandler(405)
    def _method_not_allowed(_e):  # type: ignore[no-untyped-def]
        return jsonify({"error": "Method not allowed."}), 405

    @app.errorhandler(413)
    def _too_large(_e):  # type: ignore[no-untyped-def]
        return jsonify({"error": "Request too large."}), 413

    @app.errorhandler(500)
    def _internal(_e):  # type: ignore[no-untyped-def]
        return jsonify({"error": "Internal server error."}), 500

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
