"""API tests for POST /api/analyze using Flask's test client."""

from __future__ import annotations

import pytest
from flask.testing import FlaskClient

from app import create_app
from config import TestingConfig


@pytest.fixture()
def client() -> FlaskClient:
    """Flask test client with testing config."""
    app = create_app(TestingConfig)
    return app.test_client()


def test_health(client: FlaskClient) -> None:
    """GET /api/health returns ok."""
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_analyze_happy_path(client: FlaskClient) -> None:
    """Valid request returns analysis shape without the password."""
    response = client.post("/api/analyze", json={"password": "Sunshine12!"})
    assert response.status_code == 200
    body = response.get_json()
    assert set(body.keys()) == {"score", "strength", "checks", "warnings", "suggestions"}
    assert isinstance(body["score"], int)
    assert 0 <= body["score"] <= 100
    assert "password" not in body


def test_analyze_empty_allowed(client: FlaskClient) -> None:
    """Empty string is valid input scoring 0 / Very Weak."""
    response = client.post("/api/analyze", json={"password": ""})
    assert response.status_code == 200
    body = response.get_json()
    assert body["score"] == 0
    assert body["strength"] == "Very Weak"


def test_analyze_missing_field(client: FlaskClient) -> None:
    """Missing password field yields generic 400."""
    response = client.post("/api/analyze", json={})
    assert response.status_code == 400
    assert response.get_json() == {"error": "Missing 'password' field."}


@pytest.mark.parametrize("bad", [123, None, True, ["x"], {"x": 1}])
def test_analyze_non_string(client: FlaskClient, bad: object) -> None:
    """Non-string passwords yield generic 400."""
    response = client.post("/api/analyze", json={"password": bad})
    assert response.status_code == 400
    assert response.get_json() == {"error": "Field 'password' must be a string."}


def test_analyze_too_long_413(client: FlaskClient) -> None:
    """Passwords over 1024 chars yield 413."""
    response = client.post("/api/analyze", json={"password": "A" * 1025})
    assert response.status_code == 413
    assert response.get_json() == {
        "error": "Password exceeds maximum length of 1024 characters."
    }


def test_analyze_boundary_1024_ok(client: FlaskClient) -> None:
    """Exactly 1024 chars is accepted."""
    response = client.post("/api/analyze", json={"password": "A" * 1024})
    assert response.status_code == 200


def test_analyze_malformed_json(client: FlaskClient) -> None:
    """Malformed JSON yields generic 400 without echo."""
    response = client.post(
        "/api/analyze", data="{not-json", content_type="application/json"
    )
    assert response.status_code == 400
    body = response.get_json()
    assert "error" in body


def test_analyze_non_json_content_type(client: FlaskClient) -> None:
    """Non-JSON content type yields generic 400."""
    response = client.post("/api/analyze", data="password=abc")
    assert response.status_code == 400


def test_analyze_wrong_method(client: FlaskClient) -> None:
    """GET on the analyze endpoint yields 405."""
    response = client.get("/api/analyze")
    assert response.status_code == 405


def test_no_store_header(client: FlaskClient) -> None:
    """API responses must carry no-store privacy headers."""
    response = client.post("/api/analyze", json={"password": "Sunshine12!"})
    assert response.headers.get("Cache-Control") == "no-store, no-cache"
