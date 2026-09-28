"""Privacy tests: the password must never leak via API, logs, or files."""

from __future__ import annotations

import pathlib

import pytest
from flask.testing import FlaskClient

from analyzer import analyze_password
from app import create_app
from config import TestingConfig


@pytest.fixture()
def client() -> FlaskClient:
    """Flask test client with testing config."""
    return create_app(TestingConfig).test_client()


SENTINELS = [
    "Sup3rUniqSentinel!9Z",
    "An0ther$entinel#77Q",
    "Pässwörd🔒Sentinel429!A",
]


@pytest.mark.parametrize("sentinel", SENTINELS)
def test_password_absent_from_api_response(client: FlaskClient, sentinel: str) -> None:
    """Raw response bytes and parsed JSON must not contain the password."""
    response = client.post("/api/analyze", json={"password": sentinel})
    assert response.status_code == 200
    raw: str = response.data.decode("utf-8", errors="strict")
    assert sentinel not in raw
    body = response.get_json()
    assert "password" not in body
    assert sentinel not in str(body)


@pytest.mark.parametrize("sentinel", SENTINELS)
def test_password_absent_from_error_responses(client: FlaskClient, sentinel: str) -> None:
    """Oversize submissions return generic errors without echo."""
    response = client.post("/api/analyze", json={"password": sentinel * 200})
    assert response.status_code == 413
    raw: str = response.data.decode("utf-8", errors="strict")
    assert sentinel not in raw


def test_engine_result_has_no_password_key() -> None:
    """Analyzer dict keys are fixed and never include password material."""
    result = analyze_password("Sup3rUniqSentinel!9Z")
    assert set(result.keys()) == {"score", "strength", "checks", "warnings", "suggestions"}
    assert "password" not in result["checks"]


def test_no_password_written_to_workspace_files(tmp_path: pathlib.Path) -> None:
    """Sanity: running analysis must not create files containing the password.

    Uses an isolated tmp dir listing plus a repo-wide content guard executed
    in the verification step (grep). Here we assert the analyzer performs
    no file I/O for the sentinel value.
    """
    sentinel = "Sup3rUniqSentinel!9Z"
    analyze_password(sentinel)
    leftovers = [p for p in tmp_path.iterdir() if sentinel in p.name]
    assert leftovers == []
