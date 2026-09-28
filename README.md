# Password Strength Analyzer

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Flask](https://img.shields.io/badge/flask-3.x-lightgrey)
![pytest](https://img.shields.io/badge/tests-pytest-green)
![Privacy](https://img.shields.io/badge/privacy-first-important)

A **privacy-first password strength analyzer** built with Python and Flask. It evaluates password strength with a transparent, dependency-free heuristic engine and exposes the result through a minimal JSON API — plus a lightweight dashboard UI. Passwords are analyzed **in memory only** and are never stored, logged, or returned.

> Heuristic score only — not a cracking-time estimate and not a guarantee of security.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Privacy & Security Principles](#privacy--security-principles)
- [How Scoring Works](#how-scoring-works)
- [Strength Levels](#strength-levels)
- [API Documentation](#api-documentation)
- [Input Validation](#input-validation)
- [Installation](#installation)
- [Running the App](#running-the-app)
- [Running the Tests](#running-the-tests)
- [Project Structure](#project-structure)
- [Technology Stack](#technology-stack)
- [Security Considerations](#security-considerations)
- [Example API Usage](#example-api-usage)
- [Development & Testing](#development--testing)
- [License](#license)

---

## Overview

Password Strength Analyzer checks a password against structural rules (length, character variety, diversity) and known-weak patterns (common passwords, sequences, keyboard rows, repetition, whitespace issues), then returns a **0–100 score** with a human-readable strength label, detailed `checks`, `warnings`, and actionable `suggestions`.

- Pure-Python analyzer engine (`analyzer.py`) — no database, no external API calls.
- Flask API layer (`api/`, `app.py`) — validates input and returns analysis metadata.
- Minimal dashboard UI (`templates/`, `static/`) served at `GET /` using vanilla HTML/CSS/JS (no frontend framework).
- Automated test suite (`tests/`) covering scoring, API behavior, and privacy guarantees.

---

## Key Features

- **Transparent 0–100 heuristic score** with 5 strength tiers.
- **Character-class checks:** uppercase, lowercase, digit, special (Unicode-aware; emoji/symbols count as special, spaces do not).
- **Length checks:** `min_length_8`, `min_length_12` (with extra credit at 16+).
- **Weak-pattern detection:**
  - Common-password list (offline, case-insensitive exact match, ~40 entries such as `password`, `123456`, `qwerty`, `letmein`).
  - Sequential runs (`abc`, `cba`, `123`, `321`) and keyboard rows (`qwerty`, `asdf`, `zxcv`, `1qaz`, …).
  - 3+ repeated characters in a row (`aaa`, `111`).
  - Low-diversity repetition (< 40% unique characters for length ≥ 8).
  - Leading/trailing/embedded whitespace and control characters.
- **Actionable feedback:** `warnings` describe what was found; `suggestions` tell you how to fix it — without ever echoing the password.
- **JSON API** with strict validation and generic (non-leaking) error messages.
- **Privacy headers** (`Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, …) on every response.
- **Fully typed, documented code** with `pytest` coverage for engine, API, and privacy.

---

## Privacy & Security Principles

This project is designed as a **privacy-first** password analysis tool:

| Principle | Guarantee |
|---|---|
| ❌ Never stored | No database, no files, no cache writes for passwords. |
| ❌ Never logged | No logging, no `print()` of password material. |
| ❌ Never printed | Passwords never reach stdout/stderr. |
| ❌ Never hashed | Deliberately avoided, so hashes can't imply storage. |
| ❌ Never returned | API responses and error messages never contain the password. |
| ✅ Memory-only | The password exists solely as a function argument during `analyze_password()` / the request scope, then is discarded. |
| ✅ Generic errors | Validation and error responses never reflect the submitted value. |

These guarantees are enforced by automated tests in `tests/test_privacy.py` (sentinel passwords must not appear in raw response bytes, parsed JSON, or error responses).

---

## How Scoring Works

High-level flow (see `analyze_password()` in `analyzer.py`):

1. **Measure** length and character classes (upper / lower / digit / special).
2. **Add points:**
   - Length up to **45 pts** — `≥ 8` → +20, `≥ 12` → +15, `≥ 16` → +10.
   - Variety up to **40 pts** — +10 per class present.
   - Diversity bonus up to **+15** — all 4 classes with length ≥ 12 → +10; unique-character ratio > 0.70 → +5.
3. **Subtract for weaknesses:**
   - Sequential/keyboard pattern → −20.
   - Repeated chars (`aaa`) → −15.
   - Excessive repetition / low diversity → −15.
   - Whitespace/control chars → −5.
   - Single character class (length ≥ 4) → −20.
4. **Apply caps:**
   - Length < 8 → score capped at **30**.
   - Common password → score capped at **10**.
5. **Clamp** to 0–100 and map to a strength label.

Empty string is valid input and scores `0 / Very Weak` with guidance to enter at least 12 characters.

---

## Strength Levels

| Score | Strength | Typical meaning |
|------:|---|---|
| 0–19 | **Very Weak** | Empty, common, or very short password. |
| 20–39 | **Weak** | Short or single-class password. |
| 40–59 | **Moderate** | Decent length with 2–3 character classes, no major patterns. |
| 60–79 | **Strong** | 11+ chars, all classes, no detected patterns (e.g. `Sunshine12!`). |
| 80–100 | **Very Strong** | 14+ chars, diverse, all classes (e.g. `A9$kQ7!mV2@xP4z`). |

---

## API Documentation

Base URL (local dev): `http://127.0.0.1:5000`

| Method & Path | Purpose |
|---|---|
| `POST /api/analyze` | Analyze a password (JSON only). |
| `GET /api/health` | Liveness probe → `{"status": "ok"}` (no password data). |
| `GET /` | Dashboard UI (vanilla HTML/CSS/JS). |

### `POST /api/analyze`

**Request** — JSON object with a single `password` string field:

```json
{
  "password": "Sunshine12!"
}
```

**Success response** — `200 OK` with `score`, `strength`, `checks`, `warnings`, `suggestions`:

```json
{
  "score": 65,
  "strength": "Strong",
  "checks": {
    "length": 11,
    "min_length_8": true,
    "min_length_12": false,
    "has_upper": true,
    "has_lower": true,
    "has_digit": true,
    "has_special": true,
    "no_common_password": true,
    "no_sequential_pattern": true,
    "no_repeated_chars": true,
    "no_excessive_repetition": true,
    "no_whitespace_issue": true
  },
  "warnings": [
    "No major weaknesses detected."
  ],
  "suggestions": [
    "Use at least 12 characters; longer passwords are stronger."
  ]
}
```

> The `password` itself is never included in the response.

**Error responses** — generic JSON, never echoing the password:

| Status | When | Body |
|---|---|---|
| 400 | Non-JSON body | `{"error": "Request must be JSON."}` |
| 400 | Malformed JSON | `{"error": "Malformed JSON request."}` |
| 400 | Body is not an object | `{"error": "Request must be a JSON object."}` |
| 400 | Missing field | `{"error": "Missing 'password' field."}` |
| 400 | Non-string password | `{"error": "Field 'password' must be a string."}` |
| 405 | Wrong method (e.g. `GET /api/analyze`) | `{"error": "Method not allowed."}` |
| 413 | Password longer than 1024 chars | `{"error": "Password exceeds maximum length of 1024 characters."}` |
| 413 | Request body over 16 KB | `{"error": "Request too large."}` |

### HTTP 413 Behavior

Passwords **exceeding 1024 characters** are rejected with `413`:

```json
{
  "error": "Password exceeds maximum length of 1024 characters."
}
```

- Exactly 1024 characters is accepted (`200`).
- 1025+ characters → `413` (limit comes from `MAX_PASSWORD_LENGTH = 1024` in `config.py`).
- Separately, Flask enforces a total body cap of 16 KB (`MAX_CONTENT_LENGTH`); oversized envelopes return `{"error": "Request too large."}` with `413`.
- 413 responses never contain the submitted password (verified by privacy tests).

---

## Input Validation

Implemented in `api/validation.py` (`validate_analyze_payload`):

1. Request must have a JSON content type.
2. Body must parse as JSON and be an object.
3. Object must contain a `password` key.
4. `password` must be a string (numbers, booleans, arrays, objects, `null` → `400`).
5. `password` length must be ≤ 1024 (else `413`).
6. Empty string `""` is allowed and scores `0 / Very Weak`.

All failure messages are generic and safe to display.

---

## Installation

### Prerequisites

- **Python 3.11+**
- `pip` and `venv`
- No database or external services required.

### 1. Virtual environment setup

```bash
# Windows (PowerShell)
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1

# macOS / Linux
python3.11 -m venv .venv
source .venv/bin/activate
```

### 2. Dependency installation

```bash
# Runtime only
pip install -r requirements.txt

# Runtime + test tooling
pip install -r requirements-dev.txt
```

`requirements.txt` installs `Flask>=3.0` (plus `gunicorn` on non-Windows for serving). `requirements-dev.txt` adds `pytest` and `pytest-cov`.

---

## Running the App

```bash
python app.py
```

- Serves at `http://127.0.0.1:5000` (`debug=False`).
- Open `http://127.0.0.1:5000/` for the dashboard, or call the API directly.
- App factory: `create_app()` in `app.py`; configs (`DevelopmentConfig`, `TestingConfig`, `ProductionConfig`) live in `config.py`.

---

## Running the Tests

```bash
pytest -q
# or
python -m pytest -q
```

- Configured by `pytest.ini` (`testpaths = tests`, `addopts = -q`).
- Suite covers the scoring engine (`test_analyzer.py`), API contract and validation (`test_api.py`), and privacy guarantees (`test_privacy.py`).

---

## Project Structure

```text
Password_Strength_Analyzer/
├── analyzer.py            # Pure-Python heuristic engine (analyze_password)
├── app.py                 # Flask app factory, UI route, security headers
├── config.py              # Base/Dev/Test/Prod config (length + body caps)
├── api/
│   ├── __init__.py
│   ├── routes.py          # POST /api/analyze, GET /api/health
│   └── validation.py      # Strict, non-leaking payload validation
├── templates/
│   └── index.html         # Dashboard UI (vanilla HTML, no framework)
├── static/
│   ├── css/style.css
│   └── js/app.js          # Debounced fetch, DOM-only updates, no storage
├── tests/
│   ├── test_analyzer.py   # Scoring tiers, patterns, edge cases
│   ├── test_api.py        # Status codes, 413 boundary, headers
│   └── test_privacy.py    # Sentinel leak checks
├── requirements.txt
├── requirements-dev.txt
└── pytest.ini
```

---

## Technology Stack

| Layer | Technology |
|---|---|
| Language | Python 3.11+ with type hints and docstrings |
| Web framework | Flask 3.x (app factory + Blueprint) |
| Analyzer | Pure Python (`re`, stdlib only) |
| Frontend | Vanilla HTML/CSS/JS — no framework, no external assets |
| Testing | pytest, pytest-cov, Flask test client |
| Storage / APIs | None — no database, no external API |

---

## Security Considerations

- **Transport:** run behind HTTPS in production; the app itself sets `Cache-Control: no-store, no-cache`, `Pragma: no-cache`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: no-referrer`.
- **Limits:** 1024-char password cap plus a 16 KB request body cap mitigate abuse and oversized payloads.
- **Client:** the dashboard sends passwords via `POST` JSON only (never URLs), uses `textContent` for DOM updates, and uses no `localStorage`/`sessionStorage`.
- **Scope:** the score is a transparent heuristic, not a crack-time prediction. For real accounts, pair strong passwords with a password manager and multi-factor authentication.

---

## Example API Usage

### Analyze a password with curl

```bash
curl -s -X POST http://127.0.0.1:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"password": "Sunshine12!"}'
```

### Health check

```bash
curl -s http://127.0.0.1:5000/api/health
# {"status": "ok"}
```

### Oversize password (413)

```bash
python -c "print('{\"password\": \"' + 'A'*1025 + '\"}')" > big.json
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:5000/api/analyze \
  -H "Content-Type: application/json" \
  --data @big.json
# 413
```

---

## Development & Testing

- Code style: type hints (`from __future__ import annotations`) and docstrings throughout.
- Test with `pytest -q`; add engine cases to `tests/test_analyzer.py` and contract cases to `tests/test_api.py`.
- Privacy rule for contributors: never log, print, persist, hash, or return password material — keep all feedback in `checks` / `warnings` / `suggestions` metadata.
- Config via `config.py` classes; `TestingConfig` is used by the test suite.

---

## License

No license file is currently included in this repository. Add your chosen license (e.g. `MIT`, `Apache-2.0`) as `LICENSE` and reference it here before public distribution.
