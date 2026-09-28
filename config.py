"""Application configuration.

Environment-based settings with safe defaults. No secrets or passwords
are stored here.
"""

from __future__ import annotations


class BaseConfig:
    """Base configuration shared by all environments."""

    MAX_PASSWORD_LENGTH: int = 1024
    # Total request body cap (JSON envelope overhead included).
    MAX_CONTENT_LENGTH: int = 16 * 1024
    JSON_SORT_KEYS: bool = False


class DevelopmentConfig(BaseConfig):
    """Local development configuration."""

    DEBUG: bool = True
    TESTING: bool = False


class TestingConfig(BaseConfig):
    """Pytest configuration."""

    DEBUG: bool = False
    TESTING: bool = True


class ProductionConfig(BaseConfig):
    """Production configuration (debug disabled)."""

    DEBUG: bool = False
    TESTING: bool = False
