"""
Tests for src/config.py

Covers: is_diagnostic_mode() env-var detection, and module-level constants.
"""

import pytest
from unittest.mock import patch
import os


@pytest.mark.unit
class TestIsDiagnosticMode:
    def test_returns_false_when_not_set(self):
        """Unset env var defaults to False."""
        from src.config import is_diagnostic_mode
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DIAGNOSTIC_MODE", None)
            assert is_diagnostic_mode() is False

    def test_returns_true_when_set_to_true(self):
        # load_dotenv(override=True) inside the function would overwrite our mock,
        # so we patch it out to prevent .env from clobbering the test env var.
        from src.config import is_diagnostic_mode
        with patch("src.config.load_dotenv"), patch.dict(os.environ, {"DIAGNOSTIC_MODE": "true"}):
            assert is_diagnostic_mode() is True

    def test_case_insensitive_true(self):
        from src.config import is_diagnostic_mode
        with patch("src.config.load_dotenv"), patch.dict(os.environ, {"DIAGNOSTIC_MODE": "TRUE"}):
            assert is_diagnostic_mode() is True

    def test_returns_false_for_arbitrary_value(self):
        from src.config import is_diagnostic_mode
        with patch("src.config.load_dotenv"), patch.dict(os.environ, {"DIAGNOSTIC_MODE": "yes"}):
            assert is_diagnostic_mode() is False


@pytest.mark.unit
class TestConfigConstants:
    def test_api_page_size(self):
        from src import config
        assert config.API_PAGE_SIZE == 100

    def test_api_followers_limit_positive(self):
        from src import config
        assert config.API_FOLLOWERS_LIMIT > 0

    def test_max_workouts_full_gte_incremental(self):
        from src import config
        assert config.MAX_USER_WORKOUTS_FULL >= config.MAX_USER_WORKOUTS_INCREMENTAL
        assert config.MAX_FOLLOWER_WORKOUTS_FULL >= config.MAX_FOLLOWER_WORKOUTS_INCREMENTAL

    def test_parallel_workers_positive(self):
        from src import config
        assert config.PARALLEL_WORKERS > 0
