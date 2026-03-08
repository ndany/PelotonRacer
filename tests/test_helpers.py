"""
Tests for src/utils/helpers.py

Covers: format_duration, format_timestamp, format_iso_date,
        safe_divide, get_metric_display_name, get_metric_unit
"""

import pytest
from unittest.mock import patch
from src.utils.helpers import (
    format_duration,
    format_timestamp,
    format_iso_date,
    safe_divide,
    get_metric_display_name,
    get_metric_unit,
)


@pytest.mark.unit
class TestFormatDuration:
    def test_seconds_only(self):
        """Values under 60 seconds show as Ns."""
        assert format_duration(45) == "45s"

    def test_exactly_zero_seconds(self):
        assert format_duration(0) == "0s"

    def test_exactly_59_seconds(self):
        assert format_duration(59) == "59s"

    def test_exactly_one_minute(self):
        assert format_duration(60) == "1m"

    def test_minutes_only(self):
        assert format_duration(1800) == "30m"

    def test_exactly_59_minutes(self):
        assert format_duration(59 * 60) == "59m"

    def test_exactly_one_hour(self):
        assert format_duration(3600) == "1h"

    def test_hours_and_minutes(self):
        assert format_duration(3600 + 900) == "1h 15m"

    def test_hours_no_remainder_minutes(self):
        """Exact multiple of an hour shows as Nh, not Nh 0m."""
        assert format_duration(7200) == "2h"

    @pytest.mark.parametrize("seconds,expected", [
        (61,    "1m"),
        (90,    "1m"),
        (3661,  "1h 1m"),
        (5400,  "1h 30m"),
    ])
    def test_boundary_values(self, seconds, expected):
        assert format_duration(seconds) == expected


@pytest.mark.unit
class TestFormatTimestamp:
    def test_returns_formatted_date_string(self):
        """Unix timestamp 0 is 1970-01-01 in local time — just verify format."""
        result = format_timestamp(1_700_000_000)
        # Should match YYYY-MM-DD HH:MM
        import re
        assert re.match(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", result)

    def test_known_timestamp(self):
        """2024-01-01 00:00:00 UTC is 1704067200; result depends on local tz."""
        result = format_timestamp(1_704_067_200)
        assert "2024" in result or "2023" in result  # timezone tolerance


@pytest.mark.unit
class TestFormatIsoDate:
    def test_standard_iso_string(self):
        result = format_iso_date("2024-03-15T14:30:00")
        assert result == "2024-03-15 14:30"

    def test_utc_z_suffix(self):
        """Z suffix should be handled without raising an exception."""
        result = format_iso_date("2024-03-15T14:30:00Z")
        assert "2024-03-15" in result

    def test_invalid_string_returns_original(self):
        """Unparseable strings fall back to the original value."""
        result = format_iso_date("not-a-date")
        assert result == "not-a-date"

    def test_empty_string_returns_original(self):
        result = format_iso_date("")
        assert result == ""


@pytest.mark.unit
class TestSafeDivide:
    def test_normal_division(self):
        assert safe_divide(10.0, 2.0) == 5.0

    def test_division_by_zero_returns_default(self):
        assert safe_divide(10.0, 0.0) == 0.0

    def test_custom_default_on_zero(self):
        assert safe_divide(10.0, 0.0, default=-1.0) == -1.0

    def test_zero_numerator(self):
        assert safe_divide(0.0, 5.0) == 0.0

    def test_fractional_result(self):
        assert abs(safe_divide(1.0, 3.0) - 0.3333) < 0.001


@pytest.mark.unit
class TestGetMetricDisplayName:
    @pytest.mark.parametrize("metric,expected", [
        ("output",     "Output (watts)"),
        ("cadence",    "Cadence (RPM)"),
        ("resistance", "Resistance (%)"),
        ("heart_rate", "Heart Rate (BPM)"),
        ("speed",      "Speed"),
        ("distance",   "Distance"),
    ])
    def test_known_metrics(self, metric, expected):
        assert get_metric_display_name(metric) == expected

    def test_unknown_metric_capitalizes(self):
        assert get_metric_display_name("power") == "Power"

    def test_unknown_metric_all_lower_capitalizes_first(self):
        assert get_metric_display_name("calories") == "Calories"


@pytest.mark.unit
class TestGetMetricUnit:
    @pytest.mark.parametrize("metric,expected", [
        ("output",     "W"),
        ("cadence",    "RPM"),
        ("resistance", "%"),
        ("heart_rate", "BPM"),
        ("speed",      "mph"),
        ("distance",   "mi"),
    ])
    def test_known_metrics(self, metric, expected):
        assert get_metric_unit(metric) == expected

    def test_unknown_metric_returns_empty_string(self):
        assert get_metric_unit("calories") == ""

    def test_unknown_metric_empty_key(self):
        assert get_metric_unit("") == ""
