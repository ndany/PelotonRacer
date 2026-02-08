"""
Shared test fixtures for PelotonRacer test suite

This module provides reusable fixtures for testing all components of the PelotonRacer application.
Fixtures are organized by category: data models, API mocking, file management, and utilities.
"""

import pytest
import json
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List
from unittest.mock import Mock, MagicMock
from datetime import datetime

# Import models for fixture creation
from src.models.models import User, Workout, RideInfo, PerformanceMetrics, CommonRide
from src.services.data_manager import DataManager
from src.api.peloton_client import PelotonClient


# =============================================================================
# DATA MODEL FIXTURES - Sample data for testing
# =============================================================================

@pytest.fixture
def sample_user() -> User:
    """
    Provides a sample User object for testing.

    Returns:
        User: A complete user object with all fields populated
    """
    return User(
        user_id="user123",
        username="testuser",
        display_name="Test User",
        image_url="https://example.com/avatar.jpg",
        location="San Francisco, CA",
        total_workouts=100
    )


@pytest.fixture
def sample_follower() -> User:
    """
    Provides a sample follower User object for testing.

    Returns:
        User: A follower user object
    """
    return User(
        user_id="follower456",
        username="follower1",
        display_name="Follower One",
        image_url="https://example.com/follower.jpg",
        location="New York, NY",
        total_workouts=75
    )


@pytest.fixture
def sample_followers() -> List[User]:
    """
    Provides a list of sample followers for testing.

    Returns:
        List[User]: Multiple follower objects
    """
    return [
        User(
            user_id="follower456",
            username="follower1",
            display_name="Follower One",
            location="New York, NY",
            total_workouts=75
        ),
        User(
            user_id="follower789",
            username="follower2",
            display_name="Follower Two",
            location="Chicago, IL",
            total_workouts=50
        )
    ]


@pytest.fixture
def sample_ride_info() -> RideInfo:
    """
    Provides a sample RideInfo object for testing.

    Returns:
        RideInfo: A complete ride info object
    """
    return RideInfo(
        ride_id="ride123abc",
        title="30 min HIIT Ride",
        instructor_name="Robin Arzon",
        duration=1800,  # 30 minutes in seconds
        difficulty=7.5,
        ride_type="cycling"
    )


@pytest.fixture
def sample_performance_metrics() -> PerformanceMetrics:
    """
    Provides sample performance metrics with time series data.

    Returns:
        PerformanceMetrics: Performance data over time
    """
    return PerformanceMetrics(
        seconds_since_start=[0, 5, 10, 15, 20],
        output=[100.0, 150.0, 175.0, 160.0, 140.0],
        cadence=[80, 85, 90, 88, 82],
        resistance=[40, 45, 50, 48, 42],
        heart_rate=[120, 135, 145, 140, 130],
        speed=[15.5, 16.2, 17.0, 16.8, 16.0],
        distance=[0.0, 0.1, 0.2, 0.3, 0.4]
    )


@pytest.fixture
def sample_workout(sample_ride_info, sample_performance_metrics) -> Workout:
    """
    Provides a complete sample Workout object for testing.

    Args:
        sample_ride_info: Injected ride info fixture
        sample_performance_metrics: Injected performance metrics fixture

    Returns:
        Workout: A complete workout with all data
    """
    return Workout(
        workout_id="workout123",
        user_id="user123",
        ride_info=sample_ride_info,
        created_at="2024-01-15T10:30:00Z",
        start_time=1705318200,  # Unix timestamp
        end_time=1705320000,
        total_output=250.5,
        avg_output=150.0,
        avg_cadence=85.0,
        avg_resistance=45.0,
        avg_heart_rate=135.0,
        max_heart_rate=165.0,
        distance=7.5,
        calories=350.0,
        performance_metrics=sample_performance_metrics
    )


@pytest.fixture
def sample_workouts(sample_ride_info) -> List[Workout]:
    """
    Provides a list of sample workouts for testing.

    Args:
        sample_ride_info: Injected ride info fixture

    Returns:
        List[Workout]: Multiple workout objects
    """
    return [
        Workout(
            workout_id="workout1",
            user_id="user123",
            ride_info=sample_ride_info,
            created_at="2024-01-15T10:30:00Z",
            start_time=1705318200,
            end_time=1705320000,
            total_output=250.5,
            avg_output=150.0,
            avg_cadence=85.0,
            avg_resistance=45.0,
            distance=7.5,
            calories=350.0
        ),
        Workout(
            workout_id="workout2",
            user_id="user123",
            ride_info=sample_ride_info,
            created_at="2024-01-20T09:00:00Z",
            start_time=1705741200,
            end_time=1705743000,
            total_output=275.0,
            avg_output=165.0,
            avg_cadence=90.0,
            avg_resistance=48.0,
            distance=8.0,
            calories=380.0
        )
    ]


@pytest.fixture
def invalid_ride_info() -> RideInfo:
    """
    Provides an invalid RideInfo object (outdoor ride with no instructor).

    Returns:
        RideInfo: Invalid ride for testing validation
    """
    return RideInfo(
        ride_id="00000000000000000000000000000000",
        title="Outdoor Ride",
        instructor_name="",  # No instructor = invalid
        duration=1800,
        difficulty=0.0,
        ride_type="cycling"
    )


# =============================================================================
# API MOCKING FIXTURES - Mock Peloton API responses
# =============================================================================

@pytest.fixture
def mock_peloton_client():
    """
    Provides a mock PelotonClient for testing without real API calls.

    Returns:
        Mock: A mocked PelotonClient with common methods stubbed
    """
    mock_client = Mock(spec=PelotonClient)
    mock_client.user_id = "user123"
    mock_client.session_id = "mock_session_id"
    mock_client.bearer_token = "mock_bearer_token"

    # Mock authentication
    mock_client.authenticate.return_value = True
    mock_client._validate_bearer_token.return_value = True

    return mock_client


@pytest.fixture
def mock_api_user_response() -> Dict:
    """
    Provides a mock API response for user profile endpoint.

    Returns:
        Dict: Simulated Peloton API user response
    """
    return {
        "id": "user123",
        "username": "testuser",
        "name": "Test User",
        "image_url": "https://example.com/avatar.jpg",
        "location": "San Francisco, CA",
        "total_workouts": 100
    }


@pytest.fixture
def mock_api_workout_response() -> Dict:
    """
    Provides a mock API response for workout endpoint.

    Returns:
        Dict: Simulated Peloton API workout response
    """
    return {
        "id": "workout123",
        "user_id": "user123",
        "created_at": "2024-01-15T10:30:00Z",
        "start_time": 1705318200,
        "end_time": 1705320000,
        "fitness_discipline": "cycling",
        "peloton": {
            "ride": {
                "id": "ride123abc",
                "title": "30 min HIIT Ride",
                "instructor": {
                    "name": "Robin Arzon"
                },
                "duration": 1800,
                "difficulty_rating_avg": 7.5,
                "fitness_discipline": "cycling"
            }
        },
        "summaries": [
            {"slug": "total_output", "value": 250.5},
            {"slug": "calories", "value": 350.0},
            {"slug": "distance", "value": 7.5}
        ]
    }


@pytest.fixture
def mock_api_performance_response() -> Dict:
    """
    Provides a mock API response for workout performance graph endpoint.

    Returns:
        Dict: Simulated Peloton API performance response
    """
    return {
        "seconds_since_pedaling_start": [0, 5, 10, 15, 20],
        "metrics": [
            {"slug": "output", "values": [100.0, 150.0, 175.0, 160.0, 140.0]},
            {"slug": "cadence", "values": [80, 85, 90, 88, 82]},
            {"slug": "resistance", "values": [40, 45, 50, 48, 42]},
            {"slug": "heart_rate", "values": [120, 135, 145, 140, 130]}
        ],
        "summaries": [
            {"slug": "total_output", "value": 250.5},
            {"slug": "distance", "value": 7.5},
            {"slug": "calories", "value": 350.0}
        ],
        "average_summaries": [
            {"slug": "avg_output", "value": 150.0},
            {"slug": "avg_cadence", "value": 85.0},
            {"slug": "avg_resistance", "value": 45.0},
            {"slug": "avg_heart_rate", "value": 135.0},
            {"slug": "max_heart_rate", "value": 165.0}
        ]
    }


@pytest.fixture
def mock_api_followers_response() -> Dict:
    """
    Provides a mock API response for followers endpoint.

    Returns:
        Dict: Simulated Peloton API followers response
    """
    return {
        "data": [
            {
                "id": "follower456",
                "username": "follower1",
                "name": "Follower One",
                "location": "New York, NY",
                "total_workouts": 75
            },
            {
                "id": "follower789",
                "username": "follower2",
                "name": "Follower Two",
                "location": "Chicago, IL",
                "total_workouts": 50
            }
        ]
    }


# =============================================================================
# FILE SYSTEM FIXTURES - Temporary directories for testing
# =============================================================================

@pytest.fixture
def temp_data_dir(tmp_path):
    """
    Provides a temporary directory for testing file operations.
    Directory is automatically cleaned up after test completes.

    Args:
        tmp_path: Built-in pytest fixture providing temporary directory

    Returns:
        Path: Path to temporary data directory

    Usage:
        def test_save_data(temp_data_dir):
            manager = DataManager(str(temp_data_dir))
            manager.save_user_profile(user)
            # Files are saved to temp_data_dir and auto-cleaned
    """
    data_dir = tmp_path / "test_data"
    data_dir.mkdir()
    return data_dir


@pytest.fixture
def data_manager_with_temp_dir(temp_data_dir, monkeypatch):
    """
    Provides a DataManager instance configured with a temporary directory.
    Patches ALLOWED_BASE_DIR so the temp directory is within the allowed base.

    Args:
        temp_data_dir: Injected temporary directory fixture
        monkeypatch: Built-in pytest fixture for safely modifying attributes

    Returns:
        DataManager: Configured with isolated temporary storage

    Usage:
        def test_data_operations(data_manager_with_temp_dir):
            manager = data_manager_with_temp_dir
            manager.save_user_profile(user)
            loaded = manager.load_user_profile()
    """
    monkeypatch.setattr(DataManager, 'ALLOWED_BASE_DIR', temp_data_dir.parent)
    return DataManager(str(temp_data_dir))


@pytest.fixture
def populated_data_dir(temp_data_dir, sample_user, sample_workouts, sample_followers, monkeypatch):
    """
    Provides a temporary directory pre-populated with test data.
    Useful for testing data loading and analysis without setup code.

    Args:
        temp_data_dir: Temporary directory fixture
        sample_user: Sample user fixture
        sample_workouts: Sample workouts fixture
        sample_followers: Sample followers fixture
        monkeypatch: Built-in pytest fixture for safely modifying attributes

    Returns:
        tuple: (Path to data directory, DataManager instance)

    Usage:
        def test_load_existing_data(populated_data_dir):
            data_dir, manager = populated_data_dir
            user = manager.load_user_profile()
            workouts = manager.load_workouts()
    """
    monkeypatch.setattr(DataManager, 'ALLOWED_BASE_DIR', temp_data_dir.parent)
    manager = DataManager(str(temp_data_dir))

    # Pre-populate with sample data
    manager.save_user_profile(sample_user)
    manager.save_workouts(sample_workouts)
    manager.save_followers(sample_followers)

    return temp_data_dir, manager


# =============================================================================
# UTILITY FIXTURES - Helper functions and test utilities
# =============================================================================

@pytest.fixture
def mock_responses():
    """
    Provides the responses library for mocking HTTP requests.
    Must be used as a context manager or decorator.

    Returns:
        responses: Library for mocking requests

    Usage:
        def test_api_call(mock_responses):
            mock_responses.add(
                responses.GET,
                "https://api.onepeloton.com/api/user/123",
                json={"id": "123"},
                status=200
            )
            # Make request - will return mocked response
    """
    import responses
    return responses


@pytest.fixture
def freezer():
    """
    Provides time freezing utility for testing time-dependent code.
    Requires pytest-freezegun if available.

    Returns:
        FrozenDateTimeFactory or None: Time control utility

    Usage:
        def test_timestamps(freezer):
            freezer.move_to("2024-01-15 10:30:00")
            # All time operations now return frozen time
    """
    try:
        from freezegun import freeze_time
        return freeze_time
    except ImportError:
        # Return None if freezegun not installed
        return None


@pytest.fixture
def assert_json_equal():
    """
    Provides a helper function for comparing JSON-serializable objects.

    Returns:
        callable: Function to compare JSON structures

    Usage:
        def test_serialization(assert_json_equal):
            expected = {"key": "value"}
            actual = json.loads(json.dumps(obj))
            assert_json_equal(expected, actual)
    """
    def _assert_equal(expected, actual, msg=None):
        """Compare two JSON-serializable objects"""
        assert json.dumps(expected, sort_keys=True) == json.dumps(actual, sort_keys=True), msg

    return _assert_equal


# =============================================================================
# CONFIGURATION FIXTURES - Test environment setup
# =============================================================================

@pytest.fixture(autouse=True)
def reset_environment_variables(monkeypatch):
    """
    Automatically resets environment variables for each test to ensure isolation.
    This prevents tests from interfering with each other via env vars.

    Args:
        monkeypatch: Built-in pytest fixture for safely modifying environment

    Note:
        This fixture runs automatically for every test (autouse=True)
    """
    # Set safe test defaults
    monkeypatch.setenv("DIAGNOSTIC_MODE", "false")
    # Add other environment variables as needed


@pytest.fixture
def disable_network_calls(monkeypatch):
    """
    Disables all network calls to prevent accidental API calls during testing.
    Raises an error if any code attempts to make a network request.

    Args:
        monkeypatch: Built-in pytest fixture

    Usage:
        def test_offline_functionality(disable_network_calls):
            # Any network call will raise an error
            # Forces use of mocks
    """
    import socket

    def guard(*args, **kwargs):
        raise RuntimeError(
            "Network call attempted during test! "
            "Use mock_peloton_client or responses fixture instead."
        )

    monkeypatch.setattr(socket, "socket", guard)


# =============================================================================
# MARKER FIXTURES - Pytest markers for test organization
# =============================================================================

# Use these markers in tests:
# @pytest.mark.unit - Fast unit tests with no dependencies
# @pytest.mark.integration - Tests that may use external services
# @pytest.mark.slow - Tests that take significant time
# @pytest.mark.api - Tests that interact with Peloton API (mocked or real)
