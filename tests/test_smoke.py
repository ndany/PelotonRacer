"""
Smoke tests to verify test infrastructure is working correctly

These are basic tests that validate:
1. Pytest is configured correctly
2. Fixtures are accessible and working
3. Test environment is properly isolated
4. All major dependencies can be imported
"""

import pytest
from pathlib import Path
import json


# =============================================================================
# ENVIRONMENT SMOKE TESTS
# =============================================================================

@pytest.mark.unit
def test_pytest_runs():
    """Verify pytest is working"""
    assert True


@pytest.mark.unit
def test_imports():
    """Verify all core modules can be imported"""
    # Models
    from src.models.models import User, Workout, RideInfo, PerformanceMetrics, CommonRide

    # Services
    from src.services.data_manager import DataManager
    from src.services.race_analyzer import RaceAnalyzer

    # API
    from src.api.peloton_client import PelotonClient

    # Config
    from src.config import API_PAGE_SIZE, MAX_USER_WORKOUTS_FULL

    # If we get here, all imports succeeded
    assert True


# =============================================================================
# FIXTURE SMOKE TESTS - Verify all fixtures work
# =============================================================================

@pytest.mark.unit
def test_sample_user_fixture(sample_user):
    """Verify sample_user fixture provides valid User object"""
    assert sample_user.user_id == "user123"
    assert sample_user.username == "testuser"
    assert sample_user.total_workouts == 100


@pytest.mark.unit
def test_sample_follower_fixture(sample_follower):
    """Verify sample_follower fixture provides valid User object"""
    assert sample_follower.user_id == "follower456"
    assert sample_follower.username == "follower1"


@pytest.mark.unit
def test_sample_followers_fixture(sample_followers):
    """Verify sample_followers fixture provides list of Users"""
    assert len(sample_followers) == 2
    assert all(hasattr(f, 'user_id') for f in sample_followers)


@pytest.mark.unit
def test_sample_ride_info_fixture(sample_ride_info):
    """Verify sample_ride_info fixture provides valid RideInfo"""
    assert sample_ride_info.ride_id == "ride123abc"
    assert sample_ride_info.title == "30 min HIIT Ride"
    assert sample_ride_info.instructor_name == "Robin Arzon"
    assert sample_ride_info.duration == 1800


@pytest.mark.unit
def test_sample_performance_metrics_fixture(sample_performance_metrics):
    """Verify sample_performance_metrics fixture provides valid data"""
    assert len(sample_performance_metrics.seconds_since_start) == 5
    assert len(sample_performance_metrics.output) == 5
    assert len(sample_performance_metrics.cadence) == 5


@pytest.mark.unit
def test_sample_workout_fixture(sample_workout):
    """Verify sample_workout fixture provides complete Workout"""
    assert sample_workout.workout_id == "workout123"
    assert sample_workout.user_id == "user123"
    assert sample_workout.ride_info.title == "30 min HIIT Ride"
    assert sample_workout.performance_metrics is not None
    assert sample_workout.total_output == 250.5


@pytest.mark.unit
def test_sample_workouts_fixture(sample_workouts):
    """Verify sample_workouts fixture provides list of Workouts"""
    assert len(sample_workouts) == 2
    assert sample_workouts[0].workout_id == "workout1"
    assert sample_workouts[1].workout_id == "workout2"


@pytest.mark.unit
def test_invalid_ride_info_fixture(invalid_ride_info):
    """Verify invalid_ride_info fixture provides invalid ride"""
    from src.services.data_manager import DataManager

    # Should be invalid due to no instructor
    assert not DataManager.is_valid_ride(invalid_ride_info)


# =============================================================================
# API MOCKING FIXTURES SMOKE TESTS
# =============================================================================

@pytest.mark.unit
def test_mock_peloton_client_fixture(mock_peloton_client):
    """Verify mock_peloton_client fixture is properly configured"""
    assert mock_peloton_client.user_id == "user123"
    assert mock_peloton_client.authenticate() is True


@pytest.mark.unit
def test_mock_api_user_response_fixture(mock_api_user_response):
    """Verify mock API user response has correct structure"""
    assert "id" in mock_api_user_response
    assert "username" in mock_api_user_response
    assert mock_api_user_response["id"] == "user123"


@pytest.mark.unit
def test_mock_api_workout_response_fixture(mock_api_workout_response):
    """Verify mock API workout response has correct structure"""
    assert "id" in mock_api_workout_response
    assert "peloton" in mock_api_workout_response
    assert "ride" in mock_api_workout_response["peloton"]
    assert "summaries" in mock_api_workout_response


@pytest.mark.unit
def test_mock_api_performance_response_fixture(mock_api_performance_response):
    """Verify mock API performance response has correct structure"""
    assert "seconds_since_pedaling_start" in mock_api_performance_response
    assert "metrics" in mock_api_performance_response
    assert "summaries" in mock_api_performance_response
    assert "average_summaries" in mock_api_performance_response


@pytest.mark.unit
def test_mock_api_followers_response_fixture(mock_api_followers_response):
    """Verify mock API followers response has correct structure"""
    assert "data" in mock_api_followers_response
    assert len(mock_api_followers_response["data"]) == 2


# =============================================================================
# FILE SYSTEM FIXTURES SMOKE TESTS
# =============================================================================

@pytest.mark.unit
def test_temp_data_dir_fixture(temp_data_dir):
    """Verify temp_data_dir fixture creates isolated directory"""
    assert temp_data_dir.exists()
    assert temp_data_dir.is_dir()

    # Verify we can write to it
    test_file = temp_data_dir / "test.txt"
    test_file.write_text("test content")
    assert test_file.exists()
    assert test_file.read_text() == "test content"


@pytest.mark.unit
def test_data_manager_with_temp_dir_fixture(data_manager_with_temp_dir):
    """Verify data_manager_with_temp_dir fixture provides working manager"""
    from src.services.data_manager import DataManager

    assert isinstance(data_manager_with_temp_dir, DataManager)
    assert data_manager_with_temp_dir.data_dir.exists()


@pytest.mark.unit
def test_populated_data_dir_fixture(populated_data_dir):
    """Verify populated_data_dir fixture has pre-loaded data"""
    data_dir, manager = populated_data_dir

    # Verify data files exist
    assert manager.user_profile_file.exists()
    assert manager.workouts_file.exists()
    assert manager.followers_file.exists()

    # Verify data can be loaded
    user = manager.load_user_profile()
    assert user is not None
    assert user.user_id == "user123"

    workouts = manager.load_workouts(valid_only=False)
    assert len(workouts) == 2

    followers = manager.load_followers()
    assert len(followers) == 2


# =============================================================================
# UTILITY FIXTURES SMOKE TESTS
# =============================================================================

@pytest.mark.unit
def test_assert_json_equal_fixture(assert_json_equal):
    """Verify assert_json_equal utility works"""
    dict1 = {"key": "value", "number": 42}
    dict2 = {"number": 42, "key": "value"}  # Different order

    # Should pass - JSON comparison ignores order
    assert_json_equal(dict1, dict2)


@pytest.mark.unit
def test_assert_json_equal_fails_on_difference(assert_json_equal):
    """Verify assert_json_equal detects differences"""
    dict1 = {"key": "value1"}
    dict2 = {"key": "value2"}

    with pytest.raises(AssertionError):
        assert_json_equal(dict1, dict2)


# =============================================================================
# ISOLATION SMOKE TESTS - Verify tests are isolated
# =============================================================================

@pytest.mark.unit
def test_isolation_write_to_temp_dir(temp_data_dir):
    """Write data to temp dir - should not affect other tests"""
    test_file = temp_data_dir / "isolation_test.json"
    test_file.write_text('{"test": "data"}')
    assert test_file.exists()


@pytest.mark.unit
def test_isolation_verify_clean_temp_dir(temp_data_dir):
    """Verify temp dir is clean for each test (isolation check)"""
    # This test should NOT see the file from previous test
    test_file = temp_data_dir / "isolation_test.json"
    assert not test_file.exists(), "Temp dir should be clean for each test"


# =============================================================================
# MODEL SERIALIZATION SMOKE TESTS
# =============================================================================

@pytest.mark.unit
def test_user_serialization(sample_user):
    """Verify User model can be serialized and deserialized"""
    from src.models.models import User

    # Serialize
    user_dict = sample_user.to_dict()
    assert isinstance(user_dict, dict)
    assert user_dict["user_id"] == "user123"

    # Deserialize
    restored_user = User(**user_dict)
    assert restored_user.user_id == sample_user.user_id
    assert restored_user.username == sample_user.username


@pytest.mark.unit
def test_workout_serialization(sample_workout):
    """Verify Workout model can be serialized and deserialized"""
    from src.models.models import Workout

    # Serialize
    workout_dict = sample_workout.to_dict()
    assert isinstance(workout_dict, dict)
    assert workout_dict["workout_id"] == "workout123"

    # Deserialize
    restored_workout = Workout.from_dict(workout_dict)
    assert restored_workout.workout_id == sample_workout.workout_id
    assert restored_workout.total_output == sample_workout.total_output


# =============================================================================
# DATA MANAGER BASIC SMOKE TESTS
# =============================================================================

@pytest.mark.unit
def test_data_manager_initialization(temp_data_dir, monkeypatch):
    """Verify DataManager can be initialized"""
    from src.services.data_manager import DataManager

    monkeypatch.setattr(DataManager, 'ALLOWED_BASE_DIR', temp_data_dir.parent)
    manager = DataManager(str(temp_data_dir))
    assert manager.data_dir.exists()


@pytest.mark.unit
def test_data_manager_save_and_load_user(data_manager_with_temp_dir, sample_user):
    """Verify DataManager can save and load user profile"""
    manager = data_manager_with_temp_dir

    # Save
    manager.save_user_profile(sample_user)
    assert manager.user_profile_file.exists()

    # Load
    loaded_user = manager.load_user_profile()
    assert loaded_user is not None
    assert loaded_user.user_id == sample_user.user_id
    assert loaded_user.username == sample_user.username


@pytest.mark.unit
def test_data_manager_save_and_load_workouts(data_manager_with_temp_dir, sample_workouts):
    """Verify DataManager can save and load workouts"""
    manager = data_manager_with_temp_dir

    # Save
    manager.save_workouts(sample_workouts)
    assert manager.workouts_file.exists()

    # Load
    loaded_workouts = manager.load_workouts(valid_only=False)
    assert len(loaded_workouts) == 2
    assert loaded_workouts[0].workout_id == "workout1"


# =============================================================================
# PYTEST MARKERS SMOKE TEST
# =============================================================================

@pytest.mark.unit
@pytest.mark.slow
def test_markers_work():
    """Verify pytest markers are configured correctly"""
    # This test has multiple markers
    # Run with: pytest -m unit
    # Or: pytest -m "not slow"
    assert True
