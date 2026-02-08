"""
Comprehensive tests for src/models/models.py

Tests cover:
1. Standard model serialization/deserialization
2. API response parsing
3. Security & validation (missing fields, invalid types, code injection, bounds checking)
4. Round-trip serialization
5. Edge cases and defensive deserialization

All tests use @pytest.mark.unit marker and focus on secure, defensive deserialization.
"""

import pytest
import sys
from typing import Dict, List
from src.models.models import User, Workout, RideInfo, PerformanceMetrics, CommonRide


# =============================================================================
# USER MODEL TESTS
# =============================================================================

@pytest.mark.unit
def test_user_from_api_response(mock_api_user_response):
    """Test User.from_api_response() with valid API data"""
    user = User.from_api_response(mock_api_user_response)

    assert user.user_id == "user123"
    assert user.username == "testuser"
    assert user.display_name == "Test User"
    assert user.image_url == "https://example.com/avatar.jpg"
    assert user.location == "San Francisco, CA"
    assert user.total_workouts == 100


@pytest.mark.unit
def test_user_to_dict(sample_user):
    """Test User.to_dict() serialization"""
    user_dict = sample_user.to_dict()

    assert isinstance(user_dict, dict)
    assert user_dict["user_id"] == "user123"
    assert user_dict["username"] == "testuser"
    assert user_dict["display_name"] == "Test User"
    assert user_dict["image_url"] == "https://example.com/avatar.jpg"
    assert user_dict["location"] == "San Francisco, CA"
    assert user_dict["total_workouts"] == 100


@pytest.mark.unit
def test_user_round_trip_serialization(sample_user):
    """Test User serialization round-trip (to_dict -> __init__)"""
    # Serialize
    user_dict = sample_user.to_dict()

    # Deserialize
    restored_user = User(**user_dict)

    # Verify all fields match
    assert restored_user.user_id == sample_user.user_id
    assert restored_user.username == sample_user.username
    assert restored_user.display_name == sample_user.display_name
    assert restored_user.image_url == sample_user.image_url
    assert restored_user.location == sample_user.location
    assert restored_user.total_workouts == sample_user.total_workouts


@pytest.mark.unit
def test_user_from_api_response_with_missing_fields():
    """Test User.from_api_response() handles missing optional fields gracefully"""
    minimal_data = {
        "id": "user456",
        "username": "minimaluser"
        # Missing: name, image_url, location, total_workouts
    }

    user = User.from_api_response(minimal_data)

    assert user.user_id == "user456"
    assert user.username == "minimaluser"
    assert user.display_name == ""  # Default value
    assert user.image_url == ""  # Default value
    assert user.location == ""  # Default value
    assert user.total_workouts == 0  # Default value


@pytest.mark.unit
def test_user_from_api_response_with_empty_dict():
    """Test User.from_api_response() with completely empty dict"""
    empty_data = {}

    user = User.from_api_response(empty_data)

    # Should create user with all default values
    assert user.user_id == ""
    assert user.username == ""
    assert user.display_name == ""
    assert user.image_url == ""
    assert user.location == ""
    assert user.total_workouts == 0


@pytest.mark.unit
def test_user_from_api_response_with_none_values():
    """Test User.from_api_response() handles None values safely"""
    data_with_nones = {
        "id": "user789",
        "username": None,  # None instead of string
        "name": None,
        "image_url": None,
        "location": None,
        "total_workouts": None
    }

    user = User.from_api_response(data_with_nones)

    # .get() with defaults should handle None
    assert user.user_id == "user789"
    # None values are returned as-is (not converted to defaults)
    assert user.username is None
    assert user.display_name is None
    assert user.image_url is None
    assert user.location is None
    assert user.total_workouts is None


@pytest.mark.unit
def test_user_from_api_response_ignores_extra_fields():
    """Test User.from_api_response() ignores unexpected extra fields"""
    data_with_extras = {
        "id": "user999",
        "username": "extrauser",
        "name": "Extra User",
        "malicious_code": "__import__('os').system('rm -rf /')",  # Should be ignored
        "extra_field": "extra_value",
        "nested": {"should": "be_ignored"}
    }

    user = User.from_api_response(data_with_extras)

    # Only expected fields should be present
    assert user.user_id == "user999"
    assert user.username == "extrauser"
    assert user.display_name == "Extra User"
    assert not hasattr(user, "malicious_code")
    assert not hasattr(user, "extra_field")
    assert not hasattr(user, "nested")


@pytest.mark.unit
def test_user_no_code_injection_via_string_fields():
    """Test User fields don't execute injected code"""
    malicious_data = {
        "id": "__import__('os').system('echo pwned')",
        "username": "eval('1+1')",
        "name": "exec('print(\"hacked\")')",
        "image_url": "${os.system('ls')}",
        "location": "$(rm -rf /)"
    }

    user = User.from_api_response(malicious_data)

    # Strings should be stored as-is, not evaluated
    assert user.user_id == "__import__('os').system('echo pwned')"
    assert user.username == "eval('1+1')"
    assert user.display_name == "exec('print(\"hacked\")')"
    # No code should be executed - just stored as strings


@pytest.mark.unit
def test_user_numeric_bounds_validation():
    """Test User handles invalid numeric values (negative, overflow)"""
    data_with_invalid_numbers = {
        "id": "user_numbers",
        "username": "numbertest",
        "total_workouts": -100  # Negative workouts
    }

    user = User.from_api_response(data_with_invalid_numbers)

    # Should accept the value as-is (model doesn't validate, just stores)
    assert user.total_workouts == -100
    # Note: Validation should happen at business logic layer, not model


@pytest.mark.unit
def test_user_with_very_large_numbers():
    """Test User handles very large numeric values"""
    data_with_large_numbers = {
        "id": "user_large",
        "username": "largetest",
        "total_workouts": sys.maxsize  # Maximum integer
    }

    user = User.from_api_response(data_with_large_numbers)

    assert user.total_workouts == sys.maxsize


@pytest.mark.unit
def test_user_with_very_long_strings():
    """Test User handles extremely long string values"""
    very_long_string = "A" * 100000  # 100KB string

    data_with_long_strings = {
        "id": very_long_string,
        "username": very_long_string,
        "name": very_long_string
    }

    user = User.from_api_response(data_with_long_strings)

    # Should store long strings without error
    assert len(user.user_id) == 100000
    assert len(user.username) == 100000
    assert len(user.display_name) == 100000


# =============================================================================
# RIDEINFO MODEL TESTS
# =============================================================================

@pytest.mark.unit
def test_ride_info_from_api_response(mock_api_workout_response):
    """Test RideInfo.from_api_response() with valid workout API data"""
    ride_info = RideInfo.from_api_response(mock_api_workout_response)

    assert ride_info.ride_id == "ride123abc"
    assert ride_info.title == "30 min HIIT Ride"
    assert ride_info.instructor_name == "Robin Arzon"
    assert ride_info.duration == 1800
    assert ride_info.difficulty == 7.5
    assert ride_info.ride_type == "cycling"


@pytest.mark.unit
def test_ride_info_to_dict(sample_ride_info):
    """Test RideInfo.to_dict() serialization"""
    ride_dict = sample_ride_info.to_dict()

    assert isinstance(ride_dict, dict)
    assert ride_dict["ride_id"] == "ride123abc"
    assert ride_dict["title"] == "30 min HIIT Ride"
    assert ride_dict["instructor_name"] == "Robin Arzon"
    assert ride_dict["duration"] == 1800
    assert ride_dict["difficulty"] == 7.5
    assert ride_dict["ride_type"] == "cycling"


@pytest.mark.unit
def test_ride_info_round_trip_serialization(sample_ride_info):
    """Test RideInfo serialization round-trip"""
    # Serialize
    ride_dict = sample_ride_info.to_dict()

    # Deserialize
    restored_ride = RideInfo(**ride_dict)

    # Verify all fields match
    assert restored_ride.ride_id == sample_ride_info.ride_id
    assert restored_ride.title == sample_ride_info.title
    assert restored_ride.instructor_name == sample_ride_info.instructor_name
    assert restored_ride.duration == sample_ride_info.duration
    assert restored_ride.difficulty == sample_ride_info.difficulty
    assert restored_ride.ride_type == sample_ride_info.ride_type


@pytest.mark.unit
def test_ride_info_from_api_response_outdoor_ride():
    """Test RideInfo.from_api_response() with outdoor ride (no peloton.ride)"""
    outdoor_ride_data = {
        "ride": {
            "id": "outdoor123",
            "title": "Outdoor Cycling",
            "duration": 3600,
            "fitness_discipline": "cycling"
        },
        "fitness_discipline": "cycling"
    }

    ride_info = RideInfo.from_api_response(outdoor_ride_data)

    assert ride_info.ride_id == "outdoor123"
    assert ride_info.title == "Outdoor Cycling"
    assert ride_info.instructor_name == ""  # No instructor for outdoor
    assert ride_info.duration == 3600
    assert ride_info.difficulty == 0.0  # No difficulty rating
    assert ride_info.ride_type == "cycling"


@pytest.mark.unit
def test_ride_info_from_api_response_with_difficulty_estimate():
    """Test RideInfo handles difficulty_estimate when difficulty_rating_avg missing"""
    data_with_estimate = {
        "peloton": {
            "ride": {
                "id": "ride_est",
                "title": "Test Ride",
                "duration": 1800,
                "difficulty_estimate": 6.5,  # Instead of difficulty_rating_avg
                "fitness_discipline": "cycling"
            }
        }
    }

    ride_info = RideInfo.from_api_response(data_with_estimate)

    assert ride_info.difficulty == 6.5


@pytest.mark.unit
def test_ride_info_from_api_response_title_fallback():
    """Test RideInfo.from_api_response() title fallback logic"""
    # Title in workout data directly, not in ride
    data_with_title_in_workout = {
        "title": "Workout Title",
        "ride": {
            "id": "ride_title_test",
            "duration": 1800
        }
    }

    ride_info = RideInfo.from_api_response(data_with_title_in_workout)

    assert ride_info.title == "Workout Title"


@pytest.mark.unit
def test_ride_info_from_api_response_instructor_from_peloton_ride():
    """Test RideInfo extracts instructor from peloton.ride.instructor"""
    data_with_nested_instructor = {
        "peloton": {
            "ride": {
                "id": "ride_nested",
                "title": "Test Ride",
                "duration": 1800,
                "instructor": {
                    "name": "Nested Instructor"
                }
            }
        }
    }

    ride_info = RideInfo.from_api_response(data_with_nested_instructor)

    assert ride_info.instructor_name == "Nested Instructor"


@pytest.mark.unit
def test_ride_info_from_api_response_with_missing_fields():
    """Test RideInfo.from_api_response() handles missing fields gracefully"""
    minimal_data = {
        "ride": {
            "id": "minimal_ride"
            # Missing: title, instructor, duration, difficulty, fitness_discipline
        }
    }

    ride_info = RideInfo.from_api_response(minimal_data)

    assert ride_info.ride_id == "minimal_ride"
    assert ride_info.title == ""
    assert ride_info.instructor_name == ""
    assert ride_info.duration == 0
    assert ride_info.difficulty == 0.0
    assert ride_info.ride_type == ""


@pytest.mark.unit
def test_ride_info_from_api_response_with_none_values():
    """Test RideInfo.from_api_response() handles None values safely"""
    data_with_nones = {
        "ride": {
            "id": "none_ride",
            "title": None,
            "instructor": None,  # Not a dict
            "duration": None,
            "difficulty_rating_avg": None,
            "fitness_discipline": None
        }
    }

    ride_info = RideInfo.from_api_response(data_with_nones)

    assert ride_info.ride_id == "none_ride"
    assert ride_info.title == ""  # None is converted to "" by the `or ""` logic
    assert ride_info.instructor_name == ""
    assert ride_info.duration is None
    assert ride_info.difficulty == 0.0  # None is converted to 0.0 by the `or 0.0` logic
    assert ride_info.ride_type == ""  # None is converted to "" by the `or ""` logic


@pytest.mark.unit
def test_ride_info_no_code_injection():
    """Test RideInfo doesn't execute injected code"""
    malicious_data = {
        "ride": {
            "id": "__import__('os').system('rm -rf /')",
            "title": "eval('malicious')",
            "instructor": {
                "name": "exec('hacked')"
            },
            "fitness_discipline": "${os.system('ls')}"
        }
    }

    ride_info = RideInfo.from_api_response(malicious_data)

    # Strings stored as-is, not evaluated
    assert ride_info.ride_id == "__import__('os').system('rm -rf /')"
    assert ride_info.title == "eval('malicious')"
    assert ride_info.instructor_name == "exec('hacked')"
    assert ride_info.ride_type == "${os.system('ls')}"


@pytest.mark.unit
def test_ride_info_numeric_bounds():
    """Test RideInfo handles invalid numeric values"""
    data_with_invalid_numbers = {
        "ride": {
            "id": "bounds_test",
            "title": "Test",
            "duration": -3600,  # Negative duration
            "difficulty_rating_avg": 999.99  # Unrealistic difficulty
        }
    }

    ride_info = RideInfo.from_api_response(data_with_invalid_numbers)

    # Model stores values as-is
    assert ride_info.duration == -3600
    assert ride_info.difficulty == 999.99


@pytest.mark.unit
def test_ride_info_with_non_dict_instructor():
    """Test RideInfo handles instructor as non-dict gracefully"""
    data_with_string_instructor = {
        "ride": {
            "id": "string_instructor",
            "title": "Test",
            "instructor": "Not a dict"  # Should be dict with 'name' key
        }
    }

    ride_info = RideInfo.from_api_response(data_with_string_instructor)

    # Should not crash, instructor_name should be empty
    assert ride_info.instructor_name == ""


# =============================================================================
# PERFORMANCEMETRICS MODEL TESTS
# =============================================================================

@pytest.mark.unit
def test_performance_metrics_from_api_response(mock_api_performance_response):
    """Test PerformanceMetrics.from_api_response() with valid API data"""
    metrics = PerformanceMetrics.from_api_response(mock_api_performance_response)

    assert metrics.seconds_since_start == [0, 5, 10, 15, 20]
    assert metrics.output == [100.0, 150.0, 175.0, 160.0, 140.0]
    assert metrics.cadence == [80, 85, 90, 88, 82]
    assert metrics.resistance == [40, 45, 50, 48, 42]
    assert metrics.heart_rate == [120, 135, 145, 140, 130]


@pytest.mark.unit
def test_performance_metrics_to_dict(sample_performance_metrics):
    """Test PerformanceMetrics.to_dict() serialization"""
    metrics_dict = sample_performance_metrics.to_dict()

    assert isinstance(metrics_dict, dict)
    assert metrics_dict["seconds_since_start"] == [0, 5, 10, 15, 20]
    assert metrics_dict["output"] == [100.0, 150.0, 175.0, 160.0, 140.0]
    assert metrics_dict["cadence"] == [80, 85, 90, 88, 82]
    assert metrics_dict["resistance"] == [40, 45, 50, 48, 42]
    assert metrics_dict["heart_rate"] == [120, 135, 145, 140, 130]
    assert metrics_dict["speed"] == [15.5, 16.2, 17.0, 16.8, 16.0]
    assert metrics_dict["distance"] == [0.0, 0.1, 0.2, 0.3, 0.4]


@pytest.mark.unit
def test_performance_metrics_round_trip_serialization(sample_performance_metrics):
    """Test PerformanceMetrics serialization round-trip"""
    # Serialize
    metrics_dict = sample_performance_metrics.to_dict()

    # Deserialize
    restored_metrics = PerformanceMetrics(**metrics_dict)

    # Verify all fields match
    assert restored_metrics.seconds_since_start == sample_performance_metrics.seconds_since_start
    assert restored_metrics.output == sample_performance_metrics.output
    assert restored_metrics.cadence == sample_performance_metrics.cadence
    assert restored_metrics.resistance == sample_performance_metrics.resistance
    assert restored_metrics.heart_rate == sample_performance_metrics.heart_rate
    assert restored_metrics.speed == sample_performance_metrics.speed
    assert restored_metrics.distance == sample_performance_metrics.distance


@pytest.mark.unit
def test_performance_metrics_from_api_response_with_missing_metrics():
    """Test PerformanceMetrics.from_api_response() with missing metric types"""
    partial_data = {
        "seconds_since_pedaling_start": [0, 5, 10],
        "metrics": [
            {"slug": "output", "values": [100.0, 150.0, 175.0]},
            # Missing: cadence, resistance, heart_rate, speed, distance
        ]
    }

    metrics = PerformanceMetrics.from_api_response(partial_data)

    assert metrics.seconds_since_start == [0, 5, 10]
    assert metrics.output == [100.0, 150.0, 175.0]
    assert metrics.cadence == []  # Default empty list
    assert metrics.resistance == []
    assert metrics.heart_rate == []
    assert metrics.speed == []
    assert metrics.distance == []


@pytest.mark.unit
def test_performance_metrics_from_api_response_with_empty_metrics():
    """Test PerformanceMetrics.from_api_response() with empty metrics list"""
    empty_data = {
        "seconds_since_pedaling_start": [],
        "metrics": []
    }

    metrics = PerformanceMetrics.from_api_response(empty_data)

    assert metrics.seconds_since_start == []
    assert metrics.output == []
    assert metrics.cadence == []
    assert metrics.resistance == []
    assert metrics.heart_rate == []
    assert metrics.speed == []
    assert metrics.distance == []


@pytest.mark.unit
def test_performance_metrics_from_api_response_with_none_values():
    """Test PerformanceMetrics handles None values in metrics"""
    data_with_nones = {
        "seconds_since_pedaling_start": [0, 5, 10],
        "metrics": [
            {"slug": "output", "values": [100.0, None, 175.0]},  # None in values
            {"slug": "cadence", "values": [80, 85, None]},
            {"slug": "heart_rate", "values": [None, None, None]}
        ]
    }

    metrics = PerformanceMetrics.from_api_response(data_with_nones)

    # Should preserve None values (type hints allow Optional)
    assert metrics.output == [100.0, None, 175.0]
    assert metrics.cadence == [80, 85, None]
    assert metrics.heart_rate == [None, None, None]


@pytest.mark.unit
def test_performance_metrics_from_api_response_with_missing_seconds():
    """Test PerformanceMetrics when seconds_since_pedaling_start is missing"""
    data_without_seconds = {
        "metrics": [
            {"slug": "output", "values": [100.0, 150.0]}
        ]
        # Missing: seconds_since_pedaling_start
    }

    metrics = PerformanceMetrics.from_api_response(data_without_seconds)

    assert metrics.seconds_since_start == []  # Empty list from .get() default
    assert metrics.output == [100.0, 150.0]


@pytest.mark.unit
def test_performance_metrics_no_code_injection():
    """Test PerformanceMetrics doesn't execute injected code in slugs"""
    # Attempt code injection via slug names (dictionary keys)
    malicious_data = {
        "seconds_since_pedaling_start": [0, 5],
        "metrics": [
            {"slug": "__import__('os').system('rm -rf /')", "values": [100, 150]},
            {"slug": "eval('malicious')", "values": [80, 85]}
        ]
    }

    metrics = PerformanceMetrics.from_api_response(malicious_data)

    # Malicious slugs should not match expected slugs, so lists remain empty
    assert metrics.output == []
    assert metrics.cadence == []
    # No code should be executed


@pytest.mark.unit
def test_performance_metrics_with_unknown_metric_slugs():
    """Test PerformanceMetrics ignores unknown metric types"""
    data_with_unknown_slugs = {
        "seconds_since_pedaling_start": [0, 5, 10],
        "metrics": [
            {"slug": "output", "values": [100.0, 150.0, 175.0]},
            {"slug": "unknown_metric", "values": [1, 2, 3]},  # Unknown
            {"slug": "another_unknown", "values": [4, 5, 6]}  # Unknown
        ]
    }

    metrics = PerformanceMetrics.from_api_response(data_with_unknown_slugs)

    assert metrics.output == [100.0, 150.0, 175.0]
    # Unknown metrics should be ignored
    assert not hasattr(metrics, "unknown_metric")
    assert not hasattr(metrics, "another_unknown")


@pytest.mark.unit
def test_performance_metrics_with_very_large_lists():
    """Test PerformanceMetrics handles very large metric arrays"""
    large_size = 10000
    large_data = {
        "seconds_since_pedaling_start": list(range(large_size)),
        "metrics": [
            {"slug": "output", "values": [150.0] * large_size},
            {"slug": "cadence", "values": [85] * large_size}
        ]
    }

    metrics = PerformanceMetrics.from_api_response(large_data)

    assert len(metrics.seconds_since_start) == large_size
    assert len(metrics.output) == large_size
    assert len(metrics.cadence) == large_size


@pytest.mark.unit
def test_performance_metrics_default_factory():
    """Test PerformanceMetrics uses default_factory for empty lists"""
    # Create without any parameters
    metrics = PerformanceMetrics()

    # All fields should be empty lists (not None)
    assert metrics.seconds_since_start == []
    assert metrics.output == []
    assert metrics.cadence == []
    assert metrics.resistance == []
    assert metrics.heart_rate == []
    assert metrics.speed == []
    assert metrics.distance == []


# =============================================================================
# WORKOUT MODEL TESTS
# =============================================================================

@pytest.mark.unit
def test_workout_from_api_response(mock_api_workout_response):
    """Test Workout.from_api_response() with valid API data"""
    workout = Workout.from_api_response(mock_api_workout_response)

    assert workout.workout_id == "workout123"
    assert workout.user_id == "user123"
    assert workout.ride_info.title == "30 min HIIT Ride"
    assert workout.created_at == "2024-01-15T10:30:00Z"
    assert workout.start_time == 1705318200
    assert workout.end_time == 1705320000
    assert workout.total_output == 250.5
    assert workout.calories == 350.0
    assert workout.distance == 7.5


@pytest.mark.unit
def test_workout_from_api_response_with_performance_data(
    mock_api_workout_response,
    mock_api_performance_response
):
    """Test Workout.from_api_response() with performance data included"""
    workout = Workout.from_api_response(
        mock_api_workout_response,
        mock_api_performance_response
    )

    assert workout.workout_id == "workout123"
    assert workout.performance_metrics is not None
    assert workout.performance_metrics.output == [100.0, 150.0, 175.0, 160.0, 140.0]
    assert workout.performance_metrics.cadence == [80, 85, 90, 88, 82]


@pytest.mark.unit
def test_workout_to_dict(sample_workout):
    """Test Workout.to_dict() serialization"""
    workout_dict = sample_workout.to_dict()

    assert isinstance(workout_dict, dict)
    assert workout_dict["workout_id"] == "workout123"
    assert workout_dict["user_id"] == "user123"
    assert workout_dict["ride_info"]["title"] == "30 min HIIT Ride"
    assert workout_dict["total_output"] == 250.5
    assert workout_dict["performance_metrics"] is not None
    assert isinstance(workout_dict["performance_metrics"], dict)


@pytest.mark.unit
def test_workout_to_dict_without_performance_metrics(sample_workout):
    """Test Workout.to_dict() when performance_metrics is None"""
    workout = Workout(
        workout_id="workout_no_perf",
        user_id="user123",
        ride_info=sample_workout.ride_info,
        created_at="2024-01-15T10:30:00Z",
        start_time=1705318200,
        end_time=1705320000,
        performance_metrics=None  # No performance data
    )

    workout_dict = workout.to_dict()

    assert workout_dict["performance_metrics"] is None


@pytest.mark.unit
def test_workout_from_dict(sample_workout):
    """Test Workout.from_dict() deserialization"""
    workout_dict = sample_workout.to_dict()

    restored_workout = Workout.from_dict(workout_dict)

    assert restored_workout.workout_id == sample_workout.workout_id
    assert restored_workout.user_id == sample_workout.user_id
    assert restored_workout.ride_info.title == sample_workout.ride_info.title
    assert restored_workout.total_output == sample_workout.total_output
    assert restored_workout.performance_metrics is not None


@pytest.mark.unit
def test_workout_round_trip_serialization(sample_workout):
    """Test Workout complete serialization round-trip"""
    # Serialize
    workout_dict = sample_workout.to_dict()

    # Deserialize
    restored_workout = Workout.from_dict(workout_dict)

    # Verify all key fields match
    assert restored_workout.workout_id == sample_workout.workout_id
    assert restored_workout.user_id == sample_workout.user_id
    assert restored_workout.created_at == sample_workout.created_at
    assert restored_workout.start_time == sample_workout.start_time
    assert restored_workout.end_time == sample_workout.end_time
    assert restored_workout.total_output == sample_workout.total_output
    assert restored_workout.avg_output == sample_workout.avg_output
    assert restored_workout.avg_cadence == sample_workout.avg_cadence
    assert restored_workout.distance == sample_workout.distance
    assert restored_workout.calories == sample_workout.calories

    # Verify nested RideInfo
    assert restored_workout.ride_info.ride_id == sample_workout.ride_info.ride_id
    assert restored_workout.ride_info.title == sample_workout.ride_info.title

    # Verify nested PerformanceMetrics
    assert len(restored_workout.performance_metrics.output) == len(sample_workout.performance_metrics.output)


@pytest.mark.unit
def test_workout_from_dict_without_performance_metrics():
    """Test Workout.from_dict() when performance_metrics is None"""
    workout_dict = {
        "workout_id": "workout_minimal",
        "user_id": "user123",
        "ride_info": {
            "ride_id": "ride123",
            "title": "Test Ride",
            "instructor_name": "Test Instructor",
            "duration": 1800,
            "difficulty": 7.0,
            "ride_type": "cycling"
        },
        "created_at": "2024-01-15T10:30:00Z",
        "start_time": 1705318200,
        "end_time": 1705320000,
        "performance_metrics": None
    }

    workout = Workout.from_dict(workout_dict)

    assert workout.performance_metrics is None


@pytest.mark.unit
def test_workout_update_from_performance_data(sample_workout, mock_api_performance_response):
    """Test Workout.update_from_performance_data() method"""
    # Create workout without performance data
    workout = Workout(
        workout_id="workout_update",
        user_id="user123",
        ride_info=sample_workout.ride_info,
        created_at="2024-01-15T10:30:00Z",
        start_time=1705318200,
        end_time=1705320000
    )

    assert workout.performance_metrics is None
    assert workout.avg_output == 0.0

    # Update with performance data
    workout.update_from_performance_data(mock_api_performance_response)

    # Verify performance metrics updated
    assert workout.performance_metrics is not None
    assert workout.performance_metrics.output == [100.0, 150.0, 175.0, 160.0, 140.0]

    # Verify summary statistics updated
    assert workout.total_output == 250.5
    assert workout.avg_output == 150.0
    assert workout.avg_cadence == 85.0
    assert workout.avg_resistance == 45.0
    assert workout.avg_heart_rate == 135.0
    assert workout.max_heart_rate == 165.0
    assert workout.distance == 7.5
    assert workout.calories == 350.0


@pytest.mark.unit
def test_workout_update_from_performance_data_with_total_calories():
    """Test Workout.update_from_performance_data() handles total_calories slug"""
    performance_data = {
        "seconds_since_pedaling_start": [0, 5, 10],
        "metrics": [
            {"slug": "output", "values": [100.0, 150.0, 175.0]}
        ],
        "summaries": [
            {"slug": "total_output", "value": 300.0},
            {"slug": "total_calories", "value": 400.0}  # Instead of "calories"
        ],
        "average_summaries": []
    }

    workout = Workout(
        workout_id="cal_test",
        user_id="user123",
        ride_info=RideInfo(ride_id="ride1", title="Test"),
        created_at="2024-01-15T10:30:00Z",
        start_time=1705318200,
        end_time=1705320000
    )

    workout.update_from_performance_data(performance_data)

    assert workout.calories == 400.0


@pytest.mark.unit
def test_workout_from_api_response_distance_fallback():
    """Test Workout.from_api_response() distance fallback logic"""
    # Distance in workout data directly, not in summaries
    workout_data = {
        "id": "workout_dist",
        "user_id": "user123",
        "created_at": "2024-01-15T10:30:00Z",
        "start_time": 1705318200,
        "end_time": 1705320000,
        "total_distance": 10.5,  # Fallback location
        "ride": {
            "id": "ride123",
            "title": "Test Ride",
            "duration": 1800
        },
        "summaries": []  # No distance in summaries
    }

    workout = Workout.from_api_response(workout_data)

    assert workout.distance == 10.5


@pytest.mark.unit
def test_workout_from_api_response_with_missing_fields():
    """Test Workout.from_api_response() handles missing fields gracefully"""
    minimal_data = {
        "id": "workout_minimal",
        "user_id": "user456",
        "created_at": "2024-01-15T10:30:00Z",
        "start_time": 1705318200,
        "end_time": 1705320000,
        "ride": {
            "id": "ride_minimal"
        }
        # Missing: summaries, peloton, all metrics
    }

    workout = Workout.from_api_response(minimal_data)

    assert workout.workout_id == "workout_minimal"
    assert workout.user_id == "user456"
    assert workout.total_output == 0.0
    assert workout.avg_output == 0.0
    assert workout.distance == 0.0
    assert workout.calories == 0.0
    assert workout.performance_metrics is None


@pytest.mark.unit
def test_workout_from_dict_with_missing_optional_fields():
    """Test Workout.from_dict() handles missing optional fields"""
    minimal_dict = {
        "workout_id": "workout_dict_minimal",
        "user_id": "user789",
        "ride_info": {
            "ride_id": "ride_minimal",
            "title": "Minimal Ride",
            "instructor_name": "",
            "duration": 1800,
            "difficulty": 0.0,
            "ride_type": "cycling"
        },
        "created_at": "2024-01-15T10:30:00Z",
        "start_time": 1705318200,
        "end_time": 1705320000
        # Missing: all optional metric fields
    }

    workout = Workout.from_dict(minimal_dict)

    assert workout.workout_id == "workout_dict_minimal"
    assert workout.total_output == 0.0
    assert workout.avg_output == 0.0
    assert workout.calories == 0.0


@pytest.mark.unit
def test_workout_no_code_injection():
    """Test Workout doesn't execute injected code"""
    malicious_data = {
        "id": "__import__('os').system('echo pwned')",
        "user_id": "eval('malicious')",
        "created_at": "exec('hacked')",
        "start_time": 1705318200,
        "end_time": 1705320000,
        "ride": {
            "id": "${os.system('ls')}",
            "title": "Malicious Ride"
        },
        "summaries": []
    }

    workout = Workout.from_api_response(malicious_data)

    # Strings stored as-is, not evaluated
    assert workout.workout_id == "__import__('os').system('echo pwned')"
    assert workout.user_id == "eval('malicious')"
    assert workout.created_at == "exec('hacked')"


@pytest.mark.unit
def test_workout_numeric_bounds():
    """Test Workout handles invalid numeric values"""
    data_with_invalid_numbers = {
        "id": "bounds_workout",
        "user_id": "user123",
        "created_at": "2024-01-15T10:30:00Z",
        "start_time": -1,  # Negative timestamp
        "end_time": sys.maxsize,  # Very large timestamp
        "ride": {
            "id": "ride123",
            "title": "Test"
        },
        "summaries": [
            {"slug": "total_output", "value": -999.99},  # Negative output
            {"slug": "calories", "value": 999999999.99}  # Unrealistic calories
        ]
    }

    workout = Workout.from_api_response(data_with_invalid_numbers)

    # Model stores values as-is
    assert workout.start_time == -1
    assert workout.end_time == sys.maxsize
    assert workout.total_output == -999.99
    assert workout.calories == 999999999.99


# =============================================================================
# COMMONRIDE MODEL TESTS
# =============================================================================

@pytest.mark.unit
def test_common_ride_creation(sample_ride_info, sample_workout):
    """Test CommonRide dataclass creation"""
    user_workouts = {
        "user123": [sample_workout]
    }

    common_ride = CommonRide(
        ride_info=sample_ride_info,
        user_workouts=user_workouts
    )

    assert common_ride.ride_info == sample_ride_info
    assert len(common_ride.user_workouts) == 1
    assert "user123" in common_ride.user_workouts


@pytest.mark.unit
def test_common_ride_get_participant_count(sample_ride_info, sample_workout, sample_follower):
    """Test CommonRide.get_participant_count() method"""
    follower_workout = Workout(
        workout_id="follower_workout1",
        user_id="follower456",
        ride_info=sample_ride_info,
        created_at="2024-01-15T11:00:00Z",
        start_time=1705320000,
        end_time=1705321800
    )

    user_workouts = {
        "user123": [sample_workout],
        "follower456": [follower_workout]
    }

    common_ride = CommonRide(
        ride_info=sample_ride_info,
        user_workouts=user_workouts
    )

    assert common_ride.get_participant_count() == 2


@pytest.mark.unit
def test_common_ride_get_total_workout_count(sample_ride_info, sample_workout):
    """Test CommonRide.get_total_workout_count() with multiple attempts"""
    # User took same ride multiple times
    workout2 = Workout(
        workout_id="workout456",
        user_id="user123",
        ride_info=sample_ride_info,
        created_at="2024-01-20T10:30:00Z",
        start_time=1705741200,
        end_time=1705743000
    )

    follower_workout1 = Workout(
        workout_id="follower_w1",
        user_id="follower456",
        ride_info=sample_ride_info,
        created_at="2024-01-15T11:00:00Z",
        start_time=1705320000,
        end_time=1705321800
    )

    follower_workout2 = Workout(
        workout_id="follower_w2",
        user_id="follower456",
        ride_info=sample_ride_info,
        created_at="2024-01-16T11:00:00Z",
        start_time=1705406400,
        end_time=1705408200
    )

    user_workouts = {
        "user123": [sample_workout, workout2],  # 2 attempts
        "follower456": [follower_workout1, follower_workout2]  # 2 attempts
    }

    common_ride = CommonRide(
        ride_info=sample_ride_info,
        user_workouts=user_workouts
    )

    assert common_ride.get_total_workout_count() == 4


@pytest.mark.unit
def test_common_ride_get_participant_usernames(sample_ride_info, sample_workout):
    """Test CommonRide.get_participant_usernames() method"""
    follower_workout = Workout(
        workout_id="follower_w",
        user_id="follower456",
        ride_info=sample_ride_info,
        created_at="2024-01-15T11:00:00Z",
        start_time=1705320000,
        end_time=1705321800
    )

    user_workouts = {
        "user123": [sample_workout],
        "follower456": [follower_workout],
        "follower789": [follower_workout]
    }

    common_ride = CommonRide(
        ride_info=sample_ride_info,
        user_workouts=user_workouts
    )

    usernames = common_ride.get_participant_usernames()

    assert len(usernames) == 3
    assert "user123" in usernames
    assert "follower456" in usernames
    assert "follower789" in usernames


@pytest.mark.unit
def test_common_ride_to_dict(sample_ride_info, sample_workout):
    """Test CommonRide.to_dict() serialization"""
    user_workouts = {
        "user123": [sample_workout]
    }

    common_ride = CommonRide(
        ride_info=sample_ride_info,
        user_workouts=user_workouts
    )

    common_dict = common_ride.to_dict()

    assert isinstance(common_dict, dict)
    assert "ride_info" in common_dict
    assert "user_workouts" in common_dict
    assert common_dict["ride_info"]["ride_id"] == "ride123abc"
    assert "user123" in common_dict["user_workouts"]
    assert len(common_dict["user_workouts"]["user123"]) == 1


@pytest.mark.unit
def test_common_ride_with_empty_user_workouts(sample_ride_info):
    """Test CommonRide with empty user_workouts dict"""
    common_ride = CommonRide(
        ride_info=sample_ride_info,
        user_workouts={}
    )

    assert common_ride.get_participant_count() == 0
    assert common_ride.get_total_workout_count() == 0
    assert common_ride.get_participant_usernames() == []


# =============================================================================
# SECURITY & VALIDATION TESTS
# =============================================================================

@pytest.mark.unit
def test_models_reject_type_confusion_attacks():
    """Test models handle type confusion attacks (dict instead of string, etc.)"""
    # User with dict instead of string for user_id
    user = User(
        user_id={"malicious": "dict"},  # Type confusion
        username="test"
    )
    # Should store as-is (dataclass doesn't enforce types at runtime)
    assert isinstance(user.user_id, dict)


@pytest.mark.unit
def test_workout_from_dict_with_invalid_ride_info_type():
    """Test Workout.from_dict() raises error if ride_info is not a dict"""
    invalid_dict = {
        "workout_id": "workout_invalid",
        "user_id": "user123",
        "ride_info": "not_a_dict",  # Should be dict
        "created_at": "2024-01-15T10:30:00Z",
        "start_time": 1705318200,
        "end_time": 1705320000
    }

    with pytest.raises((TypeError, KeyError)):
        Workout.from_dict(invalid_dict)


@pytest.mark.unit
def test_workout_from_dict_with_missing_required_fields():
    """Test Workout.from_dict() raises error if required fields missing"""
    incomplete_dict = {
        "workout_id": "workout_incomplete",
        # Missing: user_id, ride_info, created_at, start_time, end_time
    }

    with pytest.raises(KeyError):
        Workout.from_dict(incomplete_dict)


@pytest.mark.unit
def test_performance_metrics_with_mismatched_list_lengths():
    """Test PerformanceMetrics allows mismatched list lengths (no validation)"""
    metrics = PerformanceMetrics(
        seconds_since_start=[0, 5, 10, 15, 20],  # 5 items
        output=[100.0, 150.0],  # 2 items - mismatched
        cadence=[80, 85, 90, 88, 82, 79, 81]  # 7 items - mismatched
    )

    # Model doesn't validate list lengths match
    assert len(metrics.seconds_since_start) == 5
    assert len(metrics.output) == 2
    assert len(metrics.cadence) == 7


@pytest.mark.unit
def test_user_from_api_response_with_integer_for_string_field():
    """Test User.from_api_response() handles type mismatches from API"""
    data_with_type_mismatches = {
        "id": 12345,  # Integer instead of string
        "username": 67890,  # Integer instead of string
        "name": True,  # Boolean instead of string
        "total_workouts": "not_a_number"  # String instead of int
    }

    user = User.from_api_response(data_with_type_mismatches)

    # Values stored as-is (no type coercion in from_api_response)
    assert user.user_id == 12345
    assert user.username == 67890
    assert user.display_name is True
    assert user.total_workouts == "not_a_number"


@pytest.mark.unit
def test_ride_info_with_extremely_nested_data():
    """Test RideInfo handles deeply nested API response structures"""
    deeply_nested = {
        "peloton": {
            "ride": {
                "id": "nested_ride",
                "title": "Nested Title",
                "instructor": {
                    "name": "Nested Instructor",
                    "nested": {
                        "deep": {
                            "very_deep": "value"
                        }
                    }
                }
            }
        }
    }

    ride_info = RideInfo.from_api_response(deeply_nested)

    assert ride_info.ride_id == "nested_ride"
    assert ride_info.instructor_name == "Nested Instructor"
    # Shouldn't crash on deep nesting


@pytest.mark.unit
def test_models_handle_unicode_and_special_characters():
    """Test models handle Unicode and special characters safely"""
    unicode_data = {
        "id": "user_unicode",
        "username": "用户名",  # Chinese characters
        "name": "Tëst Ûsér 🚴‍♂️",  # Accents and emoji
        "location": "São Paulo, Brasil 🇧🇷"
    }

    user = User.from_api_response(unicode_data)

    assert user.username == "用户名"
    assert "🚴‍♂️" in user.display_name
    assert "🇧🇷" in user.location


@pytest.mark.unit
def test_performance_metrics_with_infinity_and_nan():
    """Test PerformanceMetrics handles infinity and NaN values"""
    metrics_with_special_floats = {
        "seconds_since_pedaling_start": [0, 5, 10],
        "metrics": [
            {"slug": "output", "values": [100.0, float('inf'), float('-inf')]},
            {"slug": "cadence", "values": [80, float('nan'), 85]}
        ]
    }

    metrics = PerformanceMetrics.from_api_response(metrics_with_special_floats)

    # Should store special float values
    import math
    assert math.isinf(metrics.output[1])
    assert math.isinf(metrics.output[2])
    assert math.isnan(metrics.cadence[1])


@pytest.mark.unit
def test_workout_summaries_with_duplicate_slugs():
    """Test Workout handles duplicate slugs in summaries (uses last value)"""
    workout_data = {
        "id": "workout_dup",
        "user_id": "user123",
        "created_at": "2024-01-15T10:30:00Z",
        "start_time": 1705318200,
        "end_time": 1705320000,
        "ride": {
            "id": "ride123",
            "title": "Test"
        },
        "summaries": [
            {"slug": "total_output", "value": 100.0},
            {"slug": "total_output", "value": 200.0},  # Duplicate
            {"slug": "total_output", "value": 300.0}   # Duplicate again
        ]
    }

    workout = Workout.from_api_response(workout_data)

    # Dictionary comprehension uses last value for duplicate keys
    assert workout.total_output == 300.0


# =============================================================================
# API RESPONSE PARSING TESTS
# =============================================================================

@pytest.mark.unit
def test_user_from_api_response_complete(mock_api_user_response):
    """Test complete User parsing from realistic API response"""
    user = User.from_api_response(mock_api_user_response)

    assert user.user_id == "user123"
    assert user.username == "testuser"
    assert user.display_name == "Test User"
    assert user.image_url == "https://example.com/avatar.jpg"
    assert user.location == "San Francisco, CA"
    assert user.total_workouts == 100


@pytest.mark.unit
def test_workout_from_api_response_complete(mock_api_workout_response, mock_api_performance_response):
    """Test complete Workout parsing from realistic API responses"""
    workout = Workout.from_api_response(
        mock_api_workout_response,
        mock_api_performance_response
    )

    # Verify workout fields
    assert workout.workout_id == "workout123"
    assert workout.user_id == "user123"
    assert workout.created_at == "2024-01-15T10:30:00Z"
    assert workout.start_time == 1705318200
    assert workout.end_time == 1705320000

    # Verify ride info
    assert workout.ride_info.ride_id == "ride123abc"
    assert workout.ride_info.title == "30 min HIIT Ride"
    assert workout.ride_info.instructor_name == "Robin Arzon"
    assert workout.ride_info.duration == 1800
    assert workout.ride_info.difficulty == 7.5

    # Verify summary metrics
    assert workout.total_output == 250.5
    assert workout.calories == 350.0
    assert workout.distance == 7.5

    # Verify performance metrics
    assert workout.performance_metrics is not None
    assert len(workout.performance_metrics.seconds_since_start) == 5
    assert workout.performance_metrics.output == [100.0, 150.0, 175.0, 160.0, 140.0]


@pytest.mark.unit
def test_performance_metrics_from_api_response_all_metric_types(mock_api_performance_response):
    """Test PerformanceMetrics parses all metric types correctly"""
    metrics = PerformanceMetrics.from_api_response(mock_api_performance_response)

    # Verify all metric arrays parsed
    assert metrics.seconds_since_start == [0, 5, 10, 15, 20]
    assert metrics.output == [100.0, 150.0, 175.0, 160.0, 140.0]
    assert metrics.cadence == [80, 85, 90, 88, 82]
    assert metrics.resistance == [40, 45, 50, 48, 42]
    assert metrics.heart_rate == [120, 135, 145, 140, 130]

    # Speed and distance not in mock, should be empty
    assert metrics.speed == []
    assert metrics.distance == []
