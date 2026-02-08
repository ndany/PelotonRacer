"""
Comprehensive tests for Race Analyzer service

Tests cover:
1. Standard functionality (common ride detection, DataFrame generation, rankings)
2. Input validation and security (malformed data, DoS prevention, injection protection)
3. Edge cases (empty data, single user, missing metrics)

All tests use @pytest.mark.unit marker and shared fixtures from conftest.py
"""

import pytest
import pandas as pd
from typing import List, Dict
from src.services.race_analyzer import RaceAnalyzer
from src.models.models import Workout, RideInfo, PerformanceMetrics, CommonRide, User


# =============================================================================
# STANDARD FUNCTIONALITY TESTS
# =============================================================================

@pytest.mark.unit
def test_find_common_rides_with_matches(sample_ride_info):
    """Test find_common_rides() when user and followers have matching rides"""
    # Create user workouts
    user_workouts = [
        Workout(
            workout_id="user_w1",
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
        )
    ]

    # Create follower workouts with the SAME ride
    follower_workouts = {
        "follower456": [
            Workout(
                workout_id="follower_w1",
                user_id="follower456",
                ride_info=sample_ride_info,
                created_at="2024-01-16T10:30:00Z",
                start_time=1705404600,
                end_time=1705406400,
                total_output=275.0,
                avg_output=165.0,
                avg_cadence=90.0,
                avg_resistance=48.0,
                distance=8.0,
                calories=380.0
            )
        ]
    }

    common_rides = RaceAnalyzer.find_common_rides(user_workouts, follower_workouts, "user123")

    assert len(common_rides) == 1
    assert common_rides[0].get_participant_count() == 2  # user + 1 follower
    assert common_rides[0].ride_info.ride_id == sample_ride_info.ride_id
    assert "user123" in common_rides[0].user_workouts
    assert "follower456" in common_rides[0].user_workouts


@pytest.mark.unit
def test_find_common_rides_no_matches(sample_ride_info):
    """Test find_common_rides() when there are no matching rides"""
    # Create different ride info for follower
    different_ride = RideInfo(
        ride_id="different_ride_123",
        title="45 min Endurance Ride",
        instructor_name="Matt Wilpers",
        duration=2700,
        difficulty=6.5,
        ride_type="cycling"
    )

    user_workouts = [
        Workout(
            workout_id="user_w1",
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
        )
    ]

    follower_workouts = {
        "follower456": [
            Workout(
                workout_id="follower_w1",
                user_id="follower456",
                ride_info=different_ride,
                created_at="2024-01-16T10:30:00Z",
                start_time=1705404600,
                end_time=1705406400,
                total_output=275.0,
                avg_output=165.0,
                avg_cadence=90.0,
                avg_resistance=48.0,
                distance=8.0,
                calories=380.0
            )
        ]
    }

    common_rides = RaceAnalyzer.find_common_rides(user_workouts, follower_workouts, "user123")

    assert len(common_rides) == 0


@pytest.mark.unit
def test_find_common_rides_multiple_followers_same_ride(sample_ride_info):
    """Test find_common_rides() with multiple followers taking the same ride"""
    user_workouts = [
        Workout(
            workout_id="user_w1",
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
        )
    ]

    follower_workouts = {
        "follower456": [
            Workout(
                workout_id="follower1_w1",
                user_id="follower456",
                ride_info=sample_ride_info,
                created_at="2024-01-16T10:30:00Z",
                start_time=1705404600,
                end_time=1705406400,
                total_output=275.0,
                avg_output=165.0,
                avg_cadence=90.0,
                avg_resistance=48.0,
                distance=8.0,
                calories=380.0
            )
        ],
        "follower789": [
            Workout(
                workout_id="follower2_w1",
                user_id="follower789",
                ride_info=sample_ride_info,
                created_at="2024-01-17T10:30:00Z",
                start_time=1705491000,
                end_time=1705492800,
                total_output=260.0,
                avg_output=155.0,
                avg_cadence=87.0,
                avg_resistance=46.0,
                distance=7.8,
                calories=365.0
            )
        ]
    }

    common_rides = RaceAnalyzer.find_common_rides(user_workouts, follower_workouts, "user123")

    assert len(common_rides) == 1
    assert common_rides[0].get_participant_count() == 3  # user + 2 followers
    assert "user123" in common_rides[0].user_workouts
    assert "follower456" in common_rides[0].user_workouts
    assert "follower789" in common_rides[0].user_workouts


@pytest.mark.unit
def test_find_common_rides_multiple_attempts_per_user(sample_ride_info):
    """Test find_common_rides() when users take the same ride multiple times"""
    # User takes the ride twice
    user_workouts = [
        Workout(
            workout_id="user_w1",
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
            workout_id="user_w2",
            user_id="user123",
            ride_info=sample_ride_info,
            created_at="2024-01-20T10:30:00Z",
            start_time=1705750200,
            end_time=1705752000,
            total_output=280.0,
            avg_output=168.0,
            avg_cadence=92.0,
            avg_resistance=50.0,
            distance=8.2,
            calories=390.0
        )
    ]

    # Follower also takes it twice
    follower_workouts = {
        "follower456": [
            Workout(
                workout_id="follower_w1",
                user_id="follower456",
                ride_info=sample_ride_info,
                created_at="2024-01-16T10:30:00Z",
                start_time=1705404600,
                end_time=1705406400,
                total_output=275.0,
                avg_output=165.0,
                avg_cadence=90.0,
                avg_resistance=48.0,
                distance=8.0,
                calories=380.0
            ),
            Workout(
                workout_id="follower_w2",
                user_id="follower456",
                ride_info=sample_ride_info,
                created_at="2024-01-21T10:30:00Z",
                start_time=1705836600,
                end_time=1705838400,
                total_output=290.0,
                avg_output=174.0,
                avg_cadence=95.0,
                avg_resistance=52.0,
                distance=8.5,
                calories=400.0
            )
        ]
    }

    common_rides = RaceAnalyzer.find_common_rides(user_workouts, follower_workouts, "user123")

    assert len(common_rides) == 1
    assert common_rides[0].get_total_workout_count() == 4  # 2 user + 2 follower
    assert len(common_rides[0].user_workouts["user123"]) == 2
    assert len(common_rides[0].user_workouts["follower456"]) == 2


@pytest.mark.unit
def test_create_comparison_dataframe(sample_workouts):
    """Test create_comparison_dataframe() generates proper DataFrame structure"""
    users = {
        "user123": User(user_id="user123", username="testuser", display_name="Test User"),
        "user456": User(user_id="user456", username="otheruser", display_name="Other User")
    }

    df = RaceAnalyzer.create_comparison_dataframe(sample_workouts, users)

    assert isinstance(df, pd.DataFrame)
    assert len(df) == 2
    assert "#" in df.columns
    assert "User" in df.columns
    assert "Date" in df.columns
    assert "Total Output (kJ)" in df.columns
    assert "Avg Output (W)" in df.columns
    assert "Avg Cadence (RPM)" in df.columns
    assert "Avg Resistance (%)" in df.columns
    assert "Distance (mi)" in df.columns
    assert "Calories" in df.columns

    # Check data values
    assert df.iloc[0]["Total Output (kJ)"] == 250.5
    assert df.iloc[1]["Total Output (kJ)"] == 275.0


@pytest.mark.unit
def test_create_comparison_dataframe_with_custom_labels(sample_workouts):
    """Test create_comparison_dataframe() with custom labels instead of usernames"""
    users = {
        "user123": User(user_id="user123", username="testuser", display_name="Test User")
    }

    labels = {
        "workout1": "Attempt 1",
        "workout2": "Attempt 2"
    }

    df = RaceAnalyzer.create_comparison_dataframe(sample_workouts, users, labels)

    assert df.iloc[0]["User"] == "Attempt 1"
    assert df.iloc[1]["User"] == "Attempt 2"


@pytest.mark.unit
def test_create_time_series_dataframe(sample_performance_metrics):
    """Test create_time_series_dataframe() generates proper time series data"""
    workout = Workout(
        workout_id="workout1",
        user_id="user123",
        ride_info=RideInfo(
            ride_id="ride123",
            title="Test Ride",
            instructor_name="Test Instructor",
            duration=1800,
            difficulty=7.5,
            ride_type="cycling"
        ),
        created_at="2024-01-15T10:30:00Z",
        start_time=1705318200,
        end_time=1705320000,
        total_output=250.5,
        avg_output=150.0,
        avg_cadence=85.0,
        avg_resistance=45.0,
        distance=7.5,
        calories=350.0,
        performance_metrics=sample_performance_metrics
    )

    users = {
        "user123": User(user_id="user123", username="testuser", display_name="Test User")
    }

    df = RaceAnalyzer.create_time_series_dataframe([workout], users, "output")

    assert isinstance(df, pd.DataFrame)
    assert "User" in df.columns
    assert "Time (seconds)" in df.columns
    assert "Value" in df.columns
    assert len(df) == 5  # 5 data points in sample metrics
    assert df.iloc[0]["Value"] == 100.0
    assert df.iloc[1]["Value"] == 150.0


@pytest.mark.unit
def test_calculate_rankings(sample_workouts):
    """Test calculate_rankings() returns proper sorted rankings"""
    rankings = RaceAnalyzer.calculate_rankings(sample_workouts, metric="total_output")

    assert isinstance(rankings, list)
    assert len(rankings) == 2
    assert rankings[0][0] == "user123"  # user_id
    assert rankings[0][1] == 275.0  # Higher output is first
    assert rankings[1][1] == 250.5


@pytest.mark.unit
def test_calculate_rankings_with_labels(sample_workouts):
    """Test calculate_rankings() with custom labels"""
    labels = {
        "workout1": "First Attempt",
        "workout2": "Second Attempt"
    }

    rankings = RaceAnalyzer.calculate_rankings(sample_workouts, metric="total_output", labels=labels)

    assert rankings[0][0] == "Second Attempt"
    assert rankings[1][0] == "First Attempt"


@pytest.mark.unit
def test_get_metric_stats(sample_workouts):
    """Test get_metric_stats() calculates statistics correctly"""
    stats = RaceAnalyzer.get_metric_stats(sample_workouts)

    assert isinstance(stats, dict)
    assert "total_output" in stats
    assert "avg_output" in stats
    assert "avg_cadence" in stats

    # Check total_output stats
    assert stats["total_output"]["min"] == 250.5
    assert stats["total_output"]["max"] == 275.0
    assert stats["total_output"]["avg"] == 262.75
    assert stats["total_output"]["range"] == 24.5


# =============================================================================
# EDGE CASE TESTS
# =============================================================================

@pytest.mark.unit
def test_find_common_rides_empty_user_workouts():
    """Test find_common_rides() with empty user workouts"""
    user_workouts = []
    follower_workouts = {
        "follower456": [
            Workout(
                workout_id="follower_w1",
                user_id="follower456",
                ride_info=RideInfo(
                    ride_id="ride123",
                    title="Test Ride",
                    instructor_name="Test Instructor",
                    duration=1800,
                    difficulty=7.5,
                    ride_type="cycling"
                ),
                created_at="2024-01-16T10:30:00Z",
                start_time=1705404600,
                end_time=1705406400,
                total_output=275.0,
                avg_output=165.0,
                avg_cadence=90.0,
                avg_resistance=48.0,
                distance=8.0,
                calories=380.0
            )
        ]
    }

    common_rides = RaceAnalyzer.find_common_rides(user_workouts, follower_workouts, "user123")

    assert len(common_rides) == 0


@pytest.mark.unit
def test_find_common_rides_empty_follower_workouts():
    """Test find_common_rides() with empty follower workouts"""
    user_workouts = [
        Workout(
            workout_id="user_w1",
            user_id="user123",
            ride_info=RideInfo(
                ride_id="ride123",
                title="Test Ride",
                instructor_name="Test Instructor",
                duration=1800,
                difficulty=7.5,
                ride_type="cycling"
            ),
            created_at="2024-01-15T10:30:00Z",
            start_time=1705318200,
            end_time=1705320000,
            total_output=250.5,
            avg_output=150.0,
            avg_cadence=85.0,
            avg_resistance=45.0,
            distance=7.5,
            calories=350.0
        )
    ]

    follower_workouts = {}

    common_rides = RaceAnalyzer.find_common_rides(user_workouts, follower_workouts, "user123")

    assert len(common_rides) == 0


@pytest.mark.unit
def test_create_comparison_dataframe_single_workout():
    """Test create_comparison_dataframe() with a single workout"""
    workout = Workout(
        workout_id="workout1",
        user_id="user123",
        ride_info=RideInfo(
            ride_id="ride123",
            title="Test Ride",
            instructor_name="Test Instructor",
            duration=1800,
            difficulty=7.5,
            ride_type="cycling"
        ),
        created_at="2024-01-15T10:30:00Z",
        start_time=1705318200,
        end_time=1705320000,
        total_output=250.5,
        avg_output=150.0,
        avg_cadence=85.0,
        avg_resistance=45.0,
        distance=7.5,
        calories=350.0
    )

    users = {
        "user123": User(user_id="user123", username="testuser", display_name="Test User")
    }

    df = RaceAnalyzer.create_comparison_dataframe([workout], users)

    assert len(df) == 1
    assert df.iloc[0]["User"] == "testuser"


@pytest.mark.unit
def test_create_time_series_dataframe_no_performance_metrics():
    """Test create_time_series_dataframe() with workouts lacking performance metrics"""
    workout = Workout(
        workout_id="workout1",
        user_id="user123",
        ride_info=RideInfo(
            ride_id="ride123",
            title="Test Ride",
            instructor_name="Test Instructor",
            duration=1800,
            difficulty=7.5,
            ride_type="cycling"
        ),
        created_at="2024-01-15T10:30:00Z",
        start_time=1705318200,
        end_time=1705320000,
        total_output=250.5,
        avg_output=150.0,
        avg_cadence=85.0,
        avg_resistance=45.0,
        distance=7.5,
        calories=350.0,
        performance_metrics=None
    )

    users = {
        "user123": User(user_id="user123", username="testuser", display_name="Test User")
    }

    df = RaceAnalyzer.create_time_series_dataframe([workout], users, "output")

    # Should return empty DataFrame when no performance metrics
    assert len(df) == 0


@pytest.mark.unit
def test_get_metric_stats_empty_workouts():
    """Test get_metric_stats() with empty workout list"""
    stats = RaceAnalyzer.get_metric_stats([])

    assert isinstance(stats, dict)
    assert len(stats) == 0


@pytest.mark.unit
def test_find_repeated_rides_single_attempt():
    """Test find_repeated_rides() when user has only taken each ride once"""
    ride1 = RideInfo(
        ride_id="ride123",
        title="Test Ride 1",
        instructor_name="Test Instructor",
        duration=1800,
        difficulty=7.5,
        ride_type="cycling"
    )

    ride2 = RideInfo(
        ride_id="ride456",
        title="Test Ride 2",
        instructor_name="Test Instructor",
        duration=1800,
        difficulty=7.5,
        ride_type="cycling"
    )

    user_workouts = [
        Workout(
            workout_id="w1",
            user_id="user123",
            ride_info=ride1,
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
            workout_id="w2",
            user_id="user123",
            ride_info=ride2,
            created_at="2024-01-16T10:30:00Z",
            start_time=1705404600,
            end_time=1705406400,
            total_output=275.0,
            avg_output=165.0,
            avg_cadence=90.0,
            avg_resistance=48.0,
            distance=8.0,
            calories=380.0
        )
    ]

    repeated_rides = RaceAnalyzer.find_repeated_rides(user_workouts, "user123")

    assert len(repeated_rides) == 0


@pytest.mark.unit
def test_find_repeated_rides_multiple_attempts():
    """Test find_repeated_rides() when user has taken a ride multiple times"""
    ride_info = RideInfo(
        ride_id="ride123",
        title="Test Ride",
        instructor_name="Test Instructor",
        duration=1800,
        difficulty=7.5,
        ride_type="cycling"
    )

    user_workouts = [
        Workout(
            workout_id="w1",
            user_id="user123",
            ride_info=ride_info,
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
            workout_id="w2",
            user_id="user123",
            ride_info=ride_info,
            created_at="2024-01-20T10:30:00Z",
            start_time=1705750200,
            end_time=1705752000,
            total_output=280.0,
            avg_output=168.0,
            avg_cadence=92.0,
            avg_resistance=50.0,
            distance=8.2,
            calories=390.0
        ),
        Workout(
            workout_id="w3",
            user_id="user123",
            ride_info=ride_info,
            created_at="2024-01-25T10:30:00Z",
            start_time=1706182200,
            end_time=1706184000,
            total_output=300.0,
            avg_output=180.0,
            avg_cadence=95.0,
            avg_resistance=52.0,
            distance=8.5,
            calories=410.0
        )
    ]

    repeated_rides = RaceAnalyzer.find_repeated_rides(user_workouts, "user123")

    assert len(repeated_rides) == 1
    assert repeated_rides[0].ride_info.ride_id == "ride123"
    assert len(repeated_rides[0].user_workouts["user123"]) == 3


# =============================================================================
# INPUT VALIDATION & SECURITY TESTS
# =============================================================================

@pytest.mark.unit
def test_find_common_rides_invalid_ride_info(invalid_ride_info):
    """Test find_common_rides() filters out invalid rides (no instructor)"""
    user_workouts = [
        Workout(
            workout_id="user_w1",
            user_id="user123",
            ride_info=invalid_ride_info,
            created_at="2024-01-15T10:30:00Z",
            start_time=1705318200,
            end_time=1705320000,
            total_output=250.5,
            avg_output=150.0,
            avg_cadence=85.0,
            avg_resistance=45.0,
            distance=7.5,
            calories=350.0
        )
    ]

    follower_workouts = {
        "follower456": [
            Workout(
                workout_id="follower_w1",
                user_id="follower456",
                ride_info=invalid_ride_info,
                created_at="2024-01-16T10:30:00Z",
                start_time=1705404600,
                end_time=1705406400,
                total_output=275.0,
                avg_output=165.0,
                avg_cadence=90.0,
                avg_resistance=48.0,
                distance=8.0,
                calories=380.0
            )
        ]
    }

    common_rides = RaceAnalyzer.find_common_rides(user_workouts, follower_workouts, "user123")

    # Should be empty because invalid rides are filtered out
    assert len(common_rides) == 0


@pytest.mark.unit
def test_create_comparison_dataframe_missing_user():
    """Test create_comparison_dataframe() handles missing user in users dict"""
    workout = Workout(
        workout_id="workout1",
        user_id="unknown_user",
        ride_info=RideInfo(
            ride_id="ride123",
            title="Test Ride",
            instructor_name="Test Instructor",
            duration=1800,
            difficulty=7.5,
            ride_type="cycling"
        ),
        created_at="2024-01-15T10:30:00Z",
        start_time=1705318200,
        end_time=1705320000,
        total_output=250.5,
        avg_output=150.0,
        avg_cadence=85.0,
        avg_resistance=45.0,
        distance=7.5,
        calories=350.0
    )

    users = {}  # Empty users dict

    df = RaceAnalyzer.create_comparison_dataframe([workout], users)

    # Should fall back to user_id when user not found
    assert df.iloc[0]["User"] == "unknown_user"


@pytest.mark.unit
def test_create_comparison_dataframe_none_values():
    """Test create_comparison_dataframe() handles None/missing metric values"""
    workout = Workout(
        workout_id="workout1",
        user_id="user123",
        ride_info=RideInfo(
            ride_id="ride123",
            title="Test Ride",
            instructor_name="Test Instructor",
            duration=1800,
            difficulty=7.5,
            ride_type="cycling"
        ),
        created_at="2024-01-15T10:30:00Z",
        start_time=1705318200,
        end_time=1705320000,
        total_output=None,
        avg_output=None,
        avg_cadence=None,
        avg_resistance=None,
        avg_heart_rate=None,
        max_heart_rate=None,
        distance=None,
        calories=None
    )

    users = {
        "user123": User(user_id="user123", username="testuser", display_name="Test User")
    }

    df = RaceAnalyzer.create_comparison_dataframe([workout], users)

    # Should handle None values gracefully
    assert df.iloc[0]["Total Output (kJ)"] == 0
    assert df.iloc[0]["Avg Output (W)"] == 0
    assert df.iloc[0]["Avg HR (BPM)"] == "N/A"
    assert df.iloc[0]["Max HR (BPM)"] == "N/A"


@pytest.mark.unit
def test_create_comparison_dataframe_zero_start_time():
    """Test create_comparison_dataframe() handles zero/invalid timestamps"""
    workout = Workout(
        workout_id="workout1",
        user_id="user123",
        ride_info=RideInfo(
            ride_id="ride123",
            title="Test Ride",
            instructor_name="Test Instructor",
            duration=1800,
            difficulty=7.5,
            ride_type="cycling"
        ),
        created_at="2024-01-15T10:30:00Z",
        start_time=0,  # Invalid timestamp
        end_time=0,
        total_output=250.5,
        avg_output=150.0,
        avg_cadence=85.0,
        avg_resistance=45.0,
        distance=7.5,
        calories=350.0
    )

    users = {
        "user123": User(user_id="user123", username="testuser", display_name="Test User")
    }

    df = RaceAnalyzer.create_comparison_dataframe([workout], users)

    # Should handle zero timestamp gracefully
    assert df.iloc[0]["Date"] == "N/A"


@pytest.mark.unit
def test_calculate_rankings_invalid_metric():
    """Test calculate_rankings() with non-existent metric attribute"""
    workout = Workout(
        workout_id="workout1",
        user_id="user123",
        ride_info=RideInfo(
            ride_id="ride123",
            title="Test Ride",
            instructor_name="Test Instructor",
            duration=1800,
            difficulty=7.5,
            ride_type="cycling"
        ),
        created_at="2024-01-15T10:30:00Z",
        start_time=1705318200,
        end_time=1705320000,
        total_output=250.5,
        avg_output=150.0,
        avg_cadence=85.0,
        avg_resistance=45.0,
        distance=7.5,
        calories=350.0
    )

    # Use a metric that doesn't exist on the Workout object
    rankings = RaceAnalyzer.calculate_rankings([workout], metric="nonexistent_metric")

    # Should return 0 for non-existent attributes (getattr default)
    assert rankings[0][1] == 0


@pytest.mark.unit
def test_create_time_series_dataframe_mismatched_array_lengths():
    """Test create_time_series_dataframe() with mismatched metric array lengths"""
    # Performance metrics with mismatched lengths (security issue: malformed data)
    metrics = PerformanceMetrics(
        seconds_since_start=[0, 5, 10, 15, 20],
        output=[100.0, 150.0, 175.0],  # Only 3 values instead of 5
        cadence=[80, 85, 90, 88, 82],
        resistance=[40, 45, 50, 48, 42],
        heart_rate=[120, 135, 145, 140, 130],
        speed=[15.5, 16.2, 17.0, 16.8, 16.0],
        distance=[0.0, 0.1, 0.2, 0.3, 0.4]
    )

    workout = Workout(
        workout_id="workout1",
        user_id="user123",
        ride_info=RideInfo(
            ride_id="ride123",
            title="Test Ride",
            instructor_name="Test Instructor",
            duration=1800,
            difficulty=7.5,
            ride_type="cycling"
        ),
        created_at="2024-01-15T10:30:00Z",
        start_time=1705318200,
        end_time=1705320000,
        total_output=250.5,
        avg_output=150.0,
        avg_cadence=85.0,
        avg_resistance=45.0,
        distance=7.5,
        calories=350.0,
        performance_metrics=metrics
    )

    users = {
        "user123": User(user_id="user123", username="testuser", display_name="Test User")
    }

    df = RaceAnalyzer.create_time_series_dataframe([workout], users, "output")

    # Should handle mismatched lengths gracefully
    assert len(df) == 5  # Should process all seconds_since_start entries
    assert pd.isna(df.iloc[3]["Value"])  # Missing values should be NaN
    assert pd.isna(df.iloc[4]["Value"])


@pytest.mark.unit
def test_create_time_series_dataframe_invalid_metric_name():
    """Test create_time_series_dataframe() with invalid metric name"""
    workout = Workout(
        workout_id="workout1",
        user_id="user123",
        ride_info=RideInfo(
            ride_id="ride123",
            title="Test Ride",
            instructor_name="Test Instructor",
            duration=1800,
            difficulty=7.5,
            ride_type="cycling"
        ),
        created_at="2024-01-15T10:30:00Z",
        start_time=1705318200,
        end_time=1705320000,
        total_output=250.5,
        avg_output=150.0,
        avg_cadence=85.0,
        avg_resistance=45.0,
        distance=7.5,
        calories=350.0,
        performance_metrics=PerformanceMetrics(
            seconds_since_start=[0, 5, 10],
            output=[100.0, 150.0, 175.0],
            cadence=[80, 85, 90],
            resistance=[40, 45, 50],
            heart_rate=[120, 135, 145],
            speed=[15.5, 16.2, 17.0],
            distance=[0.0, 0.1, 0.2]
        )
    )

    users = {
        "user123": User(user_id="user123", username="testuser", display_name="Test User")
    }

    # Use an invalid metric name
    df = RaceAnalyzer.create_time_series_dataframe([workout], users, "invalid_metric")

    # Should handle gracefully, values will be empty list (getattr returns [])
    assert len(df) == 3
    assert all(df["Value"].isna())


@pytest.mark.unit
@pytest.mark.slow
def test_find_common_rides_large_dataset():
    """Test find_common_rides() with large dataset (DoS prevention)"""
    # Create a large number of workouts to test performance
    ride_info = RideInfo(
        ride_id="ride123",
        title="Test Ride",
        instructor_name="Test Instructor",
        duration=1800,
        difficulty=7.5,
        ride_type="cycling"
    )

    # Generate 1000 user workouts
    user_workouts = [
        Workout(
            workout_id=f"user_w{i}",
            user_id="user123",
            ride_info=ride_info,
            created_at="2024-01-15T10:30:00Z",
            start_time=1705318200 + i * 1000,
            end_time=1705320000 + i * 1000,
            total_output=250.5,
            avg_output=150.0,
            avg_cadence=85.0,
            avg_resistance=45.0,
            distance=7.5,
            calories=350.0
        )
        for i in range(1000)
    ]

    # Generate 100 followers with 10 workouts each
    follower_workouts = {}
    for follower_num in range(100):
        follower_id = f"follower{follower_num}"
        follower_workouts[follower_id] = [
            Workout(
                workout_id=f"follower{follower_num}_w{i}",
                user_id=follower_id,
                ride_info=ride_info,
                created_at="2024-01-16T10:30:00Z",
                start_time=1705404600 + i * 1000,
                end_time=1705406400 + i * 1000,
                total_output=275.0,
                avg_output=165.0,
                avg_cadence=90.0,
                avg_resistance=48.0,
                distance=8.0,
                calories=380.0
            )
            for i in range(10)
        ]

    # Should complete without hanging or excessive memory usage
    import time
    start = time.time()
    common_rides = RaceAnalyzer.find_common_rides(user_workouts, follower_workouts, "user123")
    elapsed = time.time() - start

    # Should find the common ride
    assert len(common_rides) == 1
    assert common_rides[0].get_participant_count() == 101  # user + 100 followers

    # Should complete in reasonable time (< 5 seconds)
    assert elapsed < 5.0


@pytest.mark.unit
def test_find_common_rides_special_characters_in_ids():
    """Test find_common_rides() with special characters in IDs (injection prevention)"""
    ride_info = RideInfo(
        ride_id="ride123",
        title="Test Ride",
        instructor_name="Test Instructor",
        duration=1800,
        difficulty=7.5,
        ride_type="cycling"
    )

    # User ID with special characters that might cause SQL/DataFrame injection
    special_user_id = "user'; DROP TABLE users; --"
    special_follower_id = "<script>alert('xss')</script>"

    user_workouts = [
        Workout(
            workout_id="user_w1",
            user_id=special_user_id,
            ride_info=ride_info,
            created_at="2024-01-15T10:30:00Z",
            start_time=1705318200,
            end_time=1705320000,
            total_output=250.5,
            avg_output=150.0,
            avg_cadence=85.0,
            avg_resistance=45.0,
            distance=7.5,
            calories=350.0
        )
    ]

    follower_workouts = {
        special_follower_id: [
            Workout(
                workout_id="follower_w1",
                user_id=special_follower_id,
                ride_info=ride_info,
                created_at="2024-01-16T10:30:00Z",
                start_time=1705404600,
                end_time=1705406400,
                total_output=275.0,
                avg_output=165.0,
                avg_cadence=90.0,
                avg_resistance=48.0,
                distance=8.0,
                calories=380.0
            )
        ]
    }

    # Should handle special characters without errors or injection
    common_rides = RaceAnalyzer.find_common_rides(user_workouts, follower_workouts, special_user_id)

    assert len(common_rides) == 1
    assert special_user_id in common_rides[0].user_workouts
    assert special_follower_id in common_rides[0].user_workouts


@pytest.mark.unit
def test_create_comparison_dataframe_special_characters_in_labels():
    """Test create_comparison_dataframe() with special characters in labels (XSS prevention)"""
    workout = Workout(
        workout_id="workout1",
        user_id="user123",
        ride_info=RideInfo(
            ride_id="ride123",
            title="Test Ride",
            instructor_name="Test Instructor",
            duration=1800,
            difficulty=7.5,
            ride_type="cycling"
        ),
        created_at="2024-01-15T10:30:00Z",
        start_time=1705318200,
        end_time=1705320000,
        total_output=250.5,
        avg_output=150.0,
        avg_cadence=85.0,
        avg_resistance=45.0,
        distance=7.5,
        calories=350.0
    )

    users = {
        "user123": User(
            user_id="user123",
            username="<script>alert('xss')</script>",
            display_name="Test User"
        )
    }

    # DataFrame should handle special characters without execution
    df = RaceAnalyzer.create_comparison_dataframe([workout], users)

    assert df.iloc[0]["User"] == "<script>alert('xss')</script>"


@pytest.mark.unit
def test_get_metric_stats_with_zero_values():
    """Test get_metric_stats() correctly excludes zero values from statistics"""
    workouts = [
        Workout(
            workout_id="w1",
            user_id="user123",
            ride_info=RideInfo(
                ride_id="ride123",
                title="Test Ride",
                instructor_name="Test Instructor",
                duration=1800,
                difficulty=7.5,
                ride_type="cycling"
            ),
            created_at="2024-01-15T10:30:00Z",
            start_time=1705318200,
            end_time=1705320000,
            total_output=250.5,
            avg_output=150.0,
            avg_cadence=85.0,
            avg_resistance=45.0,
            avg_heart_rate=0,  # Zero value (no HR monitor)
            distance=7.5,
            calories=350.0
        ),
        Workout(
            workout_id="w2",
            user_id="user123",
            ride_info=RideInfo(
                ride_id="ride123",
                title="Test Ride",
                instructor_name="Test Instructor",
                duration=1800,
                difficulty=7.5,
                ride_type="cycling"
            ),
            created_at="2024-01-20T10:30:00Z",
            start_time=1705750200,
            end_time=1705752000,
            total_output=280.0,
            avg_output=168.0,
            avg_cadence=92.0,
            avg_resistance=50.0,
            avg_heart_rate=140.0,
            distance=8.2,
            calories=390.0
        )
    ]

    stats = RaceAnalyzer.get_metric_stats(workouts)

    # avg_heart_rate should only include non-zero values
    assert "avg_heart_rate" in stats
    assert stats["avg_heart_rate"]["min"] == 140.0
    assert stats["avg_heart_rate"]["max"] == 140.0
    assert stats["avg_heart_rate"]["avg"] == 140.0
