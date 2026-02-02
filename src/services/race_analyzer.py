"""
Race Analyzer - Analyzes and compares ride statistics
"""

from typing import Dict, List, Tuple
from collections import defaultdict
from src.models.models import Workout, CommonRide, RideInfo, User
from src.services.data_manager import DataManager
import pandas as pd


class RaceAnalyzer:
    """Analyzes and compares workout data for virtual races"""
    
    @staticmethod
    def find_repeated_rides(user_workouts: List[Workout], user_id: str) -> List[CommonRide]:
        """
        Find rides that the user has taken multiple times.
        
        Args:
            user_workouts: List of user's workouts
            user_id: Current user's ID
            
        Returns:
            List of CommonRide objects for rides taken 2+ times
        """
        # Create a map of ride_id to list of workouts
        ride_map: Dict[str, List[Workout]] = defaultdict(list)
        
        # Add user's workouts (only valid rides)
        for workout in user_workouts:
            if DataManager.is_valid_ride(workout.ride_info):
                ride_id = workout.ride_info.ride_id
                ride_map[ride_id].append(workout)
        
        # Create CommonRide objects for rides taken multiple times
        repeated_rides = []
        for ride_id, workouts in ride_map.items():
            if len(workouts) >= 2:  # At least 2 attempts
                # Get ride info from first workout
                ride_info = workouts[0].ride_info
                # Create user_workouts dict with just the current user
                user_workout_map = {user_id: workouts}
                common_ride = CommonRide(
                    ride_info=ride_info,
                    user_workouts=user_workout_map
                )
                repeated_rides.append(common_ride)
        
        # Sort by attempt count (descending), then by most recent date
        def get_latest_date(ride):
            timestamps = [w.start_time for w in ride.user_workouts.get(user_id, [])]
            return max(timestamps) if timestamps else 0
        
        repeated_rides.sort(key=lambda r: (len(r.user_workouts.get(user_id, [])), get_latest_date(r)), reverse=True)
        
        return repeated_rides
    
    @staticmethod
    def find_common_rides(user_workouts: List[Workout], 
                         follower_workouts: Dict[str, List[Workout]],
                         user_id: str) -> List[CommonRide]:
        """
        Find rides that the user and their followers have in common.
        Supports multiple attempts per user per ride.
        
        Args:
            user_workouts: List of user's workouts
            follower_workouts: Dict mapping follower user_id to their workouts
            user_id: Current user's ID
            
        Returns:
            List of CommonRide objects
        """
        # Create a map of ride_id to user_id to list of workouts
        # ride_map[ride_id][user_id] = [workout1, workout2, ...]
        ride_map: Dict[str, Dict[str, List[Workout]]] = defaultdict(lambda: defaultdict(list))
        
        # Add user's workouts (only valid rides)
        for workout in user_workouts:
            if DataManager.is_valid_ride(workout.ride_info):
                ride_id = workout.ride_info.ride_id
                ride_map[ride_id][user_id].append(workout)
        
        # Track which ride_ids the user has taken
        user_ride_ids = set(ride_map.keys())
        
        # Add follower workouts
        for follower_id, workouts in follower_workouts.items():
            for workout in workouts:
                # Only include if user has also taken this ride and it's a valid ride
                if DataManager.is_valid_ride(workout.ride_info):
                    ride_id = workout.ride_info.ride_id
                    if ride_id in user_ride_ids:
                        ride_map[ride_id][follower_id].append(workout)
        
        # Create CommonRide objects for rides with multiple participants
        common_rides = []
        for ride_id, user_workout_map in ride_map.items():
            if len(user_workout_map) > 1:  # At least user + 1 follower
                # Get ride info from any workout (they're all the same ride/class)
                any_workout = next(iter(user_workout_map.values()))[0]
                ride_info = any_workout.ride_info
                common_ride = CommonRide(
                    ride_info=ride_info,
                    user_workouts=dict(user_workout_map)  # Convert defaultdict to dict
                )
                common_rides.append(common_ride)
        
        # Sort by participant count (descending), then by total workouts
        common_rides.sort(key=lambda r: (r.get_participant_count(), r.get_total_workout_count()), reverse=True)
        
        return common_rides
    
    @staticmethod
    def create_comparison_dataframe(workouts: List[Workout], 
                                   users: Dict[str, User],
                                   labels: Dict[str, str] = None) -> pd.DataFrame:
        """
        Create a DataFrame comparing workout summary statistics
        
        Args:
            workouts: List of workouts to compare
            users: Dict mapping user_id to User object
            labels: Optional dict mapping workout_id to custom label
            
        Returns:
            DataFrame with comparison data
        """
        from datetime import datetime
        
        data = []
        for idx, workout in enumerate(workouts, 1):
            # Use custom label if provided, otherwise fall back to username
            if labels and workout.workout_id in labels:
                display_name = labels[workout.workout_id]
            else:
                user = users.get(workout.user_id)
                display_name = user.username if user else workout.user_id
            
            # Format workout date
            workout_date = datetime.fromtimestamp(workout.start_time).strftime('%Y-%m-%d') if workout.start_time else "N/A"
            
            data.append({
                "#": idx,
                "User": display_name,
                "Date": workout_date,
                "Total Output (kJ)": round(workout.total_output, 1) if workout.total_output else 0,
                "Avg Output (W)": round(workout.avg_output, 1) if workout.avg_output else 0,
                "Avg Cadence (RPM)": round(workout.avg_cadence, 1) if workout.avg_cadence else 0,
                "Avg Resistance (%)": round(workout.avg_resistance, 1) if workout.avg_resistance else 0,
                "Avg HR (BPM)": round(workout.avg_heart_rate, 1) if workout.avg_heart_rate else "N/A",
                "Max HR (BPM)": round(workout.max_heart_rate, 1) if workout.max_heart_rate else "N/A",
                "Distance (mi)": round(workout.distance, 2) if workout.distance else 0,
                "Calories": round(workout.calories, 0) if workout.calories else 0
            })
        
        return pd.DataFrame(data)
    
    @staticmethod
    def create_time_series_dataframe(workouts: List[Workout],
                                    users: Dict[str, User],
                                    metric: str,
                                    labels: Dict[str, str] = None) -> pd.DataFrame:
        """
        Create a time series DataFrame for a specific metric
        
        Args:
            workouts: List of workouts with performance metrics
            users: Dict mapping user_id to User object
            metric: Metric name (output, cadence, resistance, heart_rate, speed, distance)
            labels: Optional dict mapping workout_id to custom label
            
        Returns:
            DataFrame with time series data for the metric
        """
        data = []
        
        for workout in workouts:
            if not workout.performance_metrics:
                continue
            
            # Use custom label if provided, otherwise fall back to username
            if labels and workout.workout_id in labels:
                display_name = labels[workout.workout_id]
            else:
                user = users.get(workout.user_id)
                display_name = user.username if user else workout.user_id
            
            metrics = workout.performance_metrics
            seconds = metrics.seconds_since_start
            values = getattr(metrics, metric, [])
            
            # Create row for each time point
            for i, second in enumerate(seconds):
                value = values[i] if i < len(values) else None
                data.append({
                    "User": display_name,
                    "Time (seconds)": second,
                    "Value": value
                })
        
        return pd.DataFrame(data)
    
    @staticmethod
    def calculate_rankings(workouts: List[Workout], metric: str = "total_output", labels: Dict[str, str] = None) -> List[Tuple[str, float]]:
        """
        Calculate rankings based on a specific metric
        
        Args:
            workouts: List of workouts to rank
            metric: Metric to rank by (total_output, avg_output, etc.)
            labels: Optional dict mapping workout_id to custom label
            
        Returns:
            List of tuples (label, metric_value) sorted by rank
        """
        rankings = []
        for workout in workouts:
            value = getattr(workout, metric, 0)
            # Use custom label if provided, otherwise use user_id
            label = labels.get(workout.workout_id, workout.user_id) if labels else workout.user_id
            rankings.append((label, value))
        
        # Sort descending (higher is better for most metrics)
        rankings.sort(key=lambda x: x[1], reverse=True)
        
        return rankings
    
    @staticmethod
    def get_metric_stats(workouts: List[Workout]) -> Dict[str, Dict[str, float]]:
        """
        Calculate statistics across all workouts for each metric
        
        Args:
            workouts: List of workouts
            
        Returns:
            Dict with stats for each metric
        """
        metrics = ["total_output", "avg_output", "avg_cadence", "avg_resistance", 
                  "avg_heart_rate", "distance", "calories"]
        
        stats = {}
        for metric in metrics:
            values = [getattr(w, metric, 0) for w in workouts if getattr(w, metric, 0) > 0]
            if values:
                stats[metric] = {
                    "min": min(values),
                    "max": max(values),
                    "avg": sum(values) / len(values),
                    "range": max(values) - min(values)
                }
        
        return stats
