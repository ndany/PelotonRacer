"""
Data models for PelotonRacer application
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict
from datetime import datetime


@dataclass
class User:
    """Peloton user model"""
    user_id: str
    username: str
    display_name: str = ""
    image_url: str = ""
    location: str = ""
    total_workouts: int = 0
    
    @classmethod
    def from_api_response(cls, data: Dict) -> 'User':
        """Create User from Peloton API response"""
        return cls(
            user_id=data.get("id", ""),
            username=data.get("username", ""),
            display_name=data.get("name", ""),
            image_url=data.get("image_url", ""),
            location=data.get("location", ""),
            total_workouts=data.get("total_workouts", 0)
        )
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "user_id": self.user_id,
            "username": self.username,
            "display_name": self.display_name,
            "image_url": self.image_url,
            "location": self.location,
            "total_workouts": self.total_workouts
        }


@dataclass
class RideInfo:
    """Information about a Peloton ride class"""
    ride_id: str
    title: str
    instructor_name: str = ""
    duration: int = 0  # seconds
    difficulty: float = 0.0
    ride_type: str = ""
    
    @classmethod
    def from_api_response(cls, data: Dict) -> 'RideInfo':
        """Create RideInfo from Peloton API response"""
        # For on-demand classes, the ride info is in peloton.ride
        # For outdoor/freestyle, it's in ride (but with invalid IDs)
        peloton_ride = data.get("peloton", {})
        if peloton_ride and "ride" in peloton_ride:
            ride = peloton_ride["ride"]
        elif "ride" in data:
            ride = data.get("ride", {})
        else:
            ride = data
        
        # Extract instructor name - check multiple possible locations
        instructor_name = ""
        instructor = ride.get("instructor", {})
        if isinstance(instructor, dict):
            instructor_name = instructor.get("name", "")
        
        # If not found in ride.instructor, check peloton.ride.instructor
        if not instructor_name and peloton_ride:
            peloton_instructor = peloton_ride.get("ride", {}).get("instructor", {})
            if isinstance(peloton_instructor, dict):
                instructor_name = peloton_instructor.get("name", "")
        
        # The title might be in the ride or in the workout data directly
        title = ride.get("title") or data.get("title") or ""
        
        return cls(
            ride_id=ride.get("id", ""),
            title=title,
            instructor_name=instructor_name,
            duration=ride.get("duration", 0),
            difficulty=ride.get("difficulty_rating_avg", 0.0) or ride.get("difficulty_estimate", 0.0),
            ride_type=ride.get("fitness_discipline", "") or data.get("fitness_discipline", "")
        )
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "ride_id": self.ride_id,
            "title": self.title,
            "instructor_name": self.instructor_name,
            "duration": self.duration,
            "difficulty": self.difficulty,
            "ride_type": self.ride_type
        }


@dataclass
class PerformanceMetrics:
    """Performance metrics over time for a workout"""
    seconds_since_start: List[int] = field(default_factory=list)
    output: List[Optional[float]] = field(default_factory=list)  # watts
    cadence: List[Optional[int]] = field(default_factory=list)   # RPM
    resistance: List[Optional[int]] = field(default_factory=list)  # percentage
    heart_rate: List[Optional[int]] = field(default_factory=list)  # BPM
    speed: List[Optional[float]] = field(default_factory=list)    # mph or kph
    distance: List[Optional[float]] = field(default_factory=list)  # miles or km
    
    @classmethod
    def from_api_response(cls, data: Dict) -> 'PerformanceMetrics':
        """Create PerformanceMetrics from Peloton API performance graph response"""
        metrics = data.get("metrics", [])
        seconds = data.get("seconds_since_pedaling_start", [])
        
        # Initialize metric lists
        output_values = []
        cadence_values = []
        resistance_values = []
        heart_rate_values = []
        speed_values = []
        distance_values = []
        
        # Parse metrics from API response
        for metric in metrics:
            slug = metric.get("slug", "")
            values = metric.get("values", [])
            
            if slug == "output":
                output_values = values
            elif slug == "cadence":
                cadence_values = values
            elif slug == "resistance":
                resistance_values = values
            elif slug == "heart_rate":
                heart_rate_values = values
            elif slug == "speed":
                speed_values = values
            elif slug == "distance":
                distance_values = values
        
        return cls(
            seconds_since_start=seconds,
            output=output_values,
            cadence=cadence_values,
            resistance=resistance_values,
            heart_rate=heart_rate_values,
            speed=speed_values,
            distance=distance_values
        )
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "seconds_since_start": self.seconds_since_start,
            "output": self.output,
            "cadence": self.cadence,
            "resistance": self.resistance,
            "heart_rate": self.heart_rate,
            "speed": self.speed,
            "distance": self.distance
        }


@dataclass
class Workout:
    """Complete workout with performance data"""
    workout_id: str
    user_id: str
    ride_info: RideInfo
    created_at: str  # ISO format timestamp
    start_time: int  # Unix timestamp
    end_time: int  # Unix timestamp
    total_output: float = 0.0  # kJ
    avg_output: float = 0.0  # watts
    avg_cadence: float = 0.0  # RPM
    avg_resistance: float = 0.0  # percentage
    avg_heart_rate: float = 0.0  # BPM
    max_heart_rate: float = 0.0  # BPM
    distance: float = 0.0  # miles or km
    calories: float = 0.0
    performance_metrics: Optional[PerformanceMetrics] = None
    
    def update_from_performance_data(self, performance_data: Dict) -> None:
        """
        Update workout with data from performance_graph API response.
        This includes both time-series metrics and summary statistics.
        
        Args:
            performance_data: Response from /api/workout/{id}/performance_graph
        """
        # Update performance metrics (time series data)
        self.performance_metrics = PerformanceMetrics.from_api_response(performance_data)
        
        # Update summary statistics from performance_graph summaries
        summaries = performance_data.get("summaries", [])
        summary_dict = {s.get("slug"): s.get("value", 0) for s in summaries}
        
        # Also check average_summaries for avg values
        avg_summaries = performance_data.get("average_summaries", [])
        avg_dict = {s.get("slug"): s.get("value", 0) for s in avg_summaries}
        
        # Update summary fields if we got data
        if summary_dict.get("total_output"):
            self.total_output = summary_dict.get("total_output", 0.0)
        if summary_dict.get("distance"):
            self.distance = summary_dict.get("distance", 0.0)
        if summary_dict.get("total_calories"):
            self.calories = summary_dict.get("total_calories", 0.0)
        elif summary_dict.get("calories"):
            self.calories = summary_dict.get("calories", 0.0)
        
        # Update averages from average_summaries
        if avg_dict.get("avg_output"):
            self.avg_output = avg_dict.get("avg_output", 0.0)
        if avg_dict.get("avg_cadence"):
            self.avg_cadence = avg_dict.get("avg_cadence", 0.0)
        if avg_dict.get("avg_resistance"):
            self.avg_resistance = avg_dict.get("avg_resistance", 0.0)
        if avg_dict.get("avg_heart_rate"):
            self.avg_heart_rate = avg_dict.get("avg_heart_rate", 0.0)
        if avg_dict.get("max_heart_rate"):
            self.max_heart_rate = avg_dict.get("max_heart_rate", 0.0)
    
    @classmethod
    def from_api_response(cls, workout_data: Dict, performance_data: Optional[Dict] = None) -> 'Workout':
        """Create Workout from Peloton API response"""
        ride_info = RideInfo.from_api_response(workout_data)
        
        # Parse performance metrics if available
        metrics = None
        if performance_data:
            metrics = PerformanceMetrics.from_api_response(performance_data)
        
        # Get summary metrics
        summaries = workout_data.get("summaries", [])
        summary_dict = {s.get("slug"): s.get("value") for s in summaries}
        
        # Distance might be in multiple locations - check alternatives
        distance = summary_dict.get("distance", 0.0)
        if not distance:
            # Check if it's in the workout data directly
            distance = workout_data.get("total_distance", 0.0) or workout_data.get("distance", 0.0)
        
        return cls(
            workout_id=workout_data.get("id", ""),
            user_id=workout_data.get("user_id", ""),
            ride_info=ride_info,
            created_at=workout_data.get("created_at", ""),
            start_time=workout_data.get("start_time", 0),
            end_time=workout_data.get("end_time", 0),
            total_output=summary_dict.get("total_output", 0.0),
            avg_output=summary_dict.get("avg_output", 0.0),
            avg_cadence=summary_dict.get("avg_cadence", 0.0),
            avg_resistance=summary_dict.get("avg_resistance", 0.0),
            avg_heart_rate=summary_dict.get("avg_heart_rate", 0.0),
            max_heart_rate=summary_dict.get("max_heart_rate", 0.0),
            distance=distance,
            calories=summary_dict.get("calories", 0.0),
            performance_metrics=metrics
        )
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "workout_id": self.workout_id,
            "user_id": self.user_id,
            "ride_info": self.ride_info.to_dict(),
            "created_at": self.created_at,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "total_output": self.total_output,
            "avg_output": self.avg_output,
            "avg_cadence": self.avg_cadence,
            "avg_resistance": self.avg_resistance,
            "avg_heart_rate": self.avg_heart_rate,
            "max_heart_rate": self.max_heart_rate,
            "distance": self.distance,
            "calories": self.calories,
            "performance_metrics": self.performance_metrics.to_dict() if self.performance_metrics else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Workout':
        """Create Workout from dictionary"""
        ride_info = RideInfo(**data["ride_info"])
        
        metrics = None
        if data.get("performance_metrics"):
            metrics = PerformanceMetrics(**data["performance_metrics"])
        
        return cls(
            workout_id=data["workout_id"],
            user_id=data["user_id"],
            ride_info=ride_info,
            created_at=data["created_at"],
            start_time=data["start_time"],
            end_time=data["end_time"],
            total_output=data.get("total_output", 0.0),
            avg_output=data.get("avg_output", 0.0),
            avg_cadence=data.get("avg_cadence", 0.0),
            avg_resistance=data.get("avg_resistance", 0.0),
            avg_heart_rate=data.get("avg_heart_rate", 0.0),
            max_heart_rate=data.get("max_heart_rate", 0.0),
            distance=data.get("distance", 0.0),
            calories=data.get("calories", 0.0),
            performance_metrics=metrics
        )


@dataclass
class CommonRide:
    """A ride (class) taken by multiple users, potentially multiple times each"""
    ride_info: RideInfo
    user_workouts: Dict[str, List[Workout]]  # user_id -> List of Workouts (multiple attempts)
    
    def get_participant_count(self) -> int:
        """Get number of users who took this ride"""
        return len(self.user_workouts)
    
    def get_total_workout_count(self) -> int:
        """Get total number of workout attempts across all users"""
        return sum(len(workouts) for workouts in self.user_workouts.values())
    
    def get_participant_usernames(self) -> List[str]:
        """Get list of user IDs who took this ride"""
        return list(self.user_workouts.keys())
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "ride_info": self.ride_info.to_dict(),
            "user_workouts": {
                user_id: [workout.to_dict() for workout in workouts] 
                for user_id, workouts in self.user_workouts.items()
            }
        }
