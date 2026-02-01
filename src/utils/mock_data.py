"""
Mock data generator for testing PelotonRacer without API access
"""

import random
from datetime import datetime, timedelta
from typing import List, Dict
from src.models.models import User, Workout, RideInfo, PerformanceMetrics
from src.config import (
    MOCK_USER_WORKOUTS_MIN,
    MOCK_USER_WORKOUTS_MAX,
    MOCK_FOLLOWER_WORKOUTS_MIN,
    MOCK_FOLLOWER_WORKOUTS_MAX
)


class MockDataGenerator:
    """Generates realistic mock Peloton data"""
    
    INSTRUCTORS = [
        "Robin Arzón", "Cody Rigsby", "Ally Love", "Jess King", "Emma Lovewell",
        "Kendall Toole", "Leanne Hainsby", "Ben Alldis", "Hannah Frankson", "Denis Morton"
    ]
    
    RIDE_TYPES = ["cycling", "strength", "yoga", "running", "meditation"]
    
    RIDE_TITLES = [
        "45 min Rock Ride", "30 min Pop Ride", "20 min HIIT Ride", "60 min Endurance Ride",
        "30 min Climb Ride", "45 min EDM Ride", "20 min Hip Hop Ride", "30 min Low Impact Ride",
        "45 min Power Zone Ride", "30 min Intervals & Arms", "20 min Recovery Ride"
    ]
    
    @staticmethod
    def generate_user(user_id: str, username: str, is_main_user: bool = False) -> User:
        """Generate a mock user"""
        if is_main_user:
            total_workouts = random.randint(MOCK_USER_WORKOUTS_MIN, MOCK_USER_WORKOUTS_MAX)
        else:
            total_workouts = random.randint(MOCK_FOLLOWER_WORKOUTS_MIN, MOCK_FOLLOWER_WORKOUTS_MAX)
        
        return User(
            user_id=user_id,
            username=username,
            display_name=username.title().replace("_", " "),
            image_url=f"https://api.dicebear.com/7.x/avataaars/svg?seed={username}",
            location=random.choice(["New York, NY", "London, UK", "Los Angeles, CA", "Chicago, IL", "Austin, TX"]),
            total_workouts=total_workouts
        )
    
    @staticmethod
    def generate_ride_info(ride_id: str) -> RideInfo:
        """Generate a mock ride"""
        duration = random.choice([1200, 1800, 2700, 3600])  # 20, 30, 45, 60 min
        
        return RideInfo(
            ride_id=ride_id,
            title=random.choice(MockDataGenerator.RIDE_TITLES),
            instructor_name=random.choice(MockDataGenerator.INSTRUCTORS),
            duration=duration,
            difficulty=round(random.uniform(6.5, 9.5), 2),
            ride_type=random.choice(["cycling", "cycling", "cycling", "strength"])  # Bias toward cycling
        )
    
    @staticmethod
    def generate_performance_metrics(duration: int, user_fitness_level: float = 1.0) -> PerformanceMetrics:
        """
        Generate realistic performance metrics over time
        
        Args:
            duration: Ride duration in seconds
            user_fitness_level: Multiplier for performance (0.7-1.3)
        """
        # Generate data points every 5 seconds
        num_points = duration // 5
        seconds = list(range(0, duration, 5))
        
        # Base values
        base_output = 150 * user_fitness_level
        base_cadence = 80
        base_resistance = 40
        base_hr = 130
        base_speed = 20
        
        # Generate realistic patterns with warmup, work, and cooldown
        output = []
        cadence = []
        resistance = []
        heart_rate = []
        speed = []
        distance = []
        
        total_distance = 0
        
        for i in range(num_points):
            progress = i / num_points
            
            # Warmup (0-10%), Work (10-90%), Cooldown (90-100%)
            if progress < 0.1:  # Warmup
                intensity = progress / 0.1 * 0.6
            elif progress > 0.9:  # Cooldown
                intensity = (1 - progress) / 0.1 * 0.6
            else:  # Work phase with variation
                intensity = 0.6 + 0.4 * abs(random.gauss(0.5, 0.2))
            
            # Add some randomness
            noise = random.uniform(0.95, 1.05)
            
            # Output (watts)
            output_val = int(base_output * intensity * noise)
            output.append(output_val)
            
            # Cadence (RPM)
            cadence_val = int(base_cadence * (0.8 + 0.4 * intensity) * noise)
            cadence.append(cadence_val)
            
            # Resistance (%)
            resistance_val = int(base_resistance * (0.7 + 0.6 * intensity) * noise)
            resistance.append(min(100, resistance_val))
            
            # Heart rate (BPM)
            hr_val = int(base_hr + 30 * intensity * noise)
            heart_rate.append(hr_val if hr_val > 0 else None)
            
            # Speed (mph)
            speed_val = round(base_speed * (0.7 + 0.6 * intensity) * noise, 1)
            speed.append(speed_val)
            
            # Distance (cumulative miles)
            total_distance += speed_val * (5 / 3600)  # 5 seconds worth of distance
            distance.append(round(total_distance, 2))
        
        return PerformanceMetrics(
            seconds_since_start=seconds,
            output=output,
            cadence=cadence,
            resistance=resistance,
            heart_rate=heart_rate,
            speed=speed,
            distance=distance
        )
    
    @staticmethod
    def generate_workout(workout_id: str, user_id: str, ride_info: RideInfo, 
                        days_ago: int = 0, user_fitness_level: float = 1.0) -> Workout:
        """Generate a mock workout"""
        # Create timestamp
        workout_time = datetime.now() - timedelta(days=days_ago, hours=random.randint(0, 23))
        start_time = int(workout_time.timestamp())
        end_time = start_time + ride_info.duration
        
        # Generate performance metrics
        perf_metrics = MockDataGenerator.generate_performance_metrics(
            ride_info.duration, 
            user_fitness_level
        )
        
        # Calculate summary stats from performance data
        avg_output = sum(perf_metrics.output) / len(perf_metrics.output)
        avg_cadence = sum(perf_metrics.cadence) / len(perf_metrics.cadence)
        avg_resistance = sum(perf_metrics.resistance) / len(perf_metrics.resistance)
        valid_hr = [hr for hr in perf_metrics.heart_rate if hr is not None]
        avg_hr = sum(valid_hr) / len(valid_hr) if valid_hr else 0
        max_hr = max(valid_hr) if valid_hr else 0
        total_output = avg_output * ride_info.duration / 1000  # kJ
        final_distance = perf_metrics.distance[-1] if perf_metrics.distance else 0
        calories = total_output * 1.05  # Rough approximation
        
        return Workout(
            workout_id=workout_id,
            user_id=user_id,
            ride_info=ride_info,
            created_at=workout_time.isoformat(),
            start_time=start_time,
            end_time=end_time,
            total_output=round(total_output, 1),
            avg_output=round(avg_output, 1),
            avg_cadence=round(avg_cadence, 1),
            avg_resistance=round(avg_resistance, 1),
            avg_heart_rate=round(avg_hr, 1),
            max_heart_rate=round(max_hr, 1),
            distance=round(final_distance, 2),
            calories=round(calories, 1),
            performance_metrics=perf_metrics
        )
    
    @classmethod
    def generate_mock_data(cls) -> tuple[User, List[Workout], List[User], Dict[str, List[Workout]]]:
        """
        Generate complete mock dataset
        
        Returns:
            Tuple of (user_profile, user_workouts, followers, follower_workouts)
        """
        # Generate main user
        user_profile = cls.generate_user("user_main_123", "your_username", is_main_user=True)
        
        # Generate followers
        num_followers = 8
        followers = []
        for i in range(num_followers):
            follower = cls.generate_user(
                f"user_follower_{i}",
                f"rider_{random.choice(['cool', 'fast', 'strong', 'zen', 'power'])}_{i}"
            )
            followers.append(follower)
        
        # Generate 15 different rides
        num_rides = 15
        rides = []
        for i in range(num_rides):
            ride = cls.generate_ride_info(f"ride_{i:03d}")
            rides.append(ride)
        
        # Generate workouts for main user (20 workouts)
        user_workouts = []
        for i in range(20):
            ride = random.choice(rides)
            workout = cls.generate_workout(
                f"workout_main_{i}",
                user_profile.user_id,
                ride,
                days_ago=random.randint(0, 60),
                user_fitness_level=random.uniform(0.9, 1.1)
            )
            user_workouts.append(workout)
        
        # Generate workouts for followers (ensuring some overlap)
        follower_workouts = {}
        for follower in followers:
            workouts = []
            num_workouts = random.randint(10, 25)
            
            # Each follower should have some common rides with main user
            common_ride_count = random.randint(3, 8)
            user_ride_ids = [w.ride_info.ride_id for w in user_workouts]
            common_rides = random.sample(user_ride_ids, min(common_ride_count, len(user_ride_ids)))
            
            for i in range(num_workouts):
                # Sometimes use a common ride, sometimes random
                if i < len(common_rides):
                    ride_id = common_rides[i]
                    ride = next(r for r in rides if r.ride_id == ride_id)
                else:
                    ride = random.choice(rides)
                
                workout = cls.generate_workout(
                    f"workout_{follower.user_id}_{i}",
                    follower.user_id,
                    ride,
                    days_ago=random.randint(0, 60),
                    user_fitness_level=random.uniform(0.7, 1.3)
                )
                workouts.append(workout)
            
            follower_workouts[follower.user_id] = workouts
        
        return user_profile, user_workouts, followers, follower_workouts
