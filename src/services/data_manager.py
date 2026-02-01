"""
Data Manager - Handles JSON file storage and retrieval
"""

import json
import os
import time
from typing import Dict, List, Optional
from pathlib import Path
from src.models.models import User, Workout, RideInfo


class DataManager:
    """Manages local JSON data storage"""
    
    # Invalid ride IDs that should be excluded (outdoor walks, etc.)
    INVALID_RIDE_IDS = {
        None,
        "",
        "00000000000000000000000000000000",
        "0" * 32,
    }
    
    @staticmethod
    def is_valid_ride(ride_info: RideInfo) -> bool:
        """
        Check if a ride is valid for comparison.
        
        Invalid rides include:
        - Rides with null/empty/all-zeros ride IDs (outdoor walks, etc.)
        - Rides with no instructor (scenic rides, just ride, etc.)
        
        Args:
            ride_info: RideInfo object to validate
            
        Returns:
            True if the ride is valid for comparison
        """
        if ride_info is None:
            return False
        
        # Check ride ID validity
        ride_id = ride_info.ride_id
        if ride_id is None or ride_id == "":
            return False
        if ride_id in DataManager.INVALID_RIDE_IDS:
            return False
        if set(ride_id) == {'0'}:
            return False
        
        # Check instructor validity (empty string = no instructor)
        if not ride_info.instructor_name:
            return False
        
        return True
    
    def __init__(self, data_dir: str = "data"):
        """
        Initialize DataManager
        
        Args:
            data_dir: Directory to store JSON files
        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        self.user_profile_file = self.data_dir / "user_profile.json"
        self.workouts_file = self.data_dir / "workouts.json"
        self.followers_file = self.data_dir / "followers.json"
        self.follower_workouts_file = self.data_dir / "follower_workouts.json"
        self.sync_metadata_file = self.data_dir / "sync_metadata.json"
    
    def save_sync_metadata(self, last_sync_time: int, user_id: str = None) -> None:
        """Save sync metadata including last sync timestamp"""
        metadata = self.load_sync_metadata()
        metadata["last_sync_time"] = last_sync_time
        if user_id:
            metadata["user_id"] = user_id
        with open(self.sync_metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def load_sync_metadata(self) -> Dict:
        """Load sync metadata"""
        if not self.sync_metadata_file.exists():
            return {"last_sync_time": 0}
        try:
            with open(self.sync_metadata_file, 'r') as f:
                return json.load(f)
        except Exception:
            return {"last_sync_time": 0}
    
    def get_last_sync_time(self) -> int:
        """Get the timestamp of the last sync"""
        return self.load_sync_metadata().get("last_sync_time", 0)
    
    def save_user_profile(self, user: User) -> None:
        """Save user profile to JSON"""
        with open(self.user_profile_file, 'w') as f:
            json.dump(user.to_dict(), f, indent=2)
    
    def load_user_profile(self) -> Optional[User]:
        """Load user profile from JSON"""
        if not self.user_profile_file.exists():
            return None
        
        try:
            with open(self.user_profile_file, 'r') as f:
                data = json.load(f)
                return User(**data)
        except Exception as e:
            print(f"Error loading user profile: {e}")
            return None
    
    def save_workouts(self, workouts: List[Workout], merge: bool = False) -> None:
        """Save user workouts to JSON
        
        Args:
            workouts: List of workouts to save
            merge: If True, merge with existing workouts (deduped by workout_id)
        """
        # Filter out invalid rides (no instructor, invalid IDs, etc.)
        workouts = [w for w in workouts if self.is_valid_ride(w.ride_info)]
        
        if merge:
            existing = self.load_workouts()
            existing_ids = {w.workout_id for w in existing}
            # Add only new workouts
            new_workouts = [w for w in workouts if w.workout_id not in existing_ids]
            workouts = existing + new_workouts
        
        workouts_data = [w.to_dict() for w in workouts]
        with open(self.workouts_file, 'w') as f:
            json.dump(workouts_data, f, indent=2)
    
    def load_workouts(self, fitness_discipline: str = "cycling") -> List[Workout]:
        """Load user workouts from JSON
        
        Args:
            fitness_discipline: Filter by workout type (default: 'cycling')
        """
        if not self.workouts_file.exists():
            return []
        
        try:
            with open(self.workouts_file, 'r') as f:
                data = json.load(f)
                workouts = [Workout.from_dict(w) for w in data]
                # Filter by fitness discipline
                if fitness_discipline:
                    workouts = [w for w in workouts if w.ride_info.ride_type == fitness_discipline]
                return workouts
        except Exception as e:
            print(f"Error loading workouts: {e}")
            return []
    
    def save_followers(self, followers: List[User]) -> None:
        """Save followers to JSON"""
        followers_data = [f.to_dict() for f in followers]
        with open(self.followers_file, 'w') as f:
            json.dump(followers_data, f, indent=2)
    
    def load_followers(self) -> List[User]:
        """Load followers from JSON"""
        if not self.followers_file.exists():
            return []
        
        try:
            with open(self.followers_file, 'r') as f:
                data = json.load(f)
                return [User(**f) for f in data]
        except Exception as e:
            print(f"Error loading followers: {e}")
            return []
    
    def save_follower_workouts(self, workouts_by_user: Dict[str, List[Workout]], merge: bool = False) -> None:
        """
        Save follower workouts to JSON
        
        Args:
            workouts_by_user: Dictionary mapping user_id to list of workouts
            merge: If True, merge with existing workouts (deduped by workout_id)
        """
        # Filter out invalid rides from each user's list
        workouts_by_user = {
            user_id: [w for w in workouts if self.is_valid_ride(w.ride_info)]
            for user_id, workouts in workouts_by_user.items()
        }
        
        if merge:
            existing = self.load_follower_workouts()
            for user_id, workouts in workouts_by_user.items():
                existing_workouts = existing.get(user_id, [])
                existing_ids = {w.workout_id for w in existing_workouts}
                new_workouts = [w for w in workouts if w.workout_id not in existing_ids]
                existing[user_id] = existing_workouts + new_workouts
            workouts_by_user = existing
        
        data = {
            user_id: [w.to_dict() for w in workouts]
            for user_id, workouts in workouts_by_user.items()
        }
        with open(self.follower_workouts_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load_follower_workouts(self, fitness_discipline: str = "cycling") -> Dict[str, List[Workout]]:
        """Load follower workouts from JSON
        
        Args:
            fitness_discipline: Filter by workout type (default: 'cycling')
        """
        if not self.follower_workouts_file.exists():
            return {}
        
        try:
            with open(self.follower_workouts_file, 'r') as f:
                data = json.load(f)
                result = {}
                for user_id, workouts in data.items():
                    workout_objs = [Workout.from_dict(w) for w in workouts]
                    # Filter by fitness discipline
                    if fitness_discipline:
                        workout_objs = [w for w in workout_objs if w.ride_info.ride_type == fitness_discipline]
                    if workout_objs:  # Only include users with matching workouts
                        result[user_id] = workout_objs
                return result
        except Exception as e:
            print(f"Error loading follower workouts: {e}")
            return {}
    
    def clear_all_data(self) -> None:
        """Clear all stored data"""
        for file in [self.user_profile_file, self.workouts_file, 
                     self.followers_file, self.follower_workouts_file,
                     self.sync_metadata_file]:
            if file.exists():
                file.unlink()
    
    def has_data(self) -> bool:
        """Check if any data exists"""
        return any(f.exists() for f in [self.user_profile_file, self.workouts_file])
