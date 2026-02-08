"""
Peloton API Client
Handles authentication and data retrieval from Peloton API
"""

import requests
import json
import jwt
from typing import Dict, List, Optional
from datetime import datetime

from src.config import (
    API_PAGE_SIZE,
    API_FOLLOWERS_LIMIT,
    MAX_USER_WORKOUTS_FULL,
    MAX_FOLLOWER_WORKOUTS_FULL
)


class PelotonClient:
    """Client for interacting with Peloton API"""
    
    BASE_URL = "https://api.onepeloton.com"
    
    def __init__(self, username: str = None, password: str = None, session_id: str = None, bearer_token: str = None):
        """
        Initialize Peloton client with credentials or existing session/token
        
        Args:
            username: Peloton username or email (optional if token provided)
            password: Peloton password (optional if token provided)
            session_id: Existing session ID from browser cookie (optional)
            bearer_token: Bearer token from browser (recommended method)
        """
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.user_id = None
        self.session_id = session_id
        self.bearer_token = bearer_token
        
        # Set headers to mimic browser
        self.session.headers.update({
            "Peloton-Platform": "web",
            "Peloton-Client-Details": "eyJEZXZpY2UgVHlwZSI6IldlYiIsIkFwcCBWZXJzaW9uIjoiMS4wLjAifQ==",
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://members.onepeloton.com",
            "Referer": "https://members.onepeloton.com/",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
        })
        
        # If bearer_token provided, set authorization header
        if bearer_token:
            self.session.headers.update({
                "Authorization": f"Bearer {bearer_token}"
            })
        
        # If session_id provided, set cookie
        if session_id:
            self.session.cookies.set("peloton_session_id", session_id)
        
    def authenticate(self) -> bool:
        """
        Authenticate with Peloton API
        
        Returns:
            bool: True if authentication successful
        """
        # If we have a bearer token, validate it
        if self.bearer_token:
            return self._validate_bearer_token()
        
        # If we have a session_id, try to validate it
        if self.session_id:
            return self._validate_session()
        
        # Otherwise, try username/password auth
        return self._authenticate_with_credentials()
    
    def _validate_bearer_token(self) -> bool:
        """Validate bearer token by decoding JWT and verifying with API"""
        try:
            # Decode JWT using PyJWT with expiration checking
            # We cannot verify the signature since we don't have Peloton's signing key,
            # but we validate token structure, required claims, and expiration
            claims = jwt.decode(
                self.bearer_token,
                algorithms=["HS256", "RS256"],
                options={
                    "verify_signature": False,
                    "verify_exp": True,
                    "require": ["exp", "http://onepeloton.com/user_id"]
                }
            )

            # Extract user_id from claims
            self.user_id = claims.get("http://onepeloton.com/user_id")
            if not self.user_id:
                print("No user_id in JWT claims")
                return False

            # Verify the token works by fetching user profile
            endpoint = f"{self.BASE_URL}/api/user/{self.user_id}"
            response = self.session.get(endpoint)
            response.raise_for_status()

            data = response.json()
            # If we get valid user data, auth is successful
            if data.get("id") == self.user_id:
                return True

            return False
        except jwt.ExpiredSignatureError:
            print("Bearer token has expired")
            return False
        except jwt.DecodeError:
            print("Bearer token is malformed")
            return False
        except jwt.InvalidTokenError:
            print("Bearer token is invalid")
            return False
        except Exception:
            print("Bearer token validation failed")
            return False
    
    def _validate_session(self) -> bool:
        """Validate existing session by fetching user info"""
        try:
            endpoint = f"{self.BASE_URL}/auth/check_session"
            response = self.session.get(endpoint)
            response.raise_for_status()
            
            data = response.json()
            self.user_id = data.get("user_id")
            
            if self.user_id:
                return True
            return False
        except Exception:
            print("Session validation failed")
            return False
    
    def _authenticate_with_credentials(self) -> bool:
        """Authenticate using username and password"""
        try:
            # Try with ?= query param to bypass WAF (workaround from GitHub issue)
            auth_endpoint = f"{self.BASE_URL}/auth/login?="
            payload = {
                "username_or_email": self.username,
                "password": self.password
            }
            
            response = self.session.post(auth_endpoint, json=payload)
            response.raise_for_status()
            
            data = response.json()
            self.user_id = data.get("user_id")
            self.session_id = data.get("session_id")
            
            # Set session cookie
            self.session.cookies.set("peloton_session_id", self.session_id)
            
            return True
        except Exception:
            print("Authentication failed")
            return False
    
    def get_user_profile(self) -> Optional[Dict]:
        """
        Get authenticated user's profile
        
        Returns:
            Dict with user profile data or None
        """
        if not self.user_id:
            return None
            
        try:
            endpoint = f"{self.BASE_URL}/api/user/{self.user_id}"
            response = self.session.get(endpoint)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Failed to get user profile: {e}")
            return None
    
    def get_workouts(self, limit: int = 100, page: int = 0, fitness_discipline: str = None) -> List[Dict]:
        """
        Get user's workout history
        
        Args:
            limit: Number of workouts per page
            page: Page number (0-indexed)
            fitness_discipline: Filter by type (e.g., 'cycling')
            
        Returns:
            List of workout dictionaries
        """
        if not self.user_id:
            return []
            
        try:
            endpoint = f"{self.BASE_URL}/api/user/{self.user_id}/workouts"
            params = {
                "limit": str(limit),
                "page": str(page),
                "joins": "peloton.ride,peloton.ride.instructor"  # Include instructor data
            }
            if fitness_discipline:
                params["fitness_discipline"] = fitness_discipline
            
            response = self.session.get(endpoint, params=params)
            response.raise_for_status()
            
            data = response.json()
            return data.get("data", [])
        except Exception as e:
            print(f"Failed to get workouts: {e}")
            return []
    
    def get_all_workouts(self, max_workouts: int = None, fitness_discipline: str = "cycling") -> List[Dict]:
        """
        Get all user workouts (paginated)
        
        Note: Peloton API caps limit at 100 per page, so we paginate accordingly.
        
        Args:
            max_workouts: Maximum total workouts to fetch (defaults to MAX_USER_WORKOUTS_FULL from config)
            fitness_discipline: Filter by workout type (default: 'cycling')
        
        Returns:
            List of all workout dictionaries
        """
        if max_workouts is None:
            max_workouts = MAX_USER_WORKOUTS_FULL
            
        all_workouts = []
        page = 0
        
        while len(all_workouts) < max_workouts:
            workouts = self.get_workouts(limit=API_PAGE_SIZE, page=page, fitness_discipline=fitness_discipline)
            if not workouts:
                break
            all_workouts.extend(workouts)
            print(f"Fetched page {page + 1}: {len(workouts)} workouts (total: {len(all_workouts)})")
            
            # If we got less than page_size, we've reached the end
            if len(workouts) < API_PAGE_SIZE:
                break
                
            page += 1
        
        return all_workouts[:max_workouts]
    
    def get_workout_performance(self, workout_id: str) -> Optional[Dict]:
        """
        Get detailed performance metrics for a specific workout
        
        Args:
            workout_id: Workout ID
            
        Returns:
            Dict with performance data including metrics over time
        """
        try:
            endpoint = f"{self.BASE_URL}/api/workout/{workout_id}/performance_graph"
            params = {"every_n": 5}  # Data point every 5 seconds
            
            response = self.session.get(endpoint, params=params)
            response.raise_for_status()
            
            return response.json()
        except Exception as e:
            print(f"Failed to get workout performance for {workout_id}: {e}")
            return None
    
    def get_followers(self) -> List[Dict]:
        """
        Get list of users that the authenticated user follows
        
        Returns:
            List of follower dictionaries
        """
        if not self.user_id:
            return []
            
        try:
            endpoint = f"{self.BASE_URL}/api/user/{self.user_id}/following"
            params = {"limit": API_FOLLOWERS_LIMIT, "page": 0}
            
            response = self.session.get(endpoint, params=params)
            response.raise_for_status()
            
            data = response.json()
            return data.get("data", [])
        except Exception as e:
            print(f"Failed to get followers: {e}")
            return []
    
    def get_user_workouts(self, user_id: str, limit: int = 100, page: int = 0, fitness_discipline: str = None) -> List[Dict]:
        """
        Get workouts for a specific user (must be following them)
        
        Args:
            user_id: User ID to fetch workouts for
            limit: Maximum number of workouts to fetch per page
            page: Page number (0-indexed)
            fitness_discipline: Filter by type (e.g., 'cycling')
            
        Returns:
            List of workout dictionaries
        """
        try:
            endpoint = f"{self.BASE_URL}/api/user/{user_id}/workouts"
            params = {
                "limit": str(limit),
                "page": str(page),
                "joins": "peloton.ride,peloton.ride.instructor"  # Include instructor data
            }
            if fitness_discipline:
                params["fitness_discipline"] = fitness_discipline
            
            response = self.session.get(endpoint, params=params)
            response.raise_for_status()
            
            data = response.json()
            return data.get("data", [])
        except Exception as e:
            print(f"Failed to get workouts for user {user_id}: {e}")
            return []
    
    def get_all_user_workouts(self, user_id: str, max_workouts: int = None, fitness_discipline: str = "cycling") -> List[Dict]:
        """
        Get all workouts for a specific user (paginated)
        
        Note: Peloton API caps limit at 100 per page, so we paginate accordingly.
        
        Args:
            user_id: User ID to fetch workouts for
            max_workouts: Maximum total workouts to fetch (defaults to MAX_FOLLOWER_WORKOUTS_FULL from config)
            fitness_discipline: Filter by workout type (default: 'cycling')
            
        Returns:
            List of all workout dictionaries
        """
        if max_workouts is None:
            max_workouts = MAX_FOLLOWER_WORKOUTS_FULL
            
        all_workouts = []
        page = 0
        
        while len(all_workouts) < max_workouts:
            workouts = self.get_user_workouts(user_id, limit=API_PAGE_SIZE, page=page, fitness_discipline=fitness_discipline)
            if not workouts:
                break
            all_workouts.extend(workouts)
            
            # If we got less than page_size, we've reached the end
            if len(workouts) < API_PAGE_SIZE:
                break
                
            page += 1
        
        return all_workouts[:max_workouts]  # Trim to max if needed
