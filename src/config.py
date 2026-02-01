"""
Configuration constants for PelotonRacer
Centralized settings for API limits, sync behavior, and defaults
"""

# =============================================================================
# API LIMITS
# =============================================================================

# Maximum items per API request (Peloton enforces 100 max)
API_PAGE_SIZE = 100

# Maximum followers to fetch per request
API_FOLLOWERS_LIMIT = 1000

# =============================================================================
# SYNC SETTINGS
# =============================================================================

# Maximum workouts to fetch for the main user
MAX_USER_WORKOUTS_FULL = 3000      # Full sync
MAX_USER_WORKOUTS_INCREMENTAL = 500  # Quick/incremental sync

# Maximum workouts to fetch per follower
MAX_FOLLOWER_WORKOUTS_FULL = 3000      # Full sync
MAX_FOLLOWER_WORKOUTS_INCREMENTAL = 500  # Quick/incremental sync

# Number of concurrent API requests when fetching follower data
PARALLEL_WORKERS = 5

# =============================================================================
# MOCK DATA SETTINGS
# =============================================================================

# Range of total workouts for mock users (for display purposes only)
MOCK_USER_WORKOUTS_MIN = 100
MOCK_USER_WORKOUTS_MAX = 1000
MOCK_FOLLOWER_WORKOUTS_MIN = 50
MOCK_FOLLOWER_WORKOUTS_MAX = 500
