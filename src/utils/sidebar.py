"""
Shared Sidebar Component
Provides consistent sidebar navigation and controls across all pages
"""

import streamlit as st
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


def render_sidebar():
    """Render the consistent sidebar with navigation and controls for all pages"""
    from src.api.peloton_client import PelotonClient
    from src.services.data_manager import DataManager
    from src.utils.mock_data import MockDataGenerator
    from src.config import (
        MAX_USER_WORKOUTS_FULL,
        MAX_USER_WORKOUTS_INCREMENTAL,
        MAX_FOLLOWER_WORKOUTS_FULL,
        MAX_FOLLOWER_WORKOUTS_INCREMENTAL,
        PARALLEL_WORKERS
    )
    from src.models.models import User, Workout
    
    # Initialize session state if needed
    if 'data_manager' not in st.session_state:
        st.session_state.data_manager = DataManager()
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'client' not in st.session_state:
        st.session_state.client = None
    if 'use_mock_data' not in st.session_state:
        st.session_state.use_mock_data = False
    
    with st.sidebar:
        # 1. Authentication Section (top)
        st.header("🔐 Authentication")
        
        if st.session_state.use_mock_data:
            # Mock data mode
            st.info("Using Mock Data")
            if st.button("🎲 Load Mock Data", use_container_width=True, key="sidebar_load_mock"):
                _load_mock_data()
                st.rerun()
        else:
            # Real API mode
            if not st.session_state.authenticated:
                if st.button("🔐 Authenticate", use_container_width=True, key="sidebar_auth"):
                    if _authenticate_user():
                        st.rerun()
            else:
                st.success("✅ Authenticated")
        
        st.divider()
        
        # 2. Navigation Links
        st.header("📍 Navigation")
        st.page_link("app.py", label="Main Page", icon="🏠")
        st.page_link("pages/data_load_status.py", label="Data Load Status", icon="📊")
        
        st.divider()
        
        # 3. Sync Controls (only show after authentication)
        if st.session_state.authenticated or st.session_state.use_mock_data:
            st.header("🔄 Sync")
            
            # Show last sync time
            last_sync = st.session_state.data_manager.get_last_sync_time()
            if last_sync > 0:
                last_sync_str = datetime.fromtimestamp(last_sync).strftime('%Y-%m-%d %H:%M')
                st.caption(f"Last sync: {last_sync_str}")
            
            if not st.session_state.use_mock_data:
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("🔄 Quick", use_container_width=True, help="Incremental sync - only new data", key="sidebar_quick_sync"):
                        _sync_data(full_sync=False)
                with col2:
                    if st.button("📥 Full", use_container_width=True, help="Full sync - all historical data", key="sidebar_full_sync"):
                        _sync_data(full_sync=True)
            
            # Show detailed sync status (persistent after sync completes)
            if 'last_sync_results' in st.session_state:
                results = st.session_state.last_sync_results
                sync_time_str = datetime.fromtimestamp(results['timestamp']).strftime('%H:%M:%S')
                
                with st.expander(f"📋 Last Sync Details", expanded=False):
                    st.markdown(f"**Type:** {results['sync_type']} Sync")
                    st.markdown(f"**Time:** {sync_time_str}")
                    if results['username']:
                        st.markdown(f"**User:** {results['username']}")
                    st.markdown(f"**Your Workouts:** {results['user_workouts']}")
                    st.markdown(f"**Followers:** {results['followers']}")
                    st.markdown(f"**Follower Workouts:** {results['follower_workouts']}")
            
            st.divider()
        
        # 4. Data Management
        if st.button("🗑️ Clear All Data", use_container_width=True, key="sidebar_clear_data"):
            st.session_state.data_manager.clear_all_data()
            if 'common_rides' in st.session_state:
                st.session_state.common_rides = []
            st.success("Data cleared!")
            st.rerun()


def _authenticate_user():
    """Authenticate with Peloton API"""
    from src.api.peloton_client import PelotonClient
    
    bearer_token = os.getenv("PELOTON_BEARER_TOKEN")
    session_id = os.getenv("PELOTON_SESSION_ID")
    username = os.getenv("PELOTON_USERNAME")
    password = os.getenv("PELOTON_PASSWORD")
    
    # Try bearer token first (most reliable method)
    if bearer_token and bearer_token.strip():
        with st.spinner("Validating bearer token..."):
            client = PelotonClient(bearer_token=bearer_token.strip())
            if client.authenticate():
                st.session_state.client = client
                st.session_state.authenticated = True
                st.success("✅ Bearer token validated successfully!")
                return True
            else:
                st.warning("⚠️ Bearer token invalid or expired. Trying session ID...")
    
    # Try session ID next (browser cookie method)
    if session_id and session_id.strip():
        with st.spinner("Validating session ID..."):
            client = PelotonClient(session_id=session_id.strip())
            if client.authenticate():
                st.session_state.client = client
                st.session_state.authenticated = True
                st.success("✅ Session validated successfully!")
                return True
            else:
                st.warning("⚠️ Session ID invalid or expired. Trying username/password...")
    
    # Fall back to username/password
    if not username or not password:
        st.error("Please set PELOTON_BEARER_TOKEN, PELOTON_SESSION_ID, or (PELOTON_USERNAME and PELOTON_PASSWORD) in your .env file")
        st.info("""
        **To get your Bearer Token (recommended):**
        1. Log into https://members.onepeloton.com in your browser
        2. Open Developer Tools (F12)
        3. Go to Network tab, click any request to api.onepeloton.com
        4. Look in Headers for "Authorization: Bearer eyJ..."
        5. Copy everything AFTER "Bearer " to your .env file
        """)
        return False
    
    with st.spinner("Authenticating with Peloton..."):
        client = PelotonClient(username=username, password=password)
        if client.authenticate():
            st.session_state.client = client
            st.session_state.authenticated = True
            st.success("✅ Authentication successful!")
            return True
        else:
            st.error("❌ Authentication failed. Try using the Session ID method instead.")
            return False


def _load_mock_data():
    """Load mock data for testing"""
    from src.utils.mock_data import MockDataGenerator
    
    dm = st.session_state.data_manager
    
    with st.spinner("Generating mock data..."):
        # Generate mock data
        user_profile, user_workouts, followers, follower_workouts = MockDataGenerator.generate_mock_data()
        
        # Save to data manager
        dm.save_user_profile(user_profile)
        dm.save_workouts(user_workouts)
        dm.save_followers(followers)
        dm.save_follower_workouts(follower_workouts)
        
        st.success(f"✅ Mock data loaded: {len(user_workouts)} workouts, {len(followers)} followers")


def _sync_data(full_sync: bool = False):
    """Sync data from Peloton API
    
    Args:
        full_sync: If True, fetch all data. If False, only fetch new data since last sync.
    """
    import time
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from src.models.models import User, Workout
    from src.config import (
        MAX_USER_WORKOUTS_FULL,
        MAX_USER_WORKOUTS_INCREMENTAL,
        MAX_FOLLOWER_WORKOUTS_FULL,
        MAX_FOLLOWER_WORKOUTS_INCREMENTAL,
        PARALLEL_WORKERS
    )
    
    client = st.session_state.client
    dm = st.session_state.data_manager
    
    last_sync_time = dm.get_last_sync_time() if not full_sync else 0
    sync_start_time = int(time.time())
    
    # Track sync results for persistent display
    sync_results = {
        'sync_type': 'Full' if full_sync else 'Quick',
        'user_workouts': 0,
        'followers': 0,
        'follower_workouts': 0,
        'username': None,
        'timestamp': sync_start_time
    }
    
    # Get user profile
    with st.spinner("Fetching user profile..."):
        profile_data = client.get_user_profile()
        if profile_data:
            user = User.from_api_response(profile_data)
            dm.save_user_profile(user)
            sync_results['username'] = user.username
            st.success(f"✅ Profile loaded: {user.username}")
    
    # Get user workouts (incremental)
    with st.spinner("Fetching your workouts..."):
        if last_sync_time > 0:
            st.info(f"🔄 Incremental sync: fetching workouts since last sync...")
            # For incremental, just get recent workouts
            workouts_data = client.get_all_workouts(max_workouts=MAX_USER_WORKOUTS_INCREMENTAL)
        else:
            st.info("📥 Full sync: fetching all workouts...")
            workouts_data = client.get_all_workouts(max_workouts=MAX_USER_WORKOUTS_FULL)
        
        workouts = [Workout.from_api_response(w) for w in workouts_data]
        dm.save_workouts(workouts, merge=(last_sync_time > 0))
        sync_results['user_workouts'] = len(workouts)
        st.success(f"✅ Processed {len(workouts)} workouts")
    
    # Get followers
    with st.spinner("Fetching followers..."):
        followers_data = client.get_followers()
        followers = [User.from_api_response(f) for f in followers_data]
        dm.save_followers(followers)
        sync_results['followers'] = len(followers)
        st.success(f"✅ Found {len(followers)} followers")
    
    # Get follower workouts in parallel
    st.info(f"🚀 Fetching follower workouts in parallel ({PARALLEL_WORKERS} concurrent requests)...")
    
    # Determine max workouts per follower based on sync type
    max_workouts_per_follower = MAX_FOLLOWER_WORKOUTS_INCREMENTAL if last_sync_time > 0 else MAX_FOLLOWER_WORKOUTS_FULL
    
    # Function to fetch workouts for a single follower
    def fetch_follower_workouts(follower):
        try:
            workouts_data = client.get_all_user_workouts(
                follower.user_id, 
                max_workouts=max_workouts_per_follower
            )
            workouts = [Workout.from_api_response(w) for w in workouts_data]
            return follower.user_id, follower.username, workouts, None
        except Exception as e:
            return follower.user_id, follower.username, [], str(e)
    
    # Fetch in parallel with progress tracking
    follower_workouts = {}
    progress_bar = st.progress(0)
    status_text = st.empty()
    completed = 0
    
    # Use ThreadPoolExecutor for parallel API calls
    with ThreadPoolExecutor(max_workers=PARALLEL_WORKERS) as executor:
        # Submit all tasks
        future_to_follower = {
            executor.submit(fetch_follower_workouts, f): f 
            for f in followers
        }
        
        # Process completed tasks as they finish
        for future in as_completed(future_to_follower):
            user_id, username, workouts, error = future.result()
            completed += 1
            
            if error:
                status_text.warning(f"⚠️ Error fetching {username}: {error}")
            else:
                follower_workouts[user_id] = workouts
                status_text.text(f"✅ {username}: {len(workouts)} workouts ({completed}/{len(followers)})")
            
            progress_bar.progress(completed / len(followers))
    
    progress_bar.empty()
    status_text.empty()
    
    # Save follower workouts (merge if incremental)
    dm.save_follower_workouts(follower_workouts, merge=(last_sync_time > 0))
    
    # Save sync metadata
    dm.save_sync_metadata(sync_start_time, user.user_id if profile_data else None)
    
    total_follower_workouts = sum(len(w) for w in follower_workouts.values())
    sync_results['follower_workouts'] = total_follower_workouts
    
    # Store sync results in session state for persistent display
    st.session_state.last_sync_results = sync_results
    
    st.success(f"✅ All data synced! {total_follower_workouts} follower workouts from {len(followers)} followers")
    
    # Clear common rides cache to force recalculation
    if 'common_rides' in st.session_state:
        st.session_state.common_rides = []
