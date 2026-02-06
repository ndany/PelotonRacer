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
    from src.config import (
        MAX_USER_WORKOUTS_FULL,
        MAX_USER_WORKOUTS_INCREMENTAL,
        MAX_FOLLOWER_WORKOUTS_FULL,
        MAX_FOLLOWER_WORKOUTS_INCREMENTAL,
        PARALLEL_WORKERS,
        is_diagnostic_mode
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
    if 'auth_token' not in st.session_state:
        st.session_state.auth_token = None
    if 'sync_in_progress' not in st.session_state:
        st.session_state.sync_in_progress = False
    if 'pending_sync' not in st.session_state:
        st.session_state.pending_sync = None

    # Ensure data directory is set correctly based on current state
    _set_data_directory()

    with st.sidebar:
        # -- 1. Authentication (always visible) --
        st.header("🔐 Authentication")

        if not st.session_state.authenticated:
            _render_login_section()  # Basic login only
        else:
            st.success("✅ Authenticated")
            if st.button("🚪 Logout", use_container_width=True, key="sidebar_logout"):
                _logout()
                st.rerun()

        st.divider()

        # -- 2. Navigation (always visible) --
        st.header("📍 Navigation")
        st.page_link("views/main.py", label="Main Page", icon="🏠")
        st.page_link("views/data_load_status.py", label="Data Load Stats", icon="📊")

        st.divider()

        # -- 3. Data Management (always visible) --
        st.header("📂 Data Management")

        last_sync = st.session_state.data_manager.get_last_sync_time()
        if last_sync > 0:
            last_sync_str = datetime.fromtimestamp(last_sync).strftime('%Y-%m-%d %H:%M')
            st.caption(f"Last sync: {last_sync_str}")

        sync_in_progress = st.session_state.sync_in_progress
        sync_disabled = not st.session_state.authenticated or sync_in_progress
        disabled_tooltip = "Sync in progress..." if sync_in_progress else "Authenticate first"

        st.markdown("**🔄 Sync Data**")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("⚡ Quick", use_container_width=True, help=disabled_tooltip if sync_disabled else "Incremental sync - only new data", key="sidebar_quick_sync", disabled=sync_disabled):
                st.session_state.sync_in_progress = True
                st.session_state.pending_sync = 'quick'
                st.rerun()
        with col2:
            if st.button("📥 Full", use_container_width=True, help=disabled_tooltip if sync_disabled else "Full sync - all historical data", key="sidebar_full_sync", disabled=sync_disabled):
                st.session_state.sync_in_progress = True
                st.session_state.pending_sync = 'full'
                st.rerun()

        # Execute pending sync AFTER buttons are rendered (so they appear disabled during sync)
        if st.session_state.pending_sync is not None:
            pending = st.session_state.pending_sync
            st.session_state.pending_sync = None
            _sync_data(full_sync=(pending == 'full'))
            st.rerun()

        # Show sync details if available
        if 'last_sync_results' in st.session_state:
            results = st.session_state.last_sync_results
            sync_time_str = datetime.fromtimestamp(results['timestamp']).strftime('%H:%M:%S')
            with st.expander("📋 Last Sync Details", expanded=False):
                st.markdown(f"**Type:** {results['sync_type']} Sync")
                st.markdown(f"**Time:** {sync_time_str}")
                if results['username']:
                    st.markdown(f"**User:** {results['username']}")
                st.markdown(f"**Your Workouts:** {results['user_workouts']}")
                st.markdown(f"**Followers:** {results['followers']}")
                st.markdown(f"**Follower Workouts:** {results['follower_workouts']}")

        if st.button("🗑️ Clear All Data", use_container_width=True, key="sidebar_clear_data", disabled=sync_disabled, help=disabled_tooltip if sync_disabled else "Clears synced data. Full sync required after."):
            st.session_state.data_manager.clear_all_data()
            if 'common_rides' in st.session_state:
                st.session_state.common_rides = []
            if 'last_sync_results' in st.session_state:
                del st.session_state.last_sync_results
            st.success("Data cleared!")
            st.rerun()

        _render_export_button(disabled=sync_disabled, disabled_tooltip=disabled_tooltip)

        # -- 4. Developer Tools (diagnostic mode only) --
        if is_diagnostic_mode():
            st.divider()
            st.header("🔧 Developer Tools")

            # 4a. Advanced Login (inside Developer Tools)
            with st.expander("🔧 Advanced Login", expanded=False):
                bearer_token = os.getenv("PELOTON_BEARER_TOKEN")
                if bearer_token and bearer_token.strip():
                    st.caption("Use bearer token from .env file")
                    if st.button("🔐 Connect with Token", use_container_width=True, key="sidebar_auth_token"):
                        if _authenticate_with_token(bearer_token.strip()):
                            st.rerun()
                st.divider()
                st.caption("Manually enter a bearer token from your browser")
                manual_token = st.text_input("Bearer Token", type="password", key="manual_token", placeholder="eyJ...")
                if st.button("Validate Token", key="validate_manual_token"):
                    if manual_token:
                        if _authenticate_with_token(manual_token.strip()):
                            st.rerun()

            # 4b. Mock data
            st.divider()
            st.subheader("🎲 Mock Data")
            use_mock = st.toggle("Use Mock Data", value=st.session_state.use_mock_data, key="sidebar_mock_toggle")
            if use_mock != st.session_state.use_mock_data:
                st.session_state.use_mock_data = use_mock
                # Clear cached data so page recalculates with correct data source
                _clear_session_caches()
                # Switch data directory based on mode
                _set_data_directory()
                st.rerun()
            if st.session_state.use_mock_data:
                if st.button("🎲 Load Mock Data", use_container_width=True, key="sidebar_load_mock"):
                    _load_mock_data()
                    st.rerun()


def _render_login_section():
    """Render the basic login section (email/password only)"""
    from src.auth.peloton_auth import PelotonAuth, PelotonAuthError

    with st.form("login_form", clear_on_submit=False):
        email = st.text_input("Username/Email", key="login_email", placeholder="your@email.com")
        password = st.text_input("Password", type="password", key="login_password")

        submitted = st.form_submit_button("🚀 Login", use_container_width=True)

        if submitted:
            if not email or not password:
                st.error("Please enter both email and password")
            else:
                with st.spinner("Authenticating with Peloton..."):
                    try:
                        auth = PelotonAuth()
                        token = auth.login(email, password)

                        if _authenticate_with_token(token.access_token):
                            st.session_state.auth_token = token
                            st.success("✅ Login successful!")
                            st.rerun()
                        else:
                            st.error("Token validation failed")
                    except PelotonAuthError as e:
                        st.error(f"❌ {str(e)}")
                    except Exception as e:
                        st.error(f"❌ Authentication failed: {str(e)}")


def _authenticate_with_token(bearer_token: str) -> bool:
    """Authenticate using a bearer token and set up user-specific data directory"""
    from src.api.peloton_client import PelotonClient
    from src.services.data_manager import DataManager
    from src.models.models import User

    with st.spinner("Validating token..."):
        client = PelotonClient(bearer_token=bearer_token)
        if client.authenticate():
            st.session_state.client = client
            st.session_state.authenticated = True

            # Get user profile to determine data directory
            with st.spinner("Loading user profile..."):
                profile_data = client.get_user_profile()
                if profile_data:
                    user = User.from_api_response(profile_data)
                    st.session_state.current_user_id = user.user_id

                    # Set data directory to user-specific path
                    user_data_dir = DataManager.get_user_data_dir(user.user_id)
                    st.session_state.data_manager.set_data_dir(user_data_dir)

                    # Save user profile to the new directory
                    st.session_state.data_manager.save_user_profile(user)

            st.success("✅ Token validated!")
            return True
        else:
            st.error("❌ Token invalid or expired")
            return False


def _logout():
    """Log out and clear authentication state"""
    st.session_state.authenticated = False
    st.session_state.client = None
    st.session_state.auth_token = None
    if 'current_user_id' in st.session_state:
        del st.session_state.current_user_id
    # Clear cached data from pages
    _clear_session_caches()
    # Reset data directory (will be set properly on next login or mock data toggle)
    _set_data_directory()
    st.success("Logged out successfully")


def _set_data_directory():
    """Set the data directory based on current mode (mock vs user)"""
    from src.services.data_manager import DataManager

    dm = st.session_state.data_manager

    if st.session_state.use_mock_data:
        # Mock mode: use mock data directory
        dm.set_data_dir(DataManager.get_mock_data_dir())
    elif st.session_state.authenticated and 'current_user_id' in st.session_state:
        # Authenticated with known user: use user-specific directory
        dm.set_data_dir(DataManager.get_user_data_dir(st.session_state.current_user_id))
    else:
        # Not authenticated or no user ID: use base directory
        dm.set_data_dir(DataManager.BASE_DATA_DIR)


def _clear_session_caches():
    """Clear cached data from session state (used when switching data sources or logging out)"""
    if 'common_rides' in st.session_state:
        st.session_state.common_rides = []
    if 'user_map' in st.session_state:
        st.session_state.user_map = {}
    # Clear widget state for ride/competitor selection dropdowns
    keys_to_clear = [k for k in st.session_state.keys()
                     if k.startswith('ride_select_') or k in ('repeated_ride_select', 'competitor_select', 'comparison_mode')]
    for key in keys_to_clear:
        del st.session_state[key]


def _render_export_button(disabled: bool = False, disabled_tooltip: str = "Authenticate first"):
    """Render export ZIP button for all data files"""
    import zipfile
    import io
    import glob

    # Use the current data directory from the data manager
    data_dir = str(st.session_state.data_manager.data_dir)
    json_files = glob.glob(os.path.join(data_dir, "*.json"))

    enabled_tooltip = "Download synced data"

    if not json_files or disabled:
        # Show disabled tooltip when not authenticated, otherwise indicate no data
        help_text = disabled_tooltip if disabled else "No data to export"
        st.button("📤 Export Data", use_container_width=True, disabled=True, help=help_text, key="sidebar_export_disabled")
        return

    # Build ZIP in memory
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for filepath in json_files:
            zf.write(filepath, os.path.basename(filepath))
    zip_buffer.seek(0)

    st.download_button(
        "📤 Export Data",
        data=zip_buffer,
        file_name="pelotonracer_data.zip",
        mime="application/zip",
        use_container_width=True,
        help=enabled_tooltip,
        key="sidebar_export"
    )


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

    # Note: sync_in_progress flag is set by button handler before rerun
    try:
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

    finally:
        # Always clear sync in progress flag, even if an error occurred
        st.session_state.sync_in_progress = False
