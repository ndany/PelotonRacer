"""
Data Load Status Page
Shows detailed sync status and statistics for all data entities
"""

import streamlit as st
import os
from dotenv import load_dotenv
from datetime import datetime
import pandas as pd

from src.services.data_manager import DataManager
from src.services.race_analyzer import RaceAnalyzer

# Load environment variables
load_dotenv()

# Page config
st.set_page_config(
    page_title="Data Load Status - PelotonRacer",
    page_icon="📊",
    layout="wide"
)

# Hide the default Streamlit page navigation in sidebar
st.markdown("""
<style>
    [data-testid="stSidebarNav"] {
        display: none;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'data_manager' not in st.session_state:
    st.session_state.data_manager = DataManager()

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

if 'use_mock_data' not in st.session_state:
    st.session_state.use_mock_data = False


def get_followers_and_workouts_stats():
    """Get combined statistics for followers and their workouts including common rides"""
    dm = st.session_state.data_manager
    
    user_profile = dm.load_user_profile()
    followers = dm.load_followers()
    user_workouts = dm.load_workouts()  # Cycling + valid only (default)
    follower_workouts = dm.load_follower_workouts()  # Cycling + valid only (default)
    
    # Load raw data to get total counts (all workouts including invalid)
    raw_user_workouts = dm.load_workouts(fitness_discipline=None, valid_only=False)
    raw_follower_workouts = dm.load_follower_workouts(fitness_discipline=None, valid_only=False)
    
    if not followers and not user_profile:
        return None
    
    # Calculate common rides if we have enough data
    common_rides = []
    if user_profile and user_workouts and follower_workouts:
        common_rides = RaceAnalyzer.find_common_rides(
            user_workouts,
            follower_workouts,
            user_profile.user_id
        )
    
    # Build per-user stats
    user_stats = []
    
    # Add logged-in user first
    if user_profile:
        user_total_raw = len(raw_user_workouts) if raw_user_workouts else 0
        user_cycling = len(user_workouts) if user_workouts else 0
        
        # Count unique rides the user has taken (for matching with themselves - N/A)
        user_stats.append({
            "Username": f"⭐ {user_profile.username} (You)",
            "Total Workouts": user_total_raw,
            "Cycling Workouts": user_cycling,
            "Common Rides": -1  # Special marker for self (will display as —)
        })
    
    # Add followers (sorted alphabetically)
    if followers:
        sorted_followers = sorted(followers, key=lambda f: f.username.lower() if f.username else "")
        
        for follower in sorted_followers:
            # Get raw workout count (all workouts including invalid)
            raw_workouts = raw_follower_workouts.get(follower.user_id, [])
            total_raw = len(raw_workouts)
            
            # Get cycling workout count (valid only)
            cycling_workouts = follower_workouts.get(follower.user_id, [])
            cycling_count = len(cycling_workouts)
            
            # Count common rides with logged-in user
            common_count = 0
            if user_profile:
                for ride in common_rides:
                    if user_profile.user_id in ride.user_workouts and follower.user_id in ride.user_workouts:
                        common_count += 1
            
            user_stats.append({
                "Username": follower.username,
                "Total Workouts": total_raw,
                "Cycling Workouts": cycling_count,
                "Common Rides": common_count
            })
    
    return {
        "stats": user_stats,
        "total_followers": len(followers) if followers else 0,
        "total_with_workouts": len([s for s in user_stats if s["Total Workouts"] > 0]) - (1 if user_profile else 0)  # Exclude user from count
    }


def get_user_workout_stats():
    """Get workout statistics for logged-in user"""
    dm = st.session_state.data_manager
    
    user_workouts = dm.load_workouts()  # Cycling + valid only (default)
    raw_workouts = dm.load_workouts(fitness_discipline=None, valid_only=False)  # All workouts including invalid
    
    if not raw_workouts:
        return None
    
    total_raw = len(raw_workouts)
    cycling_count = len(user_workouts) if user_workouts else 0
    other_count = total_raw - cycling_count
    
    # Get date range
    dates = [w.start_time for w in raw_workouts if w.start_time]
    if dates:
        oldest = datetime.fromtimestamp(min(dates)).strftime('%Y-%m-%d')
        newest = datetime.fromtimestamp(max(dates)).strftime('%Y-%m-%d')
        date_range = f"{oldest} to {newest}"
    else:
        date_range = "N/A"
    
    return {
        "Total": total_raw,
        "Cycling": cycling_count,
        "Other": other_count,
        "Date Range": date_range
    }


def main():
    # Use shared sidebar
    from src.utils.sidebar import render_sidebar
    render_sidebar()
    
    st.title("📊 Data Load Status")
    st.markdown("View detailed statistics about loaded data")
    
    # Check authentication first - require auth before showing any data
    if not st.session_state.authenticated and not st.session_state.use_mock_data:
        st.info("👈 Please authenticate in the sidebar to view data load status.")
        return
    
    # Last sync time in main area
    dm = st.session_state.data_manager
    last_sync = dm.get_last_sync_time()
    
    if last_sync > 0:
        last_sync_str = datetime.fromtimestamp(last_sync).strftime('%Y-%m-%d %H:%M:%S')
        st.info(f"🕐 **Last Sync:** {last_sync_str}")
    else:
        st.warning("⚠️ No sync has been performed yet")
    
    # Auto-refresh toggle
    auto_refresh = st.toggle("🔄 Auto-refresh (every 5 seconds)", value=False)
    if auto_refresh:
        import time
        time.sleep(5)
        st.rerun()
    
    st.divider()
    
    # User Profile Section
    st.header("👤 User Profile")
    user_profile = dm.load_user_profile()
    if user_profile:
        col1, col2 = st.columns(2)
        col1.write(f"**Username:** {user_profile.username}")
        col2.write(f"**User ID:** {user_profile.user_id}")
    else:
        st.warning("User profile not loaded")
    
    st.divider()
    
    # Your Workouts Section
    st.header("🚴 Your Workouts")
    workout_stats = get_user_workout_stats()
    if workout_stats:
        # Date range first (matching Username/User ID styling)
        st.write(f"**Date Range:** {workout_stats['Date Range']}")
        
        # Then the stats
        col1, col2, col3 = st.columns(3)
        col1.metric("Total", workout_stats["Total"])
        col2.metric("Cycling", workout_stats["Cycling"])
        col3.metric("Other", workout_stats["Other"])
    else:
        st.warning("Workouts not loaded")
    
    st.divider()
    
    # Followers and Workouts Section (combined)
    st.header("👥 Followers and Workouts")
    
    fw_stats = get_followers_and_workouts_stats()
    if fw_stats:
        col1, col2 = st.columns(2)
        col1.metric("Total Followers", fw_stats["total_followers"])
        col2.metric("Followers with Workouts", fw_stats["total_with_workouts"])
        
        # Display table
        if fw_stats["stats"]:
            df = pd.DataFrame(fw_stats["stats"])
            
            # Replace -1 with None for proper display while keeping numeric sorting
            # Use a large negative number for "self" so it stays at top when sorting
            df_display = df.copy()
            df_display["Common Rides"] = df_display["Common Rides"].replace(-1, None)
            
            # Style the dataframe for full visibility
            st.dataframe(
                df_display,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Username": st.column_config.TextColumn("Username", width="medium"),
                    "Total Workouts": st.column_config.NumberColumn("Total Workouts", width="small"),
                    "Cycling Workouts": st.column_config.NumberColumn("Cycling Workouts", width="small"),
                    "Common Rides": st.column_config.NumberColumn("Common Rides", width="small", format="%d"),
                }
            )
        else:
            st.info("No followers loaded yet")
    else:
        st.warning("No data loaded. Please authenticate and sync first.")


if __name__ == "__main__":
    main()
