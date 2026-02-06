"""
PelotonRacer - Main Page
Virtual race comparison for Peloton rides
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from typing import List, Dict
from datetime import datetime

from src.models.models import User, Workout
from src.services.data_manager import DataManager
from src.services.race_analyzer import RaceAnalyzer
from src.utils.helpers import format_duration, format_iso_date, get_metric_display_name

# Note: Page config is handled by app.py entry point via st.navigation

# Initialize session state
if 'data_manager' not in st.session_state:
    st.session_state.data_manager = DataManager()

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

if 'client' not in st.session_state:
    st.session_state.client = None

if 'common_rides' not in st.session_state:
    st.session_state.common_rides = []

if 'user_map' not in st.session_state:
    st.session_state.user_map = {}

if 'use_mock_data' not in st.session_state:
    st.session_state.use_mock_data = False


def load_common_rides():
    """Load and analyze common rides"""
    dm = st.session_state.data_manager

    user_profile = dm.load_user_profile()
    user_workouts = dm.load_workouts()
    follower_workouts = dm.load_follower_workouts()
    followers = dm.load_followers()

    # Always populate user_map if we have profiles (needed for UI even without workouts)
    if user_profile:
        user_map = {user_profile.user_id: user_profile}
        for follower in (followers or []):
            user_map[follower.user_id] = follower
        st.session_state.user_map = user_map

    if not user_profile or not user_workouts:
        return

    # Find common rides
    common_rides = RaceAnalyzer.find_common_rides(
        user_workouts,
        follower_workouts,
        user_profile.user_id
    )
    st.session_state.common_rides = common_rides


def visualize_metric(workouts: List[Workout], metric: str, users: Dict[str, User], key_suffix: str = "", labels: Dict[str, str] = None):
    """Create a line chart for a specific metric over time"""
    df = RaceAnalyzer.create_time_series_dataframe(workouts, users, metric, labels)

    if df.empty:
        st.warning(f"No time series data available for {get_metric_display_name(metric)}")
        return

    # Create plotly line chart
    fig = go.Figure()

    for username in df['User'].unique():
        user_data = df[df['User'] == username]
        fig.add_trace(go.Scatter(
            x=user_data['Time (seconds)'],
            y=user_data['Value'],
            mode='lines',
            name=username,
            line=dict(width=2)
        ))

    fig.update_layout(
        title=f"{get_metric_display_name(metric)} Over Time",
        xaxis_title="Time (seconds)",
        yaxis_title=get_metric_display_name(metric),
        hovermode='x unified',
        height=500,
        showlegend=True
    )

    st.plotly_chart(fig, use_container_width=True, key=f"chart_{metric}_{key_suffix}")


def build_workout_labels(workouts: List[Workout], username: str, is_you: bool = False) -> List[tuple]:
    """
    Build consistent labels for workouts.

    Args:
        workouts: List of workouts to label
        username: Username to display
        is_you: Whether this is the logged-in user (adds "(You)" suffix)

    Returns:
        List of (workout, label) tuples
    """
    result = []
    name_suffix = " (You)" if is_you else ""

    for i, workout in enumerate(workouts):
        if len(workouts) > 1:
            label = f"{username}{name_suffix} - Ride {i+1}"
        else:
            label = f"{username}{name_suffix}"
        result.append((workout, label))

    return result


def main():
    """Main application"""
    st.title("🚴‍♂️ PelotonRacer")
    st.markdown("Compare your Peloton rides — race against followers or track your own progress!")

    # Use shared sidebar
    from src.utils.sidebar import render_sidebar
    render_sidebar()

    # Main content - require authentication before showing any data
    dm = st.session_state.data_manager

    # Check authentication first
    if not st.session_state.authenticated and not st.session_state.use_mock_data:
        st.info("👈 Please authenticate in the sidebar to get started!")
        return

    if not dm.has_data():
        if st.session_state.use_mock_data:
            st.info("👈 Click 'Load Mock Data' in the sidebar to get started with sample data!")
        else:
            st.info("👈 Please sync your data to get started!")
        return

    # Load data
    if not st.session_state.common_rides:
        load_common_rides()

    user_profile = dm.load_user_profile()
    followers = dm.load_followers()
    user_workouts = dm.load_workouts()
    follower_workouts = dm.load_follower_workouts()
    common_rides = st.session_state.common_rides

    # Calculate repeated rides for the user
    repeated_rides = RaceAnalyzer.find_repeated_rides(user_workouts, user_profile.user_id)

    # Mode selection toggle
    st.header("🎯 Comparison Mode")
    mode = st.radio(
        "What would you like to compare?",
        options=["competitor", "repeated"],
        format_func=lambda x: "🏁 Compare Against Competitor" if x == "competitor" else "🔄 Compare My Repeated Workouts",
        horizontal=True,
        key="comparison_mode"
    )

    # Show appropriate summary based on mode
    if mode == "repeated":
        # Repeated workouts mode
        total_repeated = len(repeated_rides)
        if total_repeated == 0:
            st.warning("⚠️ You haven't taken any rides multiple times yet! Complete the same class more than once to track your progress.")
            return

        total_attempts = sum(len(r.user_workouts.get(user_profile.user_id, [])) for r in repeated_rides)
        st.info(f"📊 You have **{total_repeated}** rides taken multiple times (**{total_attempts}** total attempts)")

        # Show user info (read-only, no selection needed)
        st.header("1️⃣ Your Profile")
        your_name = st.session_state.user_map[user_profile.user_id].username
        st.success(f"🔄 Comparing your own repeated workouts for **{your_name}**")

        # Ride selection - show only repeated rides
        st.header("2️⃣ Select a Ride")

        def get_ride_latest_date(ride):
            timestamps = [w.start_time for w in ride.user_workouts.get(user_profile.user_id, [])]
            return max(timestamps) if timestamps else 0

        # Sort by most recent
        sorted_repeated = sorted(repeated_rides, key=get_ride_latest_date, reverse=True)

        ride_options = []
        for ride in sorted_repeated:
            ride_info = ride.ride_info
            latest_date = get_ride_latest_date(ride)
            date_str = datetime.fromtimestamp(latest_date).strftime('%Y-%m-%d') if latest_date else ""
            attempt_count = len(ride.user_workouts.get(user_profile.user_id, []))
            instructor = ride_info.instructor_name if ride_info.instructor_name else None
            if instructor:
                ride_label = f"{date_str} | {ride_info.title or 'Untitled'} | {instructor} ({format_duration(ride_info.duration)}) [Taken {attempt_count}x]"
            else:
                ride_label = f"{date_str} | {ride_info.title or 'Untitled'} ({format_duration(ride_info.duration)}) [Taken {attempt_count}x]"
            ride_options.append(ride_label)

        selected_ride_idx = st.selectbox(
            "Choose a ride to analyze your progress:",
            range(len(ride_options)),
            format_func=lambda i: ride_options[i],
            key="repeated_ride_select"
        )

        selected_ride = sorted_repeated[selected_ride_idx]
        your_workouts = selected_ride.user_workouts[user_profile.user_id]

        # Show attempt count
        st.info(f"You took this ride **{len(your_workouts)}** time(s)")

        # Sort workouts by date (oldest first to show progression)
        sorted_workouts = sorted(your_workouts, key=lambda w: w.start_time or 0)

        # Build labels using common helper function
        labeled_workouts = build_workout_labels(sorted_workouts, your_name, is_you=True)

        # Create workout list and label map for visualization
        selected_workouts = [w[0] for w in labeled_workouts]
        workout_labels = {w[0].workout_id: w[1] for w in labeled_workouts}

    else:
        # Competitor mode (existing behavior)
        if not followers:
            st.warning("No followers found. Please sync your data first.")
            return

        # Build a map of follower_id -> count of common rides with you
        common_ride_counts = {}
        for follower in followers:
            count = 0
            for ride in common_rides:
                if user_profile.user_id in ride.user_workouts and follower.user_id in ride.user_workouts:
                    count += 1
            common_ride_counts[follower.user_id] = count

        # Sort followers alphabetically by username (case-insensitive)
        sorted_followers = sorted(followers, key=lambda f: f.username.lower() if f.username else "")

        # Show summary
        total_common = len(common_rides)
        followers_with_common = sum(1 for c in common_ride_counts.values() if c > 0)
        st.info(f"📊 You have **{total_common}** total common rides with **{followers_with_common}** of your **{len(followers)}** followers")

        # First: Select Competitor (single selection) - show ALL followers
        st.header("1️⃣ Select a Competitor")

        # Build user labels with common ride count
        def get_follower_label(follower_id):
            follower = st.session_state.user_map.get(follower_id)
            username = follower.username if follower else follower_id
            count = common_ride_counts.get(follower_id, 0)
            if count > 0:
                return f"{username} ({count} common rides)"
            else:
                return f"{username} (no common rides)"

        user_labels = {f.user_id: get_follower_label(f.user_id) for f in sorted_followers}
        user_labels[user_profile.user_id] = f"{st.session_state.user_map[user_profile.user_id].username} (You)"

        # Single competitor selection - show ALL followers
        selected_competitor = st.selectbox(
            "Choose a follower to race against:",
            [f.user_id for f in sorted_followers],
            format_func=lambda uid: user_labels[uid],
            key="competitor_select"
        )

        # Check if there are common rides with this competitor
        competitor_common_count = common_ride_counts.get(selected_competitor, 0)
        competitor_name = st.session_state.user_map.get(selected_competitor).username if st.session_state.user_map.get(selected_competitor) else selected_competitor

        if competitor_common_count == 0:
            st.warning(f"⚠️ You and **{competitor_name}** haven't taken any of the same classes yet!")
            st.info("Try selecting a different competitor, or take some classes together!")
            return

        st.success(f"🏁 Racing: **{st.session_state.user_map[user_profile.user_id].username}** vs **{competitor_name}** — **{competitor_common_count}** common rides!")

        # Filter rides to only those where BOTH you and the competitor participated
        filtered_rides = []
        for ride in common_rides:
            ride_participants = set(ride.user_workouts.keys())
            if user_profile.user_id in ride_participants and selected_competitor in ride_participants:
                filtered_rides.append(ride)

        # Sort rides by workout date (most recent first)
        def get_ride_latest_date(ride):
            timestamps = []
            for workouts in ride.user_workouts.values():
                for w in workouts:
                    timestamps.append(w.start_time)
            return max(timestamps) if timestamps else 0

        filtered_rides = sorted(filtered_rides, key=get_ride_latest_date, reverse=True)

        # Second: Ride selection (filtered by selected competitor)
        st.header("2️⃣ Select a Ride")

        ride_options = []
        for ride in filtered_rides:
            ride_info = ride.ride_info
            latest_date = get_ride_latest_date(ride)
            date_str = datetime.fromtimestamp(latest_date).strftime('%Y-%m-%d') if latest_date else ""
            your_attempts = len(ride.user_workouts.get(user_profile.user_id, []))
            their_attempts = len(ride.user_workouts.get(selected_competitor, []))
            instructor = ride_info.instructor_name if ride_info.instructor_name else None
            if instructor:
                ride_label = f"{date_str} | {ride_info.title or 'Untitled'} | {instructor} ({format_duration(ride_info.duration)}) [You: {your_attempts}x, Them: {their_attempts}x]"
            else:
                ride_label = f"{date_str} | {ride_info.title or 'Untitled'} ({format_duration(ride_info.duration)}) [You: {your_attempts}x, Them: {their_attempts}x]"
            ride_options.append(ride_label)

        selected_ride_idx = st.selectbox(
            "Choose a ride to analyze:",
            range(len(ride_options)),
            format_func=lambda i: ride_options[i],
            key=f"ride_select_{selected_competitor}"
        )

        selected_ride = filtered_rides[selected_ride_idx]
        your_workouts = selected_ride.user_workouts[user_profile.user_id]
        competitor_workouts = selected_ride.user_workouts[selected_competitor]

        your_name = st.session_state.user_map[user_profile.user_id].username
        their_name = st.session_state.user_map.get(selected_competitor).username if st.session_state.user_map.get(selected_competitor) else selected_competitor

        st.info(f"You took this ride **{len(your_workouts)}** time(s), **{their_name}** took it **{len(competitor_workouts)}** time(s)")

        # Build labels using common helper function
        your_labeled = build_workout_labels(your_workouts, your_name, is_you=True)
        their_labeled = build_workout_labels(competitor_workouts, their_name, is_you=False)

        # Combine all workouts
        all_labeled = your_labeled + their_labeled

        selected_workouts = [w[0] for w in all_labeled]
        workout_labels = {w[0].workout_id: w[1] for w in all_labeled}

    # Fetch detailed performance data if needed (only for real API mode)
    if not st.session_state.use_mock_data:
        client = st.session_state.client
        if client and any(not w.performance_metrics for w in selected_workouts):
            with st.spinner("Fetching detailed performance data..."):
                for workout in selected_workouts:
                    if not workout.performance_metrics:
                        perf_data = client.get_workout_performance(workout.workout_id)
                        if perf_data:
                            # Update workout with both metrics and summaries from performance_graph
                            workout.update_from_performance_data(perf_data)

    # Display comparison
    st.header("🏁 Virtual Race Comparison")

    # Summary statistics
    st.subheader("Summary Statistics")
    summary_df = RaceAnalyzer.create_comparison_dataframe(selected_workouts, st.session_state.user_map, workout_labels)

    # Check if metrics are missing (all zeros)
    metrics_missing = summary_df["Total Output (kJ)"].sum() == 0 and summary_df["Avg Output (W)"].sum() == 0
    if metrics_missing:
        st.warning("⚠️ Summary metrics are missing for these workouts. Try running a **Full Sync** to fetch updated data from Peloton.")

    st.dataframe(summary_df, use_container_width=True, hide_index=True)

    # Rankings
    col1, col2, col3 = st.columns(3)

    rankings_output = RaceAnalyzer.calculate_rankings(selected_workouts, "total_output", workout_labels)
    rankings_avg = RaceAnalyzer.calculate_rankings(selected_workouts, "avg_output", workout_labels)
    rankings_hr = RaceAnalyzer.calculate_rankings(selected_workouts, "avg_heart_rate", workout_labels)

    with col1:
        st.metric("🥇 Total Output Leader", rankings_output[0][0] if rankings_output else "N/A")

    with col2:
        st.metric("💪 Avg Output Leader", rankings_avg[0][0] if rankings_avg else "N/A")

    with col3:
        st.metric("❤️ Avg Heart Rate Leader", rankings_hr[0][0] if rankings_hr else "N/A")

    # Time series visualizations
    st.subheader("Performance Over Time")

    # Note: distance is not available as time-series from Peloton API (only as summary total)
    metrics = ["output", "cadence", "resistance", "heart_rate", "speed"]

    for metric in metrics:
        with st.expander(f"📊 {get_metric_display_name(metric)}", expanded=(metric == "output")):
            visualize_metric(selected_workouts, metric, st.session_state.user_map, key_suffix="expander", labels=workout_labels)


# Called via st.navigation from app.py
main()
