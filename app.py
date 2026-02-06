"""
PelotonRacer - Streamlit Application Entry Point
Virtual race comparison for Peloton rides
"""

import streamlit as st

from src.services.data_manager import DataManager

# Page config - must be first Streamlit command
st.set_page_config(
    page_title="PelotonRacer",
    page_icon="🚴‍♂️",
    layout="wide"
)

# Initialize session state (shared across all pages)
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

# Use st.navigation with views/ directory (not pages/) to prevent Streamlit's
# auto-discovery of pages/ which causes a flash of default navigation at startup
pg = st.navigation(
    [
        st.Page("views/main.py", title="Main Page", icon="🏠"),
        st.Page("views/data_load_status.py", title="Data Load Stats", icon="📊"),
    ],
    position="hidden"
)
pg.run()
