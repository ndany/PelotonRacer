# Diagnostic Mode Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a `DIAGNOSTIC_MODE` toggle that controls which sidebar sections are visible, separating developer tools from the normal user experience.

**Architecture:** A `is_diagnostic_mode()` function in `src/config.py` re-reads `.env` on every call for dynamic detection. The sidebar conditionally renders Developer Tools (advanced login, sync controls, clear data, export ZIP, mock data) based on this flag. No changes to data loading behavior.

**Tech Stack:** Python, Streamlit, python-dotenv, zipfile (stdlib)

**Issue:** #8 (subset of #7)

---

### Task 1: Add `is_diagnostic_mode()` to config

**Files:**
- Modify: `src/config.py`

**Step 1: Add the function**

Add at the top of `src/config.py`, after the docstring:

```python
import os
from dotenv import load_dotenv

def is_diagnostic_mode() -> bool:
    """Check if diagnostic mode is enabled. Re-reads .env for dynamic detection."""
    load_dotenv(override=True)
    return os.getenv("DIAGNOSTIC_MODE", "false").lower() == "true"
```

**Step 2: Verify import works**

Run: `python -c "from src.config import is_diagnostic_mode; print(is_diagnostic_mode())"`
Expected: `False`

**Step 3: Commit**

```bash
git add src/config.py
git commit -m "feat: add is_diagnostic_mode() to config (#8)"
```

---

### Task 2: Update `.env.example` with `DIAGNOSTIC_MODE`

**Files:**
- Modify: `.env.example`

**Step 1: Add the new flag**

Append to the end of `.env.example`:

```env

# Developer/Diagnostic Mode
# Shows Developer Tools section in sidebar (advanced login, sync controls, export, mock data)
# Set to 'true' to enable (detected dynamically, no restart needed)
DIAGNOSTIC_MODE=false
```

**Step 2: Commit**

```bash
git add .env.example
git commit -m "docs: add DIAGNOSTIC_MODE to .env.example (#8)"
```

---

### Task 3: Restructure sidebar — normal mode (basic login + navigation only)

This is the largest task. The sidebar currently renders everything unconditionally. We need to:

1. Keep basic login (email/password form) and navigation always visible
2. Move advanced login, sync controls, clear data into a Developer Tools section gated by `is_diagnostic_mode()`
3. Add export ZIP button inside Developer Tools
4. Add mock data toggle as last item in Developer Tools

**Files:**
- Modify: `src/utils/sidebar.py`

**Step 1: Import `is_diagnostic_mode`**

Add to the imports inside the `render_sidebar()` function (alongside the existing config imports):

```python
from src.config import is_diagnostic_mode
```

**Step 2: Restructure `render_sidebar()` body**

Replace the body of the `with st.sidebar:` block with this structure:

```python
with st.sidebar:
    # -- 1. Authentication (always visible) --
    st.header("🔐 Authentication")

    if not st.session_state.authenticated:
        _render_login_section(show_advanced=is_diagnostic_mode())
    else:
        st.success("✅ Authenticated")
        if st.button("🚪 Logout", use_container_width=True, key="sidebar_logout"):
            _logout()
            st.rerun()

    st.divider()

    # -- 2. Navigation (always visible) --
    st.header("📍 Navigation")
    st.page_link("app.py", label="Main Page", icon="🏠")
    st.page_link("pages/data_load_status.py", label="Data Load Stats", icon="📊")

    # -- 3. Developer Tools (diagnostic mode only) --
    if is_diagnostic_mode():
        st.divider()
        st.header("🔧 Developer Tools")

        # 3a. Sync controls (only when authenticated)
        if st.session_state.authenticated:
            last_sync = st.session_state.data_manager.get_last_sync_time()
            if last_sync > 0:
                last_sync_str = datetime.fromtimestamp(last_sync).strftime('%Y-%m-%d %H:%M')
                st.caption(f"Last sync: {last_sync_str}")

            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔄 Quick Sync", use_container_width=True, help="Incremental sync - only new data", key="sidebar_quick_sync"):
                    _sync_data(full_sync=False)
            with col2:
                if st.button("📥 Full Sync", use_container_width=True, help="Full sync - all historical data", key="sidebar_full_sync"):
                    _sync_data(full_sync=True)

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

        # 3b. Clear all data
        if st.button("🗑️ Clear All Data", use_container_width=True, key="sidebar_clear_data"):
            st.session_state.data_manager.clear_all_data()
            if 'common_rides' in st.session_state:
                st.session_state.common_rides = []
            st.success("Data cleared!")
            st.rerun()

        # 3c. Export data (ZIP)
        _render_export_button()

        # 3d. Mock data (last section)
        st.divider()
        st.subheader("🎲 Mock Data")
        use_mock = st.toggle("Use Mock Data", value=st.session_state.use_mock_data, key="sidebar_mock_toggle")
        if use_mock != st.session_state.use_mock_data:
            st.session_state.use_mock_data = use_mock
            st.rerun()
        if st.session_state.use_mock_data:
            if st.button("🎲 Load Mock Data", use_container_width=True, key="sidebar_load_mock"):
                _load_mock_data()
                st.rerun()
```

**Step 3: Update `_render_login_section()` to accept `show_advanced` parameter**

Change the signature and conditionally show advanced options:

```python
def _render_login_section(show_advanced: bool = False):
    """Render the login section with auth options"""
    from src.auth.peloton_auth import PelotonAuth, PelotonAuthError

    # Primary login: Email/Password form (always visible)
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

    # Advanced options only in diagnostic mode
    if show_advanced:
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
```

**Step 4: Add `_render_export_button()` function**

Add a new private function:

```python
def _render_export_button():
    """Render export ZIP button for all data files"""
    import zipfile
    import io
    import glob

    data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
    json_files = glob.glob(os.path.join(data_dir, "*.json"))

    if not json_files:
        st.button("📤 Export Data", use_container_width=True, disabled=True, help="No data to export", key="sidebar_export_disabled")
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
        key="sidebar_export"
    )
```

**Step 5: Remove the old mock data conditional from the authentication section**

The old code at lines 44-49 handled `st.session_state.use_mock_data` inline in the auth section. This is now handled in the Developer Tools section. Remove that conditional — the auth section should only show login/logout.

**Step 6: Remove the old standalone sync and data management sections**

The old code at lines 70-111 (sync controls + clear data) is now inside the Developer Tools block. Remove these.

**Step 7: Verify the app runs**

Run: `streamlit run app.py`
- With `DIAGNOSTIC_MODE=false` (or unset): should see only basic login + navigation
- With `DIAGNOSTIC_MODE=true`: should see Developer Tools section with all controls

**Step 8: Commit**

```bash
git add src/utils/sidebar.py
git commit -m "feat: restructure sidebar with diagnostic mode gating (#8)"
```

---

### Task 4: Rename "Data Load Status" to "Data Load Stats" in the page

**Files:**
- Modify: `pages/data_load_status.py`

**Step 1: Update the page title**

Change line 20 from:
```python
page_title="Data Load Status - PelotonRacer",
```
to:
```python
page_title="Data Load Stats - PelotonRacer",
```

Change line 157 from:
```python
st.title("📊 Data Load Status")
```
to:
```python
st.title("📊 Data Load Stats")
```

**Step 2: Commit**

```bash
git add pages/data_load_status.py
git commit -m "feat: rename Data Load Status to Data Load Stats (#8)"
```

---

### Task 5: Clean up unused code in `app.py`

**Files:**
- Modify: `app.py`

**Step 1: Remove unused `load_mock_data()` function and its import**

The `load_mock_data()` function (lines 100-114) in `app.py` is never called — mock data loading is handled entirely by the sidebar's `_load_mock_data()`. Remove the function and the unused `MockDataGenerator` import (line 18).

**Step 2: Commit**

```bash
git add app.py
git commit -m "refactor: remove unused load_mock_data from app.py (#8)"
```

---

### Task 6: Smoke test the full flow

**Step 1: Test normal mode**

1. Ensure `.env` has `DIAGNOSTIC_MODE=false` (or the line is absent)
2. Run `streamlit run app.py`
3. Verify sidebar shows: Authentication (email/password only), Navigation (Main Page, Data Load Stats)
4. Verify no sync controls, no clear data, no advanced login, no mock data toggle
5. Click "Data Load Stats" link — verify page title says "Data Load Stats"

**Step 2: Test diagnostic mode**

1. Set `DIAGNOSTIC_MODE=true` in `.env`
2. Interact with the app (click something to trigger rerun — no restart needed)
3. Verify Developer Tools section appears with: sync controls, clear data, export, mock data toggle
4. Verify Advanced Login appears inside the login section
5. Toggle mock data on, click Load Mock Data, verify it works
6. Click Export Data, verify ZIP downloads with JSON files

**Step 3: Test dynamic switching**

1. While app is running with `DIAGNOSTIC_MODE=true`, change `.env` to `false`
2. Click anything in the app
3. Verify Developer Tools section disappears

**Step 4: Final commit (if any fixes needed)**

```bash
git add -A
git commit -m "fix: address smoke test findings (#8)"
```
