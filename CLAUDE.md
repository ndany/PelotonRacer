# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PelotonRacer is a Python/Streamlit app that creates virtual races by comparing your Peloton cycling stats with followers who took the same rides. It fetches data from the Peloton API, stores it locally as JSON, and displays interactive comparisons with Plotly charts.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run the app (serves on http://localhost:8501)
streamlit run app.py
```

## Testing

```bash
# Run all tests with coverage
pytest tests/ -v --cov=src --cov-report=term-missing

# Run only security-marked tests
pytest tests/ -m security -v

# Run security audit with report generation
./scripts/run_security_audit.sh --report
```

## Architecture

**Entry point:** `app.py` — Streamlit UI that orchestrates authentication, data syncing, and race visualization.

**Layered backend in `src/`:**

- **`api/peloton_client.py`** — Peloton API wrapper. Supports three auth methods: Bearer token (JWT), session ID, or username/password. Uses browser-like headers to avoid WAF blocks. Designed to be reusable outside this project.
- **`models/models.py`** — Data classes: `User`, `Workout`, `RideInfo`, `PerformanceMetrics`, `CommonRide`. All use dataclasses with `from_dict`/`to_dict` serialization.
- **`services/data_manager.py`** — JSON file persistence in `data/` directory. Handles merge/dedup for incremental syncs.
- **`services/race_analyzer.py`** — Static methods that find common rides between users, build comparison DataFrames, generate rankings, and prepare time-series data for charts.
- **`utils/mock_data.py`** — Generates realistic test data without API credentials (toggled via sidebar).
- **`config.py`** — Constants: API page sizes, workout fetch limits, parallel worker count (5).

**Data flow:** Authenticate → Sync (parallel fetch with ThreadPoolExecutor) → Store as JSON → Analyze common rides → Visualize with Plotly.

## Configuration

Authentication credentials are set via `.env` file (see `.env.example`). Priority: bearer token → session ID → username/password.

Key constants in `src/config.py`: `API_PAGE_SIZE=100`, `MAX_USER_WORKOUTS_FULL=3000`, `PARALLEL_WORKERS=5`.

## Data Storage

JSON files in `data/` (git-ignored): `user_profile.json`, `workouts.json`, `followers.json`, `follower_workouts.json`, `sync_metadata.json`.
