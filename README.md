# PelotonRacer 🚴‍♂️

A web application that creates virtual races by comparing your Peloton cycling statistics with your followers who took the same rides.  You can also track your own progress by comparing rides you've taken multiple times.

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![Streamlit](https://img.shields.io/badge/streamlit-1.29+-red.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Features

- **🔄 Data Sync**: Fetches your workouts and your followers' workouts from Peloton API
  - **Quick Sync**: Fetches 500 most recent workouts per user (~55 seconds)
  - **Full Sync**: Fetches up to 3000 workouts per user (~2 minutes)
  - Parallel fetching for faster sync (5 concurrent requests)
  - Filters for cycling workouts only
- **🎯 Two Comparison Modes**:
  - **Compare Against Competitor**: Race against followers on common rides
  - **Compare Repeated Workouts**: Track your own progress on rides you've taken multiple times
- **👥 Competitor Selection**: Browse all followers alphabetically with common ride counts
- **🏁 Virtual Race Visualization**: Compare performance metrics over time:
  - Output (watts)
  - Cadence (RPM)
  - Resistance (%)
  - Heart rate (BPM)
  - Speed
- **📊 Summary Statistics**: Side-by-side comparison table with rankings
- **🎲 Mock Data Mode**: Test the app without Peloton credentials

## Screenshots

*Coming soon*

## Installation

### Prerequisites

- Python 3.10 or higher
- A Peloton account with followers

### Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/<your-username>/PelotonRacer.git
   cd PelotonRacer
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Peloton credentials (optional):**
   ```bash
   cp .env.example .env
   ```
   
   You can optionally add a Bearer Token for debugging purposes:
   
   ```env
   PELOTON_BEARER_TOKEN=eyJ...your_token_here
   ```
   
   However, the **recommended method** is to use the in-app login form with your Peloton email and password.

## Authentication

### Option 1: In-App Login (Recommended)

Simply enter your Peloton username/email and password in the sidebar login form. The app uses Peloton's OAuth flow to authenticate securely - your credentials are sent directly to Peloton's servers only, and is never stored.

### Option 2: Bearer Token (Advanced/Debug)

Bearer token login is available in **Diagnostic Mode** only. First enable it in `.env`:

```env
DIAGNOSTIC_MODE=true
```

Then expand "Advanced Login" in the Developer Tools section:

1. Log into [members.onepeloton.com](https://members.onepeloton.com) in your browser
2. Open Developer Tools (F12)
3. Go to the **Network** tab
4. Click any request to `api.onepeloton.com`
5. In the **Headers** section, find `Authorization: Bearer eyJ...`
6. Copy everything **after** "Bearer " and paste into the Manual Token Entry field, or save to `.env` as `PELOTON_BEARER_TOKEN`

## Usage

1. **Start the application:**
   ```bash
   streamlit run app.py
   ```

2. **Open your browser** to `http://localhost:8501`

3. **Sync your data:**
   - Enter your Peloton email and password in the sidebar
   - Click "Login" to authenticate
   - Click "Quick Sync" or "Full Sync" to fetch workout data

4. **Start racing:**
   - Choose a comparison mode:
     - **Compare Against Competitor**: Race against a follower on common rides
     - **Compare Repeated Workouts**: Track your progress on rides you've taken multiple times
   - Select a competitor (or view your own profile for repeated workouts)
   - Choose a ride
   - View the comparison statistics and charts

## Project Structure

```
PelotonRacer/
├── app.py                        # Streamlit app entry point
├── views/                        # Streamlit pages
│   ├── main.py                   # Main race comparison page
│   └── data_load_status.py       # Data loading statistics
├── src/                          # Application source code
│   ├── config.py                 # Centralized configuration
│   ├── api/
│   │   └── peloton_client.py     # Peloton API wrapper (reusable)
│   ├── auth/
│   │   └── peloton_auth.py       # OAuth PKCE authentication
│   ├── models/
│   │   └── models.py             # Data models (User, Workout, etc.)
│   ├── services/
│   │   ├── data_manager.py       # JSON file storage operations
│   │   └── race_analyzer.py      # Race comparison & analysis logic
│   └── utils/
│       ├── helpers.py            # Formatting utilities
│       ├── mock_data.py          # Test data generator
│       └── sidebar.py            # Shared sidebar component
├── tests/                        # Test suite (307 tests)
│   ├── conftest.py               # Shared fixtures
│   ├── test_data_manager.py
│   ├── test_models.py
│   ├── test_peloton_auth.py
│   ├── test_peloton_client.py
│   ├── test_race_analyzer.py
│   └── test_smoke.py
├── scripts/                      # Automation scripts
│   ├── run_security_audit.sh     # Security audit runner
│   ├── generate_security_reports.py  # Analytical audit reports
│   ├── validate_security_setup.sh    # Security tool validation
│   └── generate_coverage_report.sh   # Test coverage reports
├── docs/
│   ├── security/                 # Security documentation & audits
│   │   ├── README.md             # Security docs index
│   │   ├── QUICK_REFERENCE.md    # One-page security tools reference
│   │   ├── SECURITY_SETUP.md     # Security tool setup guide
│   │   ├── SECURITY_PROCEDURES.md  # Incident response & procedures
│   │   ├── SECURITY_SUMMARY.md   # Setup summary
│   │   └── audits/               # Generated audit reports (gitignored)
│   └── testing/                  # Testing documentation
│       └── TESTING.md            # Testing guide
├── data/                         # Local JSON storage (gitignored)
├── requirements.txt              # Python dependencies
├── requirements-security.txt     # Security tool dependencies
├── pytest.ini                    # Test configuration & markers
├── SECURITY.md                   # Security policy
├── SECURITY_QUICKSTART.md        # Quick security setup guide
├── .env.example                  # Template for environment variables
├── .pre-commit-config.yaml       # Pre-commit hooks config
├── .github/workflows/
│   └── security-scan.yml         # CI security scanning
└── CLAUDE.md                     # AI assistant guidance
```

## Configuration

### Environment Variables (`.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `PELOTON_BEARER_TOKEN` | - | Optional bearer token for debug login |
| `DIAGNOSTIC_MODE` | `false` | Show Developer Tools (Advanced Login, Mock Data) |

### Sync Settings (`src/config.py`)

| Setting | Default | Description |
|---------|---------|-------------|
| `API_PAGE_SIZE` | 100 | Peloton API max items per page |
| `MAX_USER_WORKOUTS_FULL` | 3000 | Full sync: max workouts for user |
| `MAX_USER_WORKOUTS_INCREMENTAL` | 500 | Quick sync: max workouts for user |
| `MAX_FOLLOWER_WORKOUTS_FULL` | 3000 | Full sync: max workouts per follower |
| `MAX_FOLLOWER_WORKOUTS_INCREMENTAL` | 500 | Quick sync: max workouts per follower |
| `PARALLEL_WORKERS` | 5 | Concurrent API requests |

## API Reusability

The `PelotonClient` class in `src/api/peloton_client.py` is designed to be reusable for other Peloton projects:

```python
from src.api.peloton_client import PelotonClient

client = PelotonClient(bearer_token="your_token")
client.authenticate()

# Get user profile
profile = client.get_user_profile()

# Get cycling workouts (paginated)
workouts = client.get_all_workouts(max_workouts=500, fitness_discipline="cycling")

# Get followers
followers = client.get_followers()
```

## Testing

PelotonRacer includes a comprehensive test suite with 307 automated tests covering unit, integration, and security testing.

### Run Tests

```bash
# Run all tests with coverage report
pytest tests/ -v --cov=src --cov-report=term-missing

# Run tests without coverage (faster)
pytest tests/ -v

# Run specific test categories
pytest tests/ -m unit -v           # Unit tests only
pytest tests/ -m integration -v    # Integration tests only
pytest tests/ -m "not slow" -v     # Skip slow tests
```

### Test Coverage

- **Overall Coverage:** 97%
- **Core Services:** 95-98% (Data Manager, Race Analyzer, Models)
- **Authentication:** 99-100% (API Client, OAuth)
- **Security Tests:** 42 security-marked tests
- **Total Tests:** 307 (100% passing)

### Documentation

- **Testing Guide:** [docs/testing/TESTING.md](docs/testing/TESTING.md) - Complete guide to writing and running tests
- **Test Infrastructure:** [tests/README.md](tests/README.md) - Test organization and fixtures
- **Coverage Reports:** Run `bash scripts/generate_coverage_report.sh` and open `htmlcov/index.html`

## Security

This project includes automated security monitoring with pre-commit hooks, CI/CD scanning, and a comprehensive security test suite.

- **Security Policy:** [SECURITY.md](SECURITY.md)
- **Quick Setup:** [SECURITY_QUICKSTART.md](SECURITY_QUICKSTART.md)
- **Full Documentation:** [docs/security/README.md](docs/security/README.md)
- **Run Audit:** `./scripts/run_security_audit.sh --report`

For security concerns or to report vulnerabilities, please use GitHub's private vulnerability reporting.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

**Before contributing:**
- Run the test suite: `pytest tests/ -v`
- Ensure tests pass and coverage doesn't decrease
- Follow existing code style and patterns
- Add tests for new features

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This project is not affiliated with, endorsed by, or connected to Peloton Interactive, Inc. Use at your own risk and in accordance with Peloton's Terms of Service.

## Architecture

The backend services in `src/` are framework-agnostic and can be reused with other frontends. Data is stored locally in JSON format.
