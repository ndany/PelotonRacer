# PelotonRacer 🚴‍♂️

A web application that creates virtual races by comparing your Peloton cycling statistics with your followers who took the same rides.

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![Streamlit](https://img.shields.io/badge/streamlit-1.29+-red.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Features

- **🔄 Data Sync**: Fetches your workouts and your followers' workouts from Peloton API
  - Parallel fetching for faster sync (5 concurrent requests)
  - Incremental sync support - only fetch new data
  - Filters for cycling workouts only
- **🎯 Common Rides**: Identifies rides taken by both you and your followers
- **👥 Competitor Selection**: Browse all followers alphabetically with common ride counts
- **🏁 Virtual Race Visualization**: Compare performance metrics over time:
  - Output (watts)
  - Cadence (RPM)
  - Resistance (%)
  - Heart rate (BPM)
  - Speed & Distance
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

4. **Configure Peloton credentials:**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` and add your Peloton authentication. The recommended method is using a Bearer Token:
   
   ```env
   PELOTON_BEARER_TOKEN=eyJ...your_token_here
   ```

### Getting Your Bearer Token (Recommended)

1. Log into [members.onepeloton.com](https://members.onepeloton.com) in your browser
2. Open Developer Tools (F12)
3. Go to the **Network** tab
4. Click any request to `api.onepeloton.com`
5. In the **Headers** section, find `Authorization: Bearer eyJ...`
6. Copy everything **after** "Bearer " to your `.env` file

## Usage

1. **Start the application:**
   ```bash
   streamlit run app.py
   ```

2. **Open your browser** to `http://localhost:8501`

3. **Sync your data:**
   - Toggle off "Use Mock Data" in the sidebar
   - Click "Authenticate" then "Full Sync"
   - Wait for all workout data to be fetched

4. **Start racing:**
   - Select a competitor from the dropdown
   - Choose a common ride
   - View the comparison statistics and charts

## Project Structure

```
PelotonRacer/
├── app.py                       # Streamlit UI application
├── requirements.txt             # Python dependencies
├── .env.example                 # Template for environment variables
├── .gitignore
├── README.md
├── data/                        # Local JSON storage (git-ignored)
│   ├── user_profile.json
│   ├── workouts.json
│   ├── followers.json
│   ├── follower_workouts.json
│   └── sync_metadata.json
└── src/
    ├── config.py                # Centralized configuration
    ├── api/
    │   └── peloton_client.py    # Peloton API wrapper (reusable)
    ├── models/
    │   └── models.py            # Data models (User, Workout, etc.)
    ├── services/
    │   ├── data_manager.py      # JSON file storage operations
    │   └── race_analyzer.py     # Race comparison & analysis logic
    └── utils/
        ├── helpers.py           # Formatting utilities
        └── mock_data.py         # Test data generator
```

## Configuration

Key settings in `src/config.py`:

| Setting | Default | Description |
|---------|---------|-------------|
| `API_PAGE_SIZE` | 100 | Peloton API max items per page |
| `MAX_USER_WORKOUTS_FULL` | 3000 | Max workouts to fetch for user |
| `MAX_FOLLOWER_WORKOUTS_FULL` | 2000 | Max workouts per follower |
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

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This project is not affiliated with, endorsed by, or connected to Peloton Interactive, Inc. Use at your own risk and in accordance with Peloton's Terms of Service.

## Architecture

The backend services are designed to be framework-agnostic and can be reused with other frontends (e.g., iOS app).

## Note

This is a prototype application. Data is stored locally in JSON format.
