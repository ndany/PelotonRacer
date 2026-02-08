# PelotonRacer Test Suite

This directory contains the automated test suite for PelotonRacer, built with pytest.

## Quick Start

### Install Testing Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- `pytest` - Testing framework
- `pytest-cov` - Coverage reporting
- `pytest-mock` - Enhanced mocking utilities
- `responses` - HTTP mocking for API tests

### Run All Tests

```bash
# Run all tests with coverage
pytest tests/ -v --cov=src

# Run tests without coverage (faster)
pytest tests/ -v

# Run with detailed output
pytest tests/ -vv
```

### Run Specific Test Files

```bash
# Run only smoke tests
pytest tests/test_smoke.py -v

# Run authentication tests (when implemented)
pytest tests/test_auth.py -v

# Run data manager tests (when implemented)
pytest tests/test_data_manager.py -v
```

### Run Tests by Marker

Tests are organized with markers for selective execution:

```bash
# Run only fast unit tests
pytest tests/ -m unit

# Run only integration tests
pytest tests/ -m integration

# Run only API tests
pytest tests/ -m api

# Skip slow tests
pytest tests/ -m "not slow"
```

## Test Organization

### Directory Structure

```
tests/
├── __init__.py              # Test package initialization
├── conftest.py              # Shared fixtures and test configuration
├── test_smoke.py            # Infrastructure smoke tests
├── test_auth.py             # Authentication tests (Issue #13)
├── test_data_manager.py     # Data persistence tests (Issue #14)
├── test_race_analyzer.py    # Race analysis tests (Issue #15)
└── test_models.py           # Data model tests (Issue #16)
```

### Test Markers

The test suite uses pytest markers to organize tests:

- `@pytest.mark.unit` - Fast unit tests with no external dependencies
- `@pytest.mark.integration` - Integration tests that may use external services
- `@pytest.mark.slow` - Tests that take more than a few seconds
- `@pytest.mark.api` - Tests that interact with Peloton API (mocked or real)

Example:
```python
@pytest.mark.unit
def test_user_creation():
    user = User(user_id="123", username="test")
    assert user.user_id == "123"
```

## Shared Fixtures

The `conftest.py` file provides reusable fixtures for all tests. These fixtures eliminate repetitive test setup code.

### Data Model Fixtures

Create pre-configured test data:

- `sample_user` - Single User object
- `sample_follower` - Single follower User object
- `sample_followers` - List of follower Users
- `sample_ride_info` - RideInfo object
- `sample_performance_metrics` - PerformanceMetrics with time series
- `sample_workout` - Complete Workout object
- `sample_workouts` - List of Workout objects
- `invalid_ride_info` - Invalid RideInfo for testing validation

Example usage:
```python
def test_user_serialization(sample_user):
    """Use fixture to get pre-made user"""
    user_dict = sample_user.to_dict()
    assert user_dict["username"] == "testuser"
```

### API Mocking Fixtures

Mock Peloton API responses:

- `mock_peloton_client` - Mock PelotonClient with stubbed methods
- `mock_api_user_response` - Mock user profile API response
- `mock_api_workout_response` - Mock workout API response
- `mock_api_performance_response` - Mock performance graph response
- `mock_api_followers_response` - Mock followers API response

Example usage:
```python
def test_authentication(mock_peloton_client):
    """Test auth without real API call"""
    assert mock_peloton_client.authenticate() is True
    assert mock_peloton_client.user_id == "user123"
```

### File System Fixtures

Provide isolated temporary directories:

- `temp_data_dir` - Empty temporary directory (auto-cleaned)
- `data_manager_with_temp_dir` - DataManager with temp directory
- `populated_data_dir` - Pre-populated temp directory with test data

Example usage:
```python
def test_save_data(data_manager_with_temp_dir, sample_user):
    """Test file operations in isolated directory"""
    manager = data_manager_with_temp_dir
    manager.save_user_profile(sample_user)
    loaded = manager.load_user_profile()
    assert loaded.user_id == sample_user.user_id
```

### Utility Fixtures

Helper functions for testing:

- `assert_json_equal` - Compare JSON objects (order-independent)
- `mock_responses` - HTTP request mocking library
- `disable_network_calls` - Prevent accidental network requests

Example usage:
```python
def test_json_comparison(assert_json_equal):
    """Compare JSON structures"""
    expected = {"key": "value", "num": 42}
    actual = {"num": 42, "key": "value"}
    assert_json_equal(expected, actual)  # Passes despite order
```

## Writing New Tests

### Test File Template

```python
"""
Tests for [component name]

Description of what this test file covers.
"""

import pytest
from src.module import Component


@pytest.mark.unit
def test_basic_functionality(sample_fixture):
    """
    Test description.

    What it tests and why.
    """
    # Arrange
    component = Component()

    # Act
    result = component.do_something()

    # Assert
    assert result is not None
```

### Best Practices

1. **Use Fixtures**: Leverage shared fixtures instead of duplicating setup code
2. **Mark Tests**: Always add appropriate markers (`@pytest.mark.unit`, etc.)
3. **Descriptive Names**: Use clear test names that describe what is being tested
4. **AAA Pattern**: Structure tests as Arrange, Act, Assert
5. **One Assertion Focus**: Each test should verify one specific behavior
6. **Docstrings**: Add docstrings explaining what the test validates

### Test Isolation

Tests are automatically isolated:
- Each test gets a fresh temporary directory
- Environment variables are reset between tests
- No test should depend on another test's state

### Mocking API Calls

Always mock external API calls to:
- Make tests faster
- Avoid rate limits
- Ensure tests work offline
- Make tests deterministic

Use the provided fixtures:
```python
def test_api_call(mock_peloton_client):
    """Mock API calls for testing"""
    client = mock_peloton_client
    profile = client.get_user_profile()
    # Test logic without real API call
```

## Coverage Reports

### Generate Coverage Report

```bash
# Terminal output
pytest tests/ --cov=src --cov-report=term-missing

# HTML report (opens in browser)
pytest tests/ --cov=src --cov-report=html
open htmlcov/index.html
```

### Coverage Goals

Target coverage by module:
- **Services** (data_manager, race_analyzer): 60%+ coverage
- **Models** (serialization): 80%+ coverage
- **API Client**: 50%+ coverage (many paths need real API)

Focus coverage on:
- Business logic
- Data transformations
- Error handling
- Edge cases

## Continuous Integration

(Future) When CI is configured:

```yaml
# .github/workflows/test.yml
- name: Run tests
  run: |
    pip install -r requirements.txt
    pytest tests/ -v --cov=src --cov-report=xml
```

## Troubleshooting

### Import Errors

If you see `ModuleNotFoundError`:
```bash
# Ensure you're in the project root
cd /path/to/PelotonRacer

# Run pytest from project root
pytest tests/
```

### Fixture Not Found

If pytest can't find a fixture:
1. Ensure `conftest.py` is in `tests/` directory
2. Check fixture name spelling
3. Verify you're running from project root

### Tests Fail on CI But Pass Locally

Common causes:
- Different Python version
- Missing environment variable
- File path assumptions
- Network dependencies not mocked

## Contributing Tests

When adding new tests for issues #13-16:

1. **Use existing fixtures** from `conftest.py`
2. **Add new fixtures** to `conftest.py` if reusable
3. **Mark tests appropriately** with `@pytest.mark.unit` etc.
4. **Run smoke tests first** to ensure infrastructure works:
   ```bash
   pytest tests/test_smoke.py -v
   ```
5. **Check coverage** to identify gaps:
   ```bash
   pytest tests/ --cov=src --cov-report=term-missing
   ```

## Test Issues Roadmap

- [x] **Issue #12**: Test Infrastructure Setup (this setup)
- [ ] **Issue #13**: Authentication Tests (`test_auth.py`)
  - Bearer token validation
  - Session validation
  - Credential authentication
  - Error handling
- [ ] **Issue #14**: Data Manager Tests (`test_data_manager.py`)
  - File operations
  - Data serialization
  - Merge/dedup logic
  - Validation rules
- [ ] **Issue #15**: Race Analyzer Tests (`test_race_analyzer.py`)
  - Common ride detection
  - Repeated ride detection
  - DataFrame generation
  - Statistics calculation
- [ ] **Issue #16**: Model Tests (`test_models.py`)
  - Serialization/deserialization
  - API response parsing
  - Edge cases and validation

## Resources

- [pytest documentation](https://docs.pytest.org/)
- [pytest fixtures](https://docs.pytest.org/en/stable/fixture.html)
- [pytest markers](https://docs.pytest.org/en/stable/mark.html)
- [pytest-cov documentation](https://pytest-cov.readthedocs.io/)
- [responses library](https://github.com/getsentry/responses)
