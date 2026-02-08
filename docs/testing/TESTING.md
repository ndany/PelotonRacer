# PelotonRacer Testing Guide

**Version:** 1.0
**Last Updated:** February 7, 2026

This comprehensive guide covers all aspects of testing for PelotonRacer, including how to run tests, write new tests, and interpret coverage reports.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Test Infrastructure](#test-infrastructure)
- [Running Tests](#running-tests)
- [Test Organization](#test-organization)
- [Writing New Tests](#writing-new-tests)
- [Coverage Reporting](#coverage-reporting)
- [CI/CD Integration](#cicd-integration)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

### Install Dependencies

```bash
# Install all dependencies including test tools
pip install -r requirements.txt
```

This installs:
- `pytest` - Testing framework
- `pytest-cov` - Coverage reporting
- `pytest-mock` - Enhanced mocking utilities
- `responses` - HTTP request mocking

### Run All Tests

```bash
# Run all tests with coverage report
pytest tests/ -v --cov=src --cov-report=term-missing

# Run tests without coverage (faster)
pytest tests/ -v

# Run with extra detail
pytest tests/ -vv
```

### Check Results

```
========================= test session starts ==========================
collected 196 items

tests/test_smoke.py ✓✓✓✓✓✓✓✓✓✓✓✓✓✓✓✓                            [ 8%]
tests/test_models.py ✓✓✓✓✓✓✓✓✓✓✓✓✓✓✓✓✓✓✓✓✓✓✓✓✓✓...              [55%]
tests/test_data_manager.py ✓✓✓✓✓✓✓✓✓✓✓✓✓✓✓✓✓✓...                [78%]
tests/test_race_analyzer.py ✓✓✓✓✓✓✓✓✓✓✓✓✓✓✓✓...                [92%]
tests/test_peloton_client.py ✓✓✓...                              [100%]

========================= 175 passed, 21 failed in 0.92s ===============
```

---

## Test Infrastructure

### Directory Structure

```
tests/
├── __init__.py              # Makes tests a package
├── conftest.py              # Shared fixtures and configuration
├── README.md                # Test documentation
│
├── test_smoke.py            # Infrastructure smoke tests
├── test_models.py           # Data model tests (45KB)
├── test_data_manager.py     # File persistence tests (31KB)
├── test_race_analyzer.py    # Race analysis tests (36KB)
└── test_peloton_client.py   # API client tests (23KB)
```

**Total:** 196 tests, 163KB of test code

### Key Files

#### `conftest.py` - Shared Test Configuration

Contains all reusable fixtures and test configuration. See [Fixtures](#fixtures) section.

**Key Features:**
- 30+ reusable fixtures
- Mock API responses
- Temporary directory management
- Test data factories

#### `test_smoke.py` - Infrastructure Tests

Quick tests to verify the test infrastructure itself is working.

**Purpose:**
- Verify pytest is configured correctly
- Check fixture availability
- Test marker functionality
- Validate imports

**Run First:**
```bash
pytest tests/test_smoke.py -v
```

---

## Running Tests

### Basic Commands

```bash
# All tests with coverage
pytest tests/ -v --cov=src --cov-report=term-missing

# Fast run (no coverage)
pytest tests/ -v

# Very verbose output
pytest tests/ -vv

# Show print statements
pytest tests/ -v -s

# Stop on first failure
pytest tests/ -v -x

# Run last failed tests only
pytest tests/ --lf

# Run tests in parallel (requires pytest-xdist)
pytest tests/ -n auto
```

### Run Specific Test Files

```bash
# Run only model tests
pytest tests/test_models.py -v

# Run only data manager tests
pytest tests/test_data_manager.py -v

# Run only API client tests
pytest tests/test_peloton_client.py -v

# Run only race analyzer tests
pytest tests/test_race_analyzer.py -v
```

### Run Specific Tests

```bash
# Run single test function
pytest tests/test_models.py::test_user_from_dict -v

# Run all tests matching pattern
pytest tests/ -k "test_user" -v

# Run tests in a class
pytest tests/test_models.py::TestUserModel -v

# Run multiple patterns
pytest tests/ -k "test_user or test_workout" -v
```

### Run Tests by Marker

Tests are organized with pytest markers for selective execution:

```bash
# Run only unit tests (fast)
pytest tests/ -m unit -v

# Run only integration tests
pytest tests/ -m integration -v

# Run only API tests
pytest tests/ -m api -v

# Skip slow tests
pytest tests/ -m "not slow" -v

# Run security tests
pytest tests/ -m security -v

# Combine markers (unit OR integration)
pytest tests/ -m "unit or integration" -v

# Combine markers (unit AND fast)
pytest tests/ -m "unit and not slow" -v
```

### Available Markers

| Marker | Description | Count |
|--------|-------------|-------|
| `@pytest.mark.unit` | Fast unit tests | 150+ |
| `@pytest.mark.integration` | Integration tests | 30+ |
| `@pytest.mark.api` | API interaction tests | 20+ |
| `@pytest.mark.slow` | Tests taking > 1 second | 5+ |
| `@pytest.mark.security` | Security-specific tests | 50+ |

---

## Test Organization

### Test File Naming

- **Test files:** `test_*.py` or `*_test.py`
- **Test functions:** `test_*`
- **Test classes:** `Test*`

**Example:**
```python
# File: tests/test_models.py

class TestUserModel:
    def test_user_creation(self):
        """Test user object creation"""
        pass

    def test_user_serialization(self):
        """Test user to_dict conversion"""
        pass

def test_user_from_api_response():
    """Test user creation from API data"""
    pass
```

### Test Structure - AAA Pattern

Always use the **Arrange, Act, Assert** pattern:

```python
def test_save_user_profile(data_manager, sample_user):
    """Test saving user profile to file"""

    # Arrange - Set up test data
    manager = data_manager
    user = sample_user

    # Act - Perform the action being tested
    result = manager.save_user_profile(user)

    # Assert - Verify the outcome
    assert result is True
    assert (manager.user_dir / "user_profile.json").exists()

    # Cleanup (if needed)
    # Usually handled by fixtures
```

### Test Docstrings

Always include docstrings explaining what is being tested:

```python
def test_merge_workouts_deduplicates():
    """
    Test that merging workouts removes duplicates.

    Verifies that when workouts with duplicate workout_ids are merged,
    only unique workouts are kept, preferring the most recent data.
    """
    pass
```

---

## Fixtures

### What are Fixtures?

Fixtures are reusable test components defined in `conftest.py`. They provide:
- Test data setup
- Mock objects
- Temporary resources
- Cleanup handling

### Available Fixtures

#### Data Model Fixtures

Pre-configured test data objects:

```python
def test_example(sample_user, sample_workout):
    """Fixtures provide ready-to-use test data"""
    assert sample_user.user_id == "user123"
    assert sample_workout.ride_id is not None
```

**Available:**
- `sample_user` - Single User object
- `sample_follower` - Follower User object
- `sample_followers` - List of followers (3 users)
- `sample_ride_info` - RideInfo object
- `sample_performance_metrics` - PerformanceMetrics with time series
- `sample_workout` - Complete Workout object
- `sample_workouts` - List of workouts (5 workouts)
- `invalid_ride_info` - Invalid RideInfo for error testing

#### File System Fixtures

Temporary directories that auto-cleanup:

```python
def test_file_operations(temp_data_dir):
    """temp_data_dir is automatically created and cleaned up"""
    file_path = temp_data_dir / "test.json"
    file_path.write_text('{"test": true}')
    assert file_path.exists()
    # Cleanup happens automatically
```

**Available:**
- `temp_data_dir` - Empty temporary directory
- `data_manager_with_temp_dir` - DataManager using temp directory
- `populated_data_dir` - Pre-populated with test data

#### API Mocking Fixtures

Mock Peloton API responses:

```python
def test_api_call(mock_peloton_client):
    """Mock client with stubbed methods"""
    profile = mock_peloton_client.get_user_profile()
    assert profile is not None
```

**Available:**
- `mock_peloton_client` - Mock PelotonClient
- `mock_api_user_response` - Mock user profile response
- `mock_api_workout_response` - Mock workout response
- `mock_api_performance_response` - Mock performance graph
- `mock_api_followers_response` - Mock followers list

#### Utility Fixtures

Helper functions for testing:

```python
def test_json_comparison(assert_json_equal):
    """Compare JSON ignoring key order"""
    expected = {"a": 1, "b": 2}
    actual = {"b": 2, "a": 1}
    assert_json_equal(expected, actual)  # Passes
```

**Available:**
- `assert_json_equal` - Order-independent JSON comparison
- `mock_responses` - HTTP mocking library
- `disable_network_calls` - Prevent accidental network requests

### Using Fixtures

#### Basic Usage

```python
def test_with_fixture(sample_user):
    """Fixture passed as function parameter"""
    assert sample_user.username == "testuser"
```

#### Multiple Fixtures

```python
def test_with_multiple_fixtures(sample_user, sample_workout, temp_data_dir):
    """Use multiple fixtures in one test"""
    user_file = temp_data_dir / f"{sample_user.user_id}.json"
    # Use all fixtures
```

#### Fixture Scope

Fixtures have different lifetimes:

```python
@pytest.fixture(scope="function")  # Default - new for each test
@pytest.fixture(scope="module")    # Shared across file
@pytest.fixture(scope="session")   # Shared across all tests
```

### Creating New Fixtures

Add to `conftest.py`:

```python
@pytest.fixture
def custom_test_data():
    """Provide custom test data"""
    data = {
        "key": "value",
        "number": 42
    }
    return data

# Use in tests
def test_example(custom_test_data):
    assert custom_test_data["number"] == 42
```

---

## Writing New Tests

### Step-by-Step Guide

#### 1. Choose the Right Test File

- **Models:** `tests/test_models.py`
- **Data persistence:** `tests/test_data_manager.py`
- **Race analysis:** `tests/test_race_analyzer.py`
- **API client:** `tests/test_peloton_client.py`
- **New feature:** Create `tests/test_feature_name.py`

#### 2. Write the Test Function

```python
import pytest
from src.models.models import User

@pytest.mark.unit
def test_user_creation():
    """
    Test creating a User object with valid data.

    Verifies that User objects can be instantiated with
    required fields and that all attributes are accessible.
    """
    # Arrange
    user_id = "test123"
    username = "testuser"

    # Act
    user = User(user_id=user_id, username=username)

    # Assert
    assert user.user_id == user_id
    assert user.username == username
    assert user.display_name is None  # Optional field
```

#### 3. Use Fixtures Where Possible

```python
@pytest.mark.unit
def test_user_serialization(sample_user):
    """Test User.to_dict() serialization using fixture"""
    # Act
    user_dict = sample_user.to_dict()

    # Assert
    assert user_dict["user_id"] == sample_user.user_id
    assert user_dict["username"] == sample_user.username
```

#### 4. Add Appropriate Markers

```python
@pytest.mark.unit
@pytest.mark.fast
def test_quick_operation():
    """Fast unit test"""
    pass

@pytest.mark.integration
@pytest.mark.slow
def test_complex_integration():
    """Slower integration test"""
    pass
```

#### 5. Test Edge Cases

```python
@pytest.mark.unit
def test_user_with_none_values():
    """Test User handles None values correctly"""
    user = User(user_id="test", username=None)
    assert user.username == ""  # Should default to empty string

@pytest.mark.unit
def test_user_with_missing_fields():
    """Test User handles missing fields"""
    data = {"id": "test"}  # Missing username
    user = User.from_dict(data)
    assert user.user_id == "test"
    assert user.username == ""  # Should have default
```

#### 6. Test Error Conditions

```python
@pytest.mark.unit
def test_invalid_user_id_raises_error():
    """Test that invalid user_id raises ValueError"""
    with pytest.raises(ValueError, match="Invalid user_id"):
        User(user_id=None)  # Should raise
```

### Test Template

```python
"""
Tests for [component name]

This module tests [description of what is being tested].
"""

import pytest
from src.module import Component


class TestComponentName:
    """Tests for ComponentName class"""

    @pytest.mark.unit
    def test_basic_functionality(self):
        """
        Test basic component functionality.

        Verifies that [what is being tested].
        """
        # Arrange
        component = Component()

        # Act
        result = component.method()

        # Assert
        assert result is not None

    @pytest.mark.unit
    def test_with_fixture(self, sample_data):
        """Test using a fixture"""
        # Arrange
        component = Component(sample_data)

        # Act
        result = component.process()

        # Assert
        assert result.success is True

    @pytest.mark.unit
    def test_error_handling(self):
        """Test error handling"""
        component = Component()

        with pytest.raises(ValueError):
            component.method_that_should_fail()


@pytest.mark.integration
def test_integration_scenario(temp_data_dir):
    """
    Test integration between components.

    This is a broader test that exercises multiple components.
    """
    # Arrange
    # ... setup

    # Act
    # ... perform actions

    # Assert
    # ... verify outcomes
```

---

## Coverage Reporting

### Generate Coverage Reports

#### Terminal Report

```bash
# Basic coverage report
pytest tests/ --cov=src --cov-report=term

# Show missing lines
pytest tests/ --cov=src --cov-report=term-missing

# Show branch coverage
pytest tests/ --cov=src --cov-branch --cov-report=term-missing
```

**Output:**
```
Name                            Stmts   Miss Branch BrPart  Cover   Missing
---------------------------------------------------------------------------
src/models/models.py              155     87     48      0    33%   23, 34, 59-82...
src/services/data_manager.py      148      5     44      5    95%   49, 53, 166...
src/services/race_analyzer.py      95      1     42      2    98%   32->31, 185
---------------------------------------------------------------------------
TOTAL                             804    321    244     18    59%
```

#### HTML Report

```bash
# Generate HTML coverage report
pytest tests/ --cov=src --cov-report=html

# Open in browser
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
start htmlcov/index.html  # Windows
```

**Features:**
- Visual line-by-line coverage
- Color-coded coverage indicators
- Sortable module list
- Branch coverage details

#### XML Report (for CI/CD)

```bash
# Generate XML report for CI tools
pytest tests/ --cov=src --cov-report=xml

# Output: coverage.xml
```

### Regenerating Coverage Reports

Coverage reports are **generated artifacts** and are not committed to the repository. They should be regenerated locally or in CI/CD as needed.

#### Quick Generation Script

Use the provided script for easy report generation:

```bash
# Run the automated coverage script
bash scripts/generate_coverage_report.sh
```

This script:
- Runs the full test suite
- Generates HTML coverage report (`htmlcov/index.html`)
- Generates JSON coverage data (`.coverage.json`)
- Shows terminal output with missing lines

#### Manual Generation

```bash
# Generate all report formats
pytest tests/ -v \
    --cov=src \
    --cov-report=term-missing \
    --cov-report=html:htmlcov \
    --cov-report=json:.coverage.json
```

#### Why Reports Are Not Committed

Coverage reports are excluded from git (see `.gitignore`) because:
- They change with every test run
- They can be regenerated from source code
- They may contain outdated information
- HTML reports are large (multiple files)

**To view coverage:**
1. Run `bash scripts/generate_coverage_report.sh`
2. Open `htmlcov/index.html` in your browser

### Understanding Coverage Metrics

**Statements (Stmts):** Total lines of code
**Miss:** Lines not executed by tests
**Branch:** Decision points (if/else, loops)
**BrPart:** Branches partially covered
**Cover:** Percentage coverage

**Example:**
```python
def example(x):
    if x > 0:        # Branch point
        return "pos"  # Branch 1
    else:
        return "neg"  # Branch 2
```

**Full Coverage:** Test with both `x > 0` and `x <= 0`

### Coverage Goals

| Module | Target | Current |
|--------|--------|---------|
| Models | 98% | 96% |
| Data Manager | 95% | 95% ✅ |
| Race Analyzer | 98% | 98% ✅ |
| API Client | 80% | 45% |
| Authentication | 75% | 0% |
| **Overall** | **80%** | **59%** |

### Improve Coverage

#### Find Untested Code

```bash
# Show missing lines
pytest tests/ --cov=src --cov-report=term-missing

# Focus on specific module
pytest tests/ --cov=src.services.data_manager --cov-report=term-missing
```

#### Write Tests for Missing Lines

```python
# Example: Line 49 in data_manager.py not covered
# Line 49: if not self.user_dir.exists():

@pytest.mark.unit
def test_data_manager_creates_directory(temp_data_dir):
    """Test that DataManager creates user directory if missing"""
    # Don't pre-create directory
    user_dir = temp_data_dir / "new_user"
    assert not user_dir.exists()  # Verify doesn't exist

    # Act - DataManager should create it
    dm = DataManager(user_id="new_user")

    # Assert
    assert dm.user_dir.exists()  # Line 49 now covered
```

---

## CI/CD Integration

### GitHub Actions Example

Create `.github/workflows/test.yml`:

```yaml
name: Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.10'

    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt

    - name: Run tests with coverage
      run: |
        pytest tests/ -v --cov=src --cov-report=xml --cov-report=term-missing

    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
        fail_ci_if_error: true

    - name: Check coverage threshold
      run: |
        pytest tests/ --cov=src --cov-fail-under=60
```

### Pre-commit Hooks

Install pre-commit hooks to run tests automatically:

```bash
# Install pre-commit
pip install pre-commit

# Create .pre-commit-config.yaml
cat > .pre-commit-config.yaml << EOF
repos:
  - repo: local
    hooks:
      - id: pytest
        name: pytest
        entry: pytest tests/ -v --cov=src
        language: system
        pass_filenames: false
        always_run: true
EOF

# Install hooks
pre-commit install
```

Now tests run automatically before each commit.

---

## Troubleshooting

### Common Issues

#### Issue: ModuleNotFoundError

**Error:**
```
ModuleNotFoundError: No module named 'src'
```

**Solution:**
Ensure you're running pytest from the project root:

```bash
cd /path/to/PelotonRacer
pytest tests/
```

#### Issue: Fixture Not Found

**Error:**
```
fixture 'sample_user' not found
```

**Solutions:**
1. Verify `conftest.py` is in `tests/` directory
2. Check fixture name spelling
3. Ensure you're running from project root
4. Try: `pytest tests/ --fixtures` to list available fixtures

#### Issue: Tests Pass Locally, Fail in CI

**Common Causes:**
- Different Python version
- Missing environment variables
- File path assumptions (absolute vs relative)
- Network dependencies not mocked

**Solution:**
Match CI environment locally:

```bash
# Use same Python version
python --version

# Run in clean environment
python -m venv test_env
source test_env/bin/activate
pip install -r requirements.txt
pytest tests/
```

#### Issue: Slow Tests

**Solutions:**
1. Run only unit tests: `pytest tests/ -m unit`
2. Skip slow tests: `pytest tests/ -m "not slow"`
3. Run in parallel: `pytest tests/ -n auto` (requires pytest-xdist)
4. Profile tests: `pytest tests/ --durations=10`

#### Issue: Mock Not Working

**Error:**
```
TypeError: 'module' object does not support context manager protocol
```

**Solution:**
Fix mock setup in test:

```python
import responses

@responses.activate
def test_api_call():
    responses.add(
        responses.GET,
        "https://api.onepeloton.com/api/user/me",
        json={"id": "123"},
        status=200
    )
    # Test code
```

#### Issue: Coverage Not Accurate

**Solutions:**
1. Ensure coverage measures src/ not tests/: `--cov=src`
2. Include branch coverage: `--cov-branch`
3. Clear previous coverage: `rm -rf .coverage htmlcov/`
4. Run fresh: `pytest tests/ --cov=src --cov-report=term-missing`

### Getting Help

1. **Check test documentation:** `tests/README.md`
2. **List available fixtures:** `pytest tests/ --fixtures`
3. **List test markers:** `pytest tests/ --markers`
4. **Verbose output:** `pytest tests/ -vv`
5. **Debug with print:** `pytest tests/ -v -s`
6. **Drop into debugger:** `pytest tests/ --pdb`

### Debug Mode

```bash
# Drop into debugger on failure
pytest tests/ --pdb

# Drop into debugger on error
pytest tests/ --pdb --pdbcls=IPython.terminal.debugger:Pdb

# Show local variables on failure
pytest tests/ -l

# Show captured output
pytest tests/ -v -s
```

---

## Best Practices

### Do's

✅ **Use descriptive test names**
```python
def test_user_profile_saves_to_correct_directory()
```

✅ **Test one thing per test**
```python
def test_user_serialization():
    # Only test serialization
```

✅ **Use fixtures for common setup**
```python
def test_example(sample_user, temp_data_dir):
    # Fixtures handle setup
```

✅ **Add docstrings explaining what is tested**
```python
def test_merge_workouts():
    """Test that duplicate workouts are removed during merge"""
```

✅ **Mark tests appropriately**
```python
@pytest.mark.unit
@pytest.mark.fast
def test_quick_operation():
```

✅ **Test edge cases and errors**
```python
def test_handles_none_value():
def test_raises_error_on_invalid_input():
```

### Don'ts

❌ **Don't test implementation details**
```python
# Bad: Testing internal method
def test_internal_helper_method():

# Good: Test public API behavior
def test_public_method_result():
```

❌ **Don't write interdependent tests**
```python
# Bad: Tests depend on each other
def test_step_1():
    global state
    state = "step1"

def test_step_2():
    assert state == "step1"  # Depends on test_step_1

# Good: Tests are independent
def test_step_1(setup):
    assert setup.do_step_1() == "result"

def test_step_2(setup):
    assert setup.do_step_2() == "result"
```

❌ **Don't skip cleanup**
```python
# Bad: Leaves files around
def test_creates_file():
    Path("test.txt").write_text("data")
    # No cleanup

# Good: Use fixture with cleanup
def test_creates_file(temp_data_dir):
    (temp_data_dir / "test.txt").write_text("data")
    # Fixture handles cleanup
```

❌ **Don't make real API calls in tests**
```python
# Bad: Real API call
def test_get_profile():
    client = PelotonClient(real_token)
    profile = client.get_user_profile()  # Real API call

# Good: Mock API call
def test_get_profile(mock_peloton_client):
    profile = mock_peloton_client.get_user_profile()  # Mocked
```

---

## Summary

### Quick Reference

```bash
# Run all tests with coverage
pytest tests/ -v --cov=src --cov-report=term-missing

# Run specific test file
pytest tests/test_models.py -v

# Run specific test
pytest tests/test_models.py::test_user_creation -v

# Run by marker
pytest tests/ -m unit -v

# HTML coverage report
pytest tests/ --cov=src --cov-report=html
open htmlcov/index.html

# Debug mode
pytest tests/ --pdb -v
```

### Resources

- **Test Documentation:** `tests/README.md`
- **Coverage Report:** `docs/testing/coverage-report.md`
- **pytest Documentation:** https://docs.pytest.org/
- **pytest-cov Documentation:** https://pytest-cov.readthedocs.io/

---

**Last Updated:** February 7, 2026
**Maintainer:** QA Team
**Questions:** qa@pelotonracer.com
