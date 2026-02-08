# Agent System Implementation Plan - Phases 1-4

> **STATUS: ✅ COMPLETE** - All tasks completed on 2026-02-07
>
> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Complete Testing Agent (Phases 1-2) and Security Agent (Phases 3-4) foundations to enable automated testing and security analysis across Python projects.

**Architecture:** Claude Code skills that invoke specialized agents via `/agent:test` and `/agent:security`. Each agent uses modular analyzers/scanners, generates tests/reports, and produces both JSON and Markdown outputs.

**Tech Stack:** Python 3.10+, AST parsing, pytest, pytest-cov, Jinja2 templates, subprocess, regex, pathlib

**Final State:**
- ✅ Testing agent: skill.md, framework_detector.py, test templates, test_runner.py
- ✅ Testing agent: gap_analyzer.py, coverage_analyzer.py, mock_generator.py, streamlit_fixture.py
- ✅ Shared: report_generator.py
- ✅ Security agent: skill.md, stride.py, owasp.py, config_scanner.py, dependency_scanner.py
- ✅ Documentation: Updated README.md with complete architecture

---

## Phase 1: Testing Agent Foundation

### Task 1: Create gap analyzer for untested code detection

**Files:**
- Create: `~/.claude/skills/agents/agent-test/analyzers/gap_analyzer.py`

**Step 1: Write the gap analyzer module**

Create the file with AST-based code analysis:

```python
"""
Gap analyzer to identify untested code paths using AST parsing.
"""

import ast
from pathlib import Path
from typing import List, Dict, Set
from dataclasses import dataclass


@dataclass
class UntestFunction:
    """Represents a function that needs testing."""
    name: str
    file: str
    line_number: int
    is_method: bool
    class_name: str = None
    docstring: str = None
    complexity: int = 1  # Simple complexity score


@dataclass
class GapAnalysisResult:
    """Results from gap analysis."""
    untested_functions: List[UntestedFunction]
    untested_files: List[str]
    total_functions: int
    tested_functions: int
    coverage_percent: float


class GapAnalyzer:
    """Analyzes codebase to find untested code."""

    def __init__(self, project_root: str, test_dir: str):
        self.project_root = Path(project_root)
        self.test_dir = Path(test_dir)

    def analyze(self, target_path: str = None) -> GapAnalysisResult:
        """
        Analyze codebase to find untested functions.

        Args:
            target_path: Specific file or directory to analyze (None = all source)

        Returns:
            GapAnalysisResult with findings
        """
        # Find all source files
        source_files = self._find_source_files(target_path)

        # Find all test files
        test_files = self._find_test_files()

        # Extract tested function names from test files
        tested_functions = self._extract_tested_functions(test_files)

        # Analyze source files for functions
        all_functions = []
        for source_file in source_files:
            functions = self._extract_functions(source_file)
            all_functions.extend(functions)

        # Identify untested functions
        untested = [
            f for f in all_functions
            if f.name not in tested_functions
        ]

        # Calculate coverage
        total = len(all_functions)
        tested = total - len(untested)
        coverage = (tested / total * 100) if total > 0 else 0.0

        # Identify files with no tests
        untested_files = self._find_untested_files(source_files, test_files)

        return GapAnalysisResult(
            untested_functions=untested,
            untested_files=untested_files,
            total_functions=total,
            tested_functions=tested,
            coverage_percent=coverage
        )

    def _find_source_files(self, target_path: str = None) -> List[Path]:
        """Find all Python source files (excluding tests)."""
        if target_path:
            target = self.project_root / target_path
            if target.is_file():
                return [target]
            elif target.is_dir():
                source_files = list(target.rglob("*.py"))
            else:
                return []
        else:
            source_files = list(self.project_root.rglob("*.py"))

        # Exclude test files and common non-source directories
        excluded_dirs = {'tests', 'test', '__pycache__', '.venv', 'venv', 'env', 'build', 'dist'}

        filtered = []
        for f in source_files:
            # Skip if in test directory
            if any(part in excluded_dirs for part in f.parts):
                continue
            # Skip if filename starts with test_
            if f.name.startswith('test_'):
                continue
            filtered.append(f)

        return filtered

    def _find_test_files(self) -> List[Path]:
        """Find all test files."""
        if not self.test_dir.exists():
            return []

        test_files = []
        test_files.extend(self.test_dir.rglob("test_*.py"))
        test_files.extend(self.test_dir.rglob("*_test.py"))

        return test_files

    def _extract_functions(self, filepath: Path) -> List[UntestedFunction]:
        """Extract all functions and methods from a Python file using AST."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                source = f.read()

            tree = ast.parse(source, filename=str(filepath))
        except Exception:
            return []

        functions = []
        current_class = None

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                current_class = node.name

            if isinstance(node, ast.FunctionDef):
                # Skip private functions (start with _) unless they're special methods
                if node.name.startswith('_') and not node.name.startswith('__'):
                    continue

                # Extract docstring
                docstring = ast.get_docstring(node)

                # Determine if method or function
                is_method = current_class is not None

                # Calculate simple complexity (number of branches)
                complexity = self._calculate_complexity(node)

                func = UntestedFunction(
                    name=node.name,
                    file=str(filepath.relative_to(self.project_root)),
                    line_number=node.lineno,
                    is_method=is_method,
                    class_name=current_class if is_method else None,
                    docstring=docstring,
                    complexity=complexity
                )

                functions.append(func)

        return functions

    def _calculate_complexity(self, node: ast.FunctionDef) -> int:
        """Calculate cyclomatic complexity (simplified)."""
        complexity = 1  # Base complexity

        for child in ast.walk(node):
            # Count decision points
            if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1

        return complexity

    def _extract_tested_functions(self, test_files: List[Path]) -> Set[str]:
        """Extract function names that are being tested."""
        tested = set()

        for test_file in test_files:
            try:
                with open(test_file, 'r', encoding='utf-8') as f:
                    source = f.read()

                tree = ast.parse(source, filename=str(test_file))
            except Exception:
                continue

            # Look for test function names like test_foo_bar
            # Infer that they test function "foo" or method "foo_bar"
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    if node.name.startswith('test_'):
                        # Extract tested function name
                        # test_authenticate_success -> authenticate
                        # test_load_data_from_file -> load_data
                        parts = node.name.replace('test_', '').split('_')
                        if parts:
                            # Add various permutations (heuristic)
                            tested.add(parts[0])
                            if len(parts) > 1:
                                tested.add('_'.join(parts[:2]))
                            tested.add('_'.join(parts))

        return tested

    def _find_untested_files(self, source_files: List[Path], test_files: List[Path]) -> List[str]:
        """Identify source files with no corresponding test file."""
        untested = []

        # Build set of tested file basenames
        tested_basenames = set()
        for test_file in test_files:
            # test_foo.py -> foo
            basename = test_file.name.replace('test_', '').replace('_test.py', '.py')
            tested_basenames.add(basename)

        for source_file in source_files:
            if source_file.name not in tested_basenames:
                untested.append(str(source_file.relative_to(self.project_root)))

        return untested

    def prioritize_untested_functions(self, result: GapAnalysisResult) -> List[UntestedFunction]:
        """
        Prioritize untested functions by importance.

        Priority order:
        1. API clients (high complexity)
        2. Data models with serialization
        3. Business logic (medium-high complexity)
        4. Utility functions (lower complexity)
        """
        # Categorize by file path patterns
        api_pattern = {'api', 'client', 'service'}
        model_pattern = {'model', 'schema', 'entity'}
        business_pattern = {'manager', 'handler', 'processor', 'analyzer'}

        def priority_score(func: UntestedFunction) -> int:
            score = 0

            # File path hints
            path_lower = func.file.lower()
            if any(p in path_lower for p in api_pattern):
                score += 100
            elif any(p in path_lower for p in model_pattern):
                score += 80
            elif any(p in path_lower for p in business_pattern):
                score += 60

            # Complexity bonus
            score += func.complexity * 10

            # Method vs function (methods often more important)
            if func.is_method:
                score += 20

            return score

        sorted_functions = sorted(
            result.untested_functions,
            key=priority_score,
            reverse=True
        )

        return sorted_functions


if __name__ == "__main__":
    import sys

    project_root = sys.argv[1] if len(sys.argv) > 1 else "."
    test_dir = sys.argv[2] if len(sys.argv) > 2 else "tests"

    analyzer = GapAnalyzer(project_root, test_dir)
    result = analyzer.analyze()

    print(f"Total functions: {result.total_functions}")
    print(f"Tested: {result.tested_functions}")
    print(f"Untested: {len(result.untested_functions)}")
    print(f"Coverage: {result.coverage_percent:.1f}%")
    print(f"\nUntested files: {len(result.untested_files)}")

    prioritized = analyzer.prioritize_untested_functions(result)
    print(f"\nTop 5 priority untested functions:")
    for func in prioritized[:5]:
        print(f"  - {func.file}:{func.line_number} {func.name} (complexity={func.complexity})")
```

**Step 2: Test the gap analyzer**

Run: `python3 ~/.claude/skills/agents/agent-test/analyzers/gap_analyzer.py /Users/nissim/dev/PelotonRacer tests`

Expected: Should analyze PelotonRacer and show untested functions

**Step 3: Commit**

```bash
git add ~/.claude/skills/agents/agent-test/analyzers/gap_analyzer.py
git commit -m "feat: add gap analyzer for untested code detection (Phase 1)"
```

---

### Task 2: Create coverage analyzer for pytest-cov integration

**Files:**
- Create: `~/.claude/skills/agents/agent-test/analyzers/coverage_analyzer.py`

**Step 1: Write the coverage analyzer module**

```python
"""
Coverage analyzer for integrating pytest-cov results.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class FileCoverage:
    """Coverage data for a single file."""
    file: str
    total_lines: int
    covered_lines: int
    missing_lines: List[int]
    coverage_percent: float


@dataclass
class CoverageAnalysisResult:
    """Overall coverage analysis result."""
    total_lines: int
    covered_lines: int
    coverage_percent: float
    file_coverage: List[FileCoverage]
    uncovered_files: List[FileCoverage]  # Files with < 80% coverage


class CoverageAnalyzer:
    """Analyzes pytest coverage results."""

    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.coverage_file = self.project_root / "coverage.json"
        self.coverage_threshold = 80.0  # Files below this are flagged

    def analyze(self) -> Optional[CoverageAnalysisResult]:
        """
        Analyze coverage.json from pytest-cov.

        Returns:
            CoverageAnalysisResult or None if no coverage data exists
        """
        if not self.coverage_file.exists():
            return None

        try:
            with open(self.coverage_file, 'r') as f:
                data = json.load(f)
        except Exception:
            return None

        # Extract file-level coverage
        file_coverage = []
        for filepath, coverage_data in data.get('files', {}).items():
            # Skip test files and external packages
            if 'test' in filepath.lower() or 'site-packages' in filepath:
                continue

            summary = coverage_data.get('summary', {})
            total_statements = summary.get('num_statements', 0)
            covered_statements = summary.get('covered_lines', 0)
            missing_lines = coverage_data.get('missing_lines', [])

            if total_statements == 0:
                continue

            coverage_pct = (covered_statements / total_statements * 100)

            fc = FileCoverage(
                file=filepath,
                total_lines=total_statements,
                covered_lines=covered_statements,
                missing_lines=missing_lines,
                coverage_percent=coverage_pct
            )

            file_coverage.append(fc)

        # Calculate overall coverage
        totals = data.get('totals', {})
        total_lines = totals.get('num_statements', 0)
        covered_lines = totals.get('covered_lines', 0)
        overall_pct = totals.get('percent_covered', 0.0)

        # Identify files with low coverage
        uncovered = [fc for fc in file_coverage if fc.coverage_percent < self.coverage_threshold]
        uncovered.sort(key=lambda x: x.coverage_percent)

        return CoverageAnalysisResult(
            total_lines=total_lines,
            covered_lines=covered_lines,
            coverage_percent=overall_pct,
            file_coverage=file_coverage,
            uncovered_files=uncovered
        )

    def get_priority_uncovered_lines(self, result: CoverageAnalysisResult,
                                     max_files: int = 5) -> Dict[str, List[int]]:
        """
        Get priority uncovered lines to focus testing efforts.

        Args:
            result: CoverageAnalysisResult from analyze()
            max_files: Maximum number of files to return

        Returns:
            Dict mapping file paths to lists of uncovered line numbers
        """
        priority_files = result.uncovered_files[:max_files]

        uncovered_map = {}
        for fc in priority_files:
            uncovered_map[fc.file] = fc.missing_lines[:20]  # Max 20 lines per file

        return uncovered_map


if __name__ == "__main__":
    import sys

    project_root = sys.argv[1] if len(sys.argv) > 1 else "."

    analyzer = CoverageAnalyzer(project_root)
    result = analyzer.analyze()

    if result:
        print(f"Overall Coverage: {result.coverage_percent:.1f}%")
        print(f"Total Lines: {result.total_lines}")
        print(f"Covered Lines: {result.covered_lines}")
        print(f"\nFiles with low coverage (<{analyzer.coverage_threshold}%):")
        for fc in result.uncovered_files[:5]:
            print(f"  - {fc.file}: {fc.coverage_percent:.1f}%")
    else:
        print("No coverage data found. Run tests with --cov first.")
```

**Step 2: Test the coverage analyzer**

Run: `cd /Users/nissim/dev/PelotonRacer && pytest --cov --cov-report=json tests/ || true && python3 ~/.claude/skills/agents/agent-test/analyzers/coverage_analyzer.py .`

Expected: Should show coverage analysis (or "No coverage data" if no tests exist yet)

**Step 3: Commit**

```bash
git add ~/.claude/skills/agents/agent-test/analyzers/coverage_analyzer.py
git commit -m "feat: add coverage analyzer for pytest-cov integration (Phase 1)"
```

---

### Task 3: Update agent-test skill to integrate analyzers

**Files:**
- Modify: `~/.claude/skills/agents/agent-test/skill.md`

**Step 1: Add imports and usage to skill workflow**

Insert after line 68 (in "Analyze Codebase" section):

```markdown
**Using Gap Analyzer:**
```python
from analyzers.gap_analyzer import GapAnalyzer

analyzer = GapAnalyzer(project_root, test_dir)
gap_result = analyzer.analyze(target_path=args.file if args.file else None)
prioritized_functions = analyzer.prioritize_untested_functions(gap_result)

# Show top priorities
print(f"📊 Analyzing codebase...")
print(f"✅ Found {gap_result.total_functions} functions")
print(f"⚠️  {len(gap_result.untested_functions)} functions need tests")
print(f"⚠️  {len(gap_result.untested_files)} files have no test coverage")

# Focus on top 10 priority functions for test generation
focus_functions = prioritized_functions[:10]
```

**Using Coverage Analyzer (when --full flag is used):**
```python
if args.full:
    from analyzers.coverage_analyzer import CoverageAnalyzer

    cov_analyzer = CoverageAnalyzer(project_root)
    cov_result = cov_analyzer.analyze()

    if cov_result:
        print(f"📊 Coverage: {cov_result.coverage_percent:.1f}%")
        print(f"⚠️  {len(cov_result.uncovered_files)} files below {cov_analyzer.coverage_threshold}% coverage")
```
```

**Step 2: Commit**

```bash
git add ~/.claude/skills/agents/agent-test/skill.md
git commit -m "feat: integrate gap and coverage analyzers into testing agent workflow (Phase 1)"
```

---

## Phase 2: Testing Agent Enhancements

### Task 4: Create Streamlit test fixtures template

**Files:**
- Create: `~/.claude/skills/agents/agent-test/templates/streamlit_fixture.py`

**Step 1: Write Streamlit test fixture generator**

```python
"""
Streamlit-specific test fixtures and templates.
"""

from jinja2 import Template


STREAMLIT_SESSION_STATE_FIXTURE = Template("""
import pytest
from unittest.mock import Mock


@pytest.fixture
def mock_streamlit_session_state():
    \"\"\"Mock Streamlit session_state with common defaults.\"\"\"
    class MockSessionState(dict):
        def __getattr__(self, key):
            try:
                return self[key]
            except KeyError:
                return None

        def __setattr__(self, key, value):
            self[key] = value

    state = MockSessionState({
        {{ state_defaults }}
    })

    return state


@pytest.fixture
def mock_streamlit_components(monkeypatch):
    \"\"\"Mock Streamlit components to prevent actual rendering.\"\"\"
    import streamlit as st

    mocks = {}

    # Mock common components
    for component in ['write', 'title', 'header', 'subheader', 'text',
                      'button', 'selectbox', 'multiselect', 'slider',
                      'text_input', 'number_input', 'checkbox',
                      'radio', 'dataframe', 'table', 'json',
                      'markdown', 'code', 'divider', 'columns',
                      'expander', 'tabs', 'sidebar', 'container',
                      'empty', 'spinner', 'success', 'error',
                      'warning', 'info', 'exception']:
        mock = Mock(return_value=None)
        mocks[component] = mock
        monkeypatch.setattr(f'streamlit.{component}', mock)

    return mocks
""")


STREAMLIT_PAGE_TEST = Template("""
import pytest
from unittest.mock import Mock, patch, MagicMock
import streamlit as st


class Test{{ page_name }}:
    \"\"\"Tests for {{ page_file }} Streamlit page.\"\"\"

    @pytest.fixture
    def mock_session_state(self):
        \"\"\"Create mock session state with page-specific defaults.\"\"\"
        return {
            {{ session_state_defaults }}
        }

    @pytest.fixture
    def mock_st_components(self, monkeypatch):
        \"\"\"Mock Streamlit components.\"\"\"
        mocks = {}
        for component in ['title', 'write', 'button', 'dataframe']:
            mock = Mock()
            mocks[component] = mock
            monkeypatch.setattr(f'streamlit.{component}', mock)
        return mocks

    def test_page_renders_without_error(self, mock_session_state, mock_st_components):
        \"\"\"Test {{ page_name }} page renders without raising exceptions.\"\"\"
        with patch('streamlit.session_state', mock_session_state):
            # Import page module (this executes the page code)
            try:
                from {{ module_path }} import {{ page_function }}
                {{ page_function }}()
            except Exception as e:
                pytest.fail(f"Page raised exception during render: {e}")

    def test_page_displays_title(self, mock_session_state, mock_st_components):
        \"\"\"Test that page displays expected title.\"\"\"
        with patch('streamlit.session_state', mock_session_state):
            from {{ module_path }} import {{ page_function }}
            {{ page_function }}()

            # Verify title was called
            mock_st_components['title'].assert_called()

    def test_page_handles_missing_session_state(self, mock_st_components):
        \"\"\"Test page handles missing session state gracefully.\"\"\"
        with patch('streamlit.session_state', {}):
            from {{ module_path }} import {{ page_function }}

            # Should not crash, might initialize defaults
            try:
                {{ page_function }}()
            except KeyError as e:
                pytest.fail(f"Page doesn't handle missing session state: {e}")

    def test_page_button_interactions(self, mock_session_state, mock_st_components):
        \"\"\"Test button click handlers.\"\"\"
        # Mock button to return True (clicked)
        mock_st_components['button'].return_value = True

        with patch('streamlit.session_state', mock_session_state):
            from {{ module_path }} import {{ page_function }}
            {{ page_function }}()

            # Verify button click triggered expected behavior
            # Add specific assertions based on page logic
""")


def generate_streamlit_session_fixture(state_defaults: Dict[str, Any]) -> str:
    """
    Generate Streamlit session state fixture.

    Args:
        state_defaults: Dict of default session state values

    Returns:
        Pytest fixture code as string
    """
    # Format state defaults as Python dict entries
    defaults_str = ",\n        ".join(
        f'"{key}": {repr(value)}'
        for key, value in state_defaults.items()
    )

    return STREAMLIT_SESSION_STATE_FIXTURE.render(
        state_defaults=defaults_str
    )


def generate_streamlit_page_test(page_name: str, page_file: str,
                                 module_path: str, page_function: str,
                                 session_state_defaults: Dict[str, Any]) -> str:
    """
    Generate test for a Streamlit page.

    Args:
        page_name: Human-readable page name (e.g., "MainPage")
        page_file: Source file name (e.g., "app.py")
        module_path: Python import path (e.g., "app")
        page_function: Function that renders the page
        session_state_defaults: Default session state values

    Returns:
        Test code as string
    """
    defaults_str = ",\n            ".join(
        f'"{key}": {repr(value)}'
        for key, value in session_state_defaults.items()
    )

    return STREAMLIT_PAGE_TEST.render(
        page_name=page_name,
        page_file=page_file,
        module_path=module_path,
        page_function=page_function,
        session_state_defaults=defaults_str
    )


if __name__ == "__main__":
    # Example usage
    defaults = {
        "authenticated": False,
        "user_id": None,
        "data_loaded": False
    }

    print("=== Session State Fixture ===")
    print(generate_streamlit_session_fixture(defaults))

    print("\n=== Page Test ===")
    print(generate_streamlit_page_test(
        page_name="Dashboard",
        page_file="pages/dashboard.py",
        module_path="pages.dashboard",
        page_function="render_dashboard",
        session_state_defaults=defaults
    ))
```

**Step 2: Test the template generator**

Run: `python3 ~/.claude/skills/agents/agent-test/templates/streamlit_fixture.py`

Expected: Should output Streamlit test fixtures and page test template

**Step 3: Commit**

```bash
git add ~/.claude/skills/agents/agent-test/templates/streamlit_fixture.py
git commit -m "feat: add Streamlit test fixture generator (Phase 2)"
```

---

### Task 5: Create mock generator for API clients

**Files:**
- Create: `~/.claude/skills/agents/agent-test/utils/mock_generator.py`

**Step 1: Write mock generator for API clients**

```python
"""
Auto-generate mocks for API clients using AST analysis.
"""

import ast
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass
from jinja2 import Template


@dataclass
class APIMethod:
    """Represents an API method to mock."""
    class_name: str
    method_name: str
    http_method: str  # get, post, put, delete, patch
    is_async: bool = False


API_MOCK_TEMPLATE = Template("""
@pytest.fixture
def mock_{{ fixture_name }}(monkeypatch):
    \"\"\"Mock {{ class_name }} for testing.\"\"\"
    from unittest.mock import Mock, AsyncMock
    from {{ module_path }} import {{ class_name }}

    mock_instance = Mock(spec={{ class_name }})

    {% for method in methods %}
    # Mock {{ method.method_name }}
    {% if method.is_async %}
    mock_instance.{{ method.method_name }} = AsyncMock(return_value={{ '{' }}"status": "success"{{ '}' }})
    {% else %}
    mock_instance.{{ method.method_name }} = Mock(return_value={{ '{' }}"status": "success"{{ '}' }})
    {% endif %}
    {% endfor %}

    return mock_instance
""")


API_CLIENT_MOCK_RESPONSE_TEMPLATE = Template("""
@pytest.fixture
def mock_{{ http_method }}_response():
    \"\"\"Mock successful {{ http_method.upper() }} response.\"\"\"
    from unittest.mock import Mock

    response = Mock()
    response.status_code = 200
    response.json.return_value = {{ expected_response }}
    response.raise_for_status = Mock()

    return response


@pytest.fixture
def mock_{{ http_method }}_error_response():
    \"\"\"Mock failed {{ http_method.upper() }} response.\"\"\"
    from unittest.mock import Mock
    import requests

    response = Mock()
    response.status_code = {{ error_code }}
    response.raise_for_status.side_effect = requests.HTTPError("{{ error_code }} Error")

    return response
""")


class MockGenerator:
    """Generates mocks for API clients and external dependencies."""

    def __init__(self, project_root: str):
        self.project_root = Path(project_root)

    def analyze_api_client(self, filepath: str) -> List[APIMethod]:
        """
        Analyze API client file to identify methods to mock.

        Args:
            filepath: Path to API client file

        Returns:
            List of APIMethod instances
        """
        file_path = self.project_root / filepath

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source = f.read()

            tree = ast.parse(source, filename=str(file_path))
        except Exception:
            return []

        methods = []
        current_class = None

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                current_class = node.name

            if isinstance(node, ast.FunctionDef) and current_class:
                # Skip private methods and __init__
                if node.name.startswith('_'):
                    continue

                # Detect async
                is_async = isinstance(node, ast.AsyncFunctionDef)

                # Try to infer HTTP method from function name or code
                http_method = self._infer_http_method(node)

                if http_method:
                    method = APIMethod(
                        class_name=current_class,
                        method_name=node.name,
                        http_method=http_method,
                        is_async=is_async
                    )
                    methods.append(method)

        return methods

    def _infer_http_method(self, node: ast.FunctionDef) -> Optional[str]:
        """Infer HTTP method from function name or implementation."""
        name_lower = node.name.lower()

        # Check function name for HTTP verbs
        if any(verb in name_lower for verb in ['get', 'fetch', 'retrieve', 'list']):
            return 'get'
        elif any(verb in name_lower for verb in ['post', 'create', 'add']):
            return 'post'
        elif any(verb in name_lower for verb in ['put', 'update', 'modify']):
            return 'put'
        elif any(verb in name_lower for verb in ['delete', 'remove']):
            return 'delete'
        elif 'patch' in name_lower:
            return 'patch'

        # Analyze function body for requests calls
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    if child.func.attr in ['get', 'post', 'put', 'delete', 'patch']:
                        return child.func.attr

        return None

    def generate_mock_fixture(self, class_name: str, module_path: str,
                             methods: List[APIMethod]) -> str:
        """Generate pytest fixture for mocking an API client."""
        fixture_name = class_name.lower().replace('client', '').replace('api', '') + '_client'

        return API_MOCK_TEMPLATE.render(
            fixture_name=fixture_name,
            class_name=class_name,
            module_path=module_path,
            methods=methods
        )

    def generate_response_mocks(self, http_method: str,
                               expected_response: str = '{"status": "ok"}',
                               error_code: int = 500) -> str:
        """Generate mock HTTP response fixtures."""
        return API_CLIENT_MOCK_RESPONSE_TEMPLATE.render(
            http_method=http_method,
            expected_response=expected_response,
            error_code=error_code
        )


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python mock_generator.py <project_root> <api_client_file>")
        sys.exit(1)

    project_root = sys.argv[1]
    api_client_file = sys.argv[2] if len(sys.argv) > 2 else "src/api/client.py"

    generator = MockGenerator(project_root)
    methods = generator.analyze_api_client(api_client_file)

    print(f"Found {len(methods)} API methods to mock:")
    for method in methods:
        print(f"  - {method.class_name}.{method.method_name} ({method.http_method})")

    if methods:
        print("\n=== Generated Mock Fixture ===")
        fixture = generator.generate_mock_fixture(
            class_name=methods[0].class_name,
            module_path=f"{api_client_file.replace('/', '.').replace('.py', '')}",
            methods=methods
        )
        print(fixture)
```

**Step 2: Test on PelotonRacer**

Run: `python3 ~/.claude/skills/agents/agent-test/utils/mock_generator.py /Users/nissim/dev/PelotonRacer src/api/peloton_client.py`

Expected: Should detect API methods and generate mock fixtures

**Step 3: Commit**

```bash
git add ~/.claude/skills/agents/agent-test/utils/mock_generator.py
git commit -m "feat: add mock generator for API clients (Phase 2)"
```

---

## Phase 3: Security Agent Foundation

### Task 6: Create STRIDE threat modeler

**Files:**
- Create: `~/.claude/skills/agents/agent-security/threat_models/stride.py`

**Step 1: Write STRIDE analyzer**

```python
"""
STRIDE threat modeling implementation.
STRIDE = Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
"""

import ast
import re
from pathlib import Path
from typing import List, Dict, Set
from dataclasses import dataclass
from enum import Enum


class ThreatCategory(Enum):
    """STRIDE threat categories."""
    SPOOFING = "STRIDE-Spoofing"
    TAMPERING = "STRIDE-Tampering"
    REPUDIATION = "STRIDE-Repudiation"
    INFORMATION_DISCLOSURE = "STRIDE-InformationDisclosure"
    DENIAL_OF_SERVICE = "STRIDE-DenialOfService"
    ELEVATION_OF_PRIVILEGE = "STRIDE-ElevationOfPrivilege"


class Severity(Enum):
    """Threat severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Threat:
    """Represents a security threat."""
    id: str
    category: ThreatCategory
    severity: Severity
    title: str
    description: str
    affected_files: List[str]
    attack_scenario: str
    mitigation: str
    impact: str
    likelihood: str
    status: str = "open"  # open, mitigated, accepted
    cwe: str = None
    test_coverage: List[str] = None

    def __post_init__(self):
        if self.test_coverage is None:
            self.test_coverage = []


@dataclass
class TrustBoundary:
    """Represents a trust boundary in the system."""
    source: str
    destination: str
    data_flow: str


class STRIDEAnalyzer:
    """Performs STRIDE threat modeling on a codebase."""

    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.threats: List[Threat] = []
        self.threat_counter = 1

    def analyze(self, target_path: str = None) -> List[Threat]:
        """
        Perform STRIDE analysis on codebase.

        Args:
            target_path: Specific file or directory to analyze

        Returns:
            List of identified threats
        """
        self.threats = []
        self.threat_counter = 1

        # Identify trust boundaries
        boundaries = self._identify_trust_boundaries()

        # Analyze for each STRIDE category
        self._analyze_spoofing()
        self._analyze_tampering()
        self._analyze_repudiation()
        self._analyze_information_disclosure()
        self._analyze_denial_of_service()
        self._analyze_elevation_of_privilege()

        return self.threats

    def _identify_trust_boundaries(self) -> List[TrustBoundary]:
        """Identify trust boundaries in the application."""
        boundaries = []

        # Common trust boundaries to look for:
        # 1. User input → Application
        # 2. Application → External APIs
        # 3. Application → File System
        # 4. Application → Database
        # 5. Environment Variables → Application

        # Scan for API calls (external boundary)
        python_files = list(self.project_root.rglob("*.py"))
        for file in python_files:
            if self._file_contains_pattern(file, r'requests\.(get|post|put|delete|patch)'):
                boundaries.append(TrustBoundary(
                    source="Application",
                    destination="External API",
                    data_flow="HTTP requests/responses"
                ))
                break

        # Scan for file I/O (filesystem boundary)
        for file in python_files:
            if self._file_contains_pattern(file, r'open\(|Path\(.*\)\.write|Path\(.*\)\.read'):
                boundaries.append(TrustBoundary(
                    source="Application",
                    destination="File System",
                    data_flow="File read/write operations"
                ))
                break

        # Check for user input (Streamlit, input(), etc.)
        for file in python_files:
            if self._file_contains_pattern(file, r'st\.(text_input|number_input|file_uploader|selectbox)'):
                boundaries.append(TrustBoundary(
                    source="User",
                    destination="Application",
                    data_flow="User interface inputs"
                ))
                break

        # Check for environment variables (config boundary)
        for file in python_files:
            if self._file_contains_pattern(file, r'os\.getenv|load_dotenv'):
                boundaries.append(TrustBoundary(
                    source="Environment",
                    destination="Application",
                    data_flow="Configuration and secrets"
                ))
                break

        return boundaries

    def _analyze_spoofing(self):
        """Detect spoofing threats (impersonation, fake identity)."""
        # Look for authentication mechanisms
        auth_files = self._find_files_matching(r'auth|login|session')

        for file in auth_files:
            # Check for bearer token validation
            if self._file_contains_pattern(file, r'bearer|token|jwt'):
                # Check if there's validation
                if not self._file_contains_pattern(file, r'verify|validate|decode'):
                    self._add_threat(
                        category=ThreatCategory.SPOOFING,
                        severity=Severity.HIGH,
                        title="Missing token validation in authentication",
                        description=f"File {file.name} handles bearer tokens but may not validate them properly",
                        affected_files=[str(file.relative_to(self.project_root))],
                        attack_scenario="Attacker provides fake or expired token to impersonate legitimate user",
                        mitigation="Implement proper token validation (signature, expiry, issuer checks)",
                        impact="Unauthorized access to user accounts and data",
                        likelihood="Medium (requires token knowledge)",
                        cwe="CWE-287: Improper Authentication"
                    )

    def _analyze_tampering(self):
        """Detect tampering threats (data modification)."""
        # Look for file write operations without integrity checks
        files_with_writes = self._find_files_with_pattern(r'\.write\(|json\.dump|pickle\.dump')

        for file in files_with_writes:
            # Check if there's any integrity protection (hashing, signing)
            if not self._file_contains_pattern(file, r'hash|hmac|signature|checksum'):
                self._add_threat(
                    category=ThreatCategory.TAMPERING,
                    severity=Severity.MEDIUM,
                    title="Data files lack integrity protection",
                    description=f"File {file.name} writes data without integrity checks",
                    affected_files=[str(file.relative_to(self.project_root))],
                    attack_scenario="Attacker modifies stored data files to manipulate application behavior or corrupt data",
                    mitigation="Add integrity checks (HMAC, digital signatures) for critical data files",
                    impact="Data corruption, manipulation of application state",
                    likelihood="Low (requires file system access)",
                    cwe="CWE-353: Missing Support for Integrity Check"
                )

    def _analyze_repudiation(self):
        """Detect repudiation threats (lack of audit logging)."""
        # Look for authentication and sensitive operations
        sensitive_files = self._find_files_matching(r'auth|login|delete|update|admin')

        has_logging = any(
            self._file_contains_pattern(f, r'logging\.|logger\.')
            for f in self._find_files_matching('.')
        )

        if sensitive_files and not has_logging:
            self._add_threat(
                category=ThreatCategory.REPUDIATION,
                severity=Severity.LOW,
                title="Insufficient audit logging for sensitive operations",
                description="Application performs sensitive operations without logging",
                affected_files=[str(f.relative_to(self.project_root)) for f in sensitive_files[:3]],
                attack_scenario="User performs malicious action and denies it; no audit trail exists",
                mitigation="Implement comprehensive logging for authentication, data modifications, and admin actions",
                impact="Cannot trace security incidents or user actions",
                likelihood="Medium",
                cwe="CWE-778: Insufficient Logging"
            )

    def _analyze_information_disclosure(self):
        """Detect information disclosure threats (data leaks)."""
        # Check for credentials in code
        files_with_secrets = self._find_files_with_pattern(
            r'(api_key|secret|password|token)\s*=\s*["\'][^"\']{10,}'
        )

        for file in files_with_secrets:
            self._add_threat(
                category=ThreatCategory.INFORMATION_DISCLOSURE,
                severity=Severity.HIGH,
                title="Hardcoded credentials in source code",
                description=f"File {file.name} may contain hardcoded secrets",
                affected_files=[str(file.relative_to(self.project_root))],
                attack_scenario="Credentials committed to version control can be extracted by anyone with repository access",
                mitigation="Move all secrets to environment variables or secure secret management system",
                impact="Complete compromise of API access and user accounts",
                likelihood="High (if repo is public or has many collaborators)",
                cwe="CWE-798: Use of Hard-coded Credentials"
            )

        # Check for error messages that might leak info
        files_with_exceptions = self._find_files_with_pattern(r'except.*:\s*print|except.*:\s*st\.error')

        for file in files_with_exceptions:
            if self._file_contains_pattern(file, r'str\(e\)|exception\.'):
                self._add_threat(
                    category=ThreatCategory.INFORMATION_DISCLOSURE,
                    severity=Severity.MEDIUM,
                    title="Error messages may leak sensitive information",
                    description=f"File {file.name} displays raw exception messages to users",
                    affected_files=[str(file.relative_to(self.project_root))],
                    attack_scenario="Exception messages reveal internal paths, tokens, or system details",
                    mitigation="Sanitize error messages; log details but show generic messages to users",
                    impact="Information about system internals aids further attacks",
                    likelihood="Medium",
                    cwe="CWE-209: Information Exposure Through an Error Message"
                )

    def _analyze_denial_of_service(self):
        """Detect denial of service threats."""
        # Check for unbounded operations
        files_with_api_calls = self._find_files_with_pattern(r'requests\.(get|post)')

        for file in files_with_api_calls:
            # Check for rate limiting or pagination
            if not self._file_contains_pattern(file, r'sleep|rate_limit|throttle|timeout'):
                self._add_threat(
                    category=ThreatCategory.DENIAL_OF_SERVICE,
                    severity=Severity.MEDIUM,
                    title="API calls lack rate limiting",
                    description=f"File {file.name} makes external API calls without rate limiting",
                    affected_files=[str(file.relative_to(self.project_root))],
                    attack_scenario="Unbounded API requests exhaust rate limits or cause service degradation",
                    mitigation="Implement rate limiting, timeouts, and retry logic with exponential backoff",
                    impact="Service unavailability, API quota exhaustion",
                    likelihood="Medium",
                    cwe="CWE-400: Uncontrolled Resource Consumption"
                )

    def _analyze_elevation_of_privilege(self):
        """Detect elevation of privilege threats."""
        # Check for authorization checks
        files_with_permissions = self._find_files_matching(r'admin|role|permission|access')

        for file in files_with_permissions:
            # Look for permission checks
            if not self._file_contains_pattern(file, r'is_admin|has_permission|check_access|require_auth'):
                self._add_threat(
                    category=ThreatCategory.ELEVATION_OF_PRIVILEGE,
                    severity=Severity.HIGH,
                    title="Missing authorization checks",
                    description=f"File {file.name} handles privileged operations without authorization checks",
                    affected_files=[str(file.relative_to(self.project_root))],
                    attack_scenario="Regular user accesses admin functionality or other users' data",
                    mitigation="Implement role-based access control (RBAC) and verify permissions before sensitive operations",
                    impact="Unauthorized access to privileged functionality",
                    likelihood="Medium",
                    cwe="CWE-862: Missing Authorization"
                )

    def _add_threat(self, category: ThreatCategory, severity: Severity,
                   title: str, description: str, affected_files: List[str],
                   attack_scenario: str, mitigation: str, impact: str,
                   likelihood: str, cwe: str = None):
        """Add a threat to the list."""
        threat_id = f"THREAT-{self.threat_counter:03d}"
        self.threat_counter += 1

        threat = Threat(
            id=threat_id,
            category=category,
            severity=severity,
            title=title,
            description=description,
            affected_files=affected_files,
            attack_scenario=attack_scenario,
            mitigation=mitigation,
            impact=impact,
            likelihood=likelihood,
            cwe=cwe
        )

        self.threats.append(threat)

    def _find_files_matching(self, pattern: str) -> List[Path]:
        """Find files whose names match a pattern."""
        python_files = list(self.project_root.rglob("*.py"))
        # Exclude common non-source directories
        excluded = {'__pycache__', '.venv', 'venv', 'env', 'build', 'dist', 'tests', 'test'}

        matching = []
        for file in python_files:
            if any(part in excluded for part in file.parts):
                continue
            if re.search(pattern, file.name, re.IGNORECASE):
                matching.append(file)

        return matching

    def _find_files_with_pattern(self, pattern: str) -> List[Path]:
        """Find files whose content matches a pattern."""
        python_files = list(self.project_root.rglob("*.py"))
        excluded = {'__pycache__', '.venv', 'venv', 'env', 'build', 'dist', 'tests', 'test'}

        matching = []
        for file in python_files:
            if any(part in excluded for part in file.parts):
                continue

            if self._file_contains_pattern(file, pattern):
                matching.append(file)

        return matching

    def _file_contains_pattern(self, filepath: Path, pattern: str) -> bool:
        """Check if file content matches regex pattern."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            return bool(re.search(pattern, content))
        except Exception:
            return False


if __name__ == "__main__":
    import sys

    project_root = sys.argv[1] if len(sys.argv) > 1 else "."

    analyzer = STRIDEAnalyzer(project_root)
    threats = analyzer.analyze()

    print(f"STRIDE Threat Analysis")
    print(f"======================")
    print(f"Found {len(threats)} threats\n")

    for threat in threats:
        print(f"{threat.id}: {threat.title}")
        print(f"  Category: {threat.category.value}")
        print(f"  Severity: {threat.severity.value}")
        print(f"  Files: {', '.join(threat.affected_files)}")
        print()
```

**Step 2: Test STRIDE analyzer on PelotonRacer**

Run: `python3 ~/.claude/skills/agents/agent-security/threat_models/stride.py /Users/nissim/dev/PelotonRacer`

Expected: Should identify STRIDE threats in the codebase

**Step 3: Commit**

```bash
git add ~/.claude/skills/agents/agent-security/threat_models/stride.py
git commit -m "feat: add STRIDE threat modeling analyzer (Phase 3)"
```

---

### Task 7: Create OWASP Top 10 scanner

**Files:**
- Create: `~/.claude/skills/agents/agent-security/threat_models/owasp.py`

**Step 2: Write OWASP Top 10 scanner**

```python
"""
OWASP Top 10 vulnerability scanner.
"""

import re
from pathlib import Path
from typing import List, Dict, Set
from dataclasses import dataclass
from enum import Enum


class OWASPCategory(Enum):
    """OWASP Top 10 2021 categories."""
    A01_BROKEN_ACCESS_CONTROL = "OWASP-A01-BrokenAccessControl"
    A02_CRYPTOGRAPHIC_FAILURES = "OWASP-A02-CryptographicFailures"
    A03_INJECTION = "OWASP-A03-Injection"
    A04_INSECURE_DESIGN = "OWASP-A04-InsecureDesign"
    A05_SECURITY_MISCONFIGURATION = "OWASP-A05-SecurityMisconfiguration"
    A06_VULNERABLE_COMPONENTS = "OWASP-A06-VulnerableComponents"
    A07_AUTHENTICATION_FAILURES = "OWASP-A07-AuthenticationFailures"
    A08_DATA_INTEGRITY_FAILURES = "OWASP-A08-DataIntegrityFailures"
    A09_LOGGING_FAILURES = "OWASP-A09-LoggingFailures"
    A10_SSRF = "OWASP-A10-SSRF"


@dataclass
class Vulnerability:
    """Represents an OWASP vulnerability finding."""
    id: str
    category: OWASPCategory
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    affected_files: List[str]
    line_numbers: List[int]
    cwe: str
    mitigation: str
    code_example: str = None
    status: str = "open"


class OWASPScanner:
    """Scans for OWASP Top 10 vulnerabilities."""

    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.vulnerabilities: List[Vulnerability] = []
        self.vuln_counter = 1

    def scan(self, target_path: str = None) -> List[Vulnerability]:
        """
        Scan codebase for OWASP Top 10 vulnerabilities.

        Args:
            target_path: Specific file or directory to scan

        Returns:
            List of vulnerabilities
        """
        self.vulnerabilities = []
        self.vuln_counter = 1

        # Run all OWASP checks
        self._check_a01_broken_access_control()
        self._check_a02_cryptographic_failures()
        self._check_a03_injection()
        self._check_a04_insecure_design()
        self._check_a05_security_misconfiguration()
        self._check_a07_authentication_failures()
        self._check_a08_data_integrity_failures()
        self._check_a09_logging_failures()
        self._check_a10_ssrf()

        return self.vulnerabilities

    def _check_a01_broken_access_control(self):
        """Check for broken access control issues."""
        # Look for direct object references without authorization
        files = self._find_python_files()

        for file in files:
            content = self._read_file(file)
            if not content:
                continue

            # Check for file path operations with user input
            if re.search(r'Path\([^)]*input|Path\([^)]*request\.|Path\([^)]*st\.(text_input|selectbox)', content):
                if not re.search(r'resolve\(\)|abspath|realpath', content):
                    self._add_vulnerability(
                        category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                        severity="HIGH",
                        title="Potential path traversal vulnerability",
                        description=f"File operations use user input without path validation",
                        affected_files=[str(file.relative_to(self.project_root))],
                        cwe="CWE-22: Path Traversal",
                        mitigation="Use Path.resolve() and validate paths stay within allowed directory",
                        code_example="# Secure:\npath = Path(user_input).resolve()\nif not path.is_relative_to(allowed_dir):\n    raise ValueError('Access denied')"
                    )

    def _check_a02_cryptographic_failures(self):
        """Check for cryptographic failures."""
        files = self._find_python_files()

        for file in files:
            content = self._read_file(file)
            if not content:
                continue

            # Check for hardcoded secrets
            secret_patterns = [
                (r'(api[_-]?key|apikey)\s*=\s*["\'][a-zA-Z0-9]{20,}["\']', "API key"),
                (r'(password|passwd|pwd)\s*=\s*["\'][^"\']{3,}["\']', "Password"),
                (r'(secret|token)\s*=\s*["\'][a-zA-Z0-9+/=]{20,}["\']', "Secret/Token"),
                (r'(aws_access_key|aws_secret)\s*=\s*["\'][A-Z0-9]{20,}["\']', "AWS credentials"),
            ]

            for pattern, secret_type in secret_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    # Skip if it's in a comment or example
                    line = content[max(0, match.start()-100):match.end()+100]
                    if '#' in line or 'example' in line.lower() or 'todo' in line.lower():
                        continue

                    self._add_vulnerability(
                        category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                        severity="CRITICAL",
                        title=f"Hardcoded {secret_type} in source code",
                        description=f"Hardcoded credentials found in {file.name}",
                        affected_files=[str(file.relative_to(self.project_root))],
                        cwe="CWE-798: Use of Hard-coded Credentials",
                        mitigation="Move all secrets to environment variables or secure vault",
                        code_example="# Secure:\nimport os\napi_key = os.getenv('API_KEY')\nif not api_key:\n    raise ValueError('API_KEY not configured')"
                    )

            # Check for weak hashing
            if re.search(r'\bmd5\b|\bsha1\b', content):
                self._add_vulnerability(
                    category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                    severity="MEDIUM",
                    title="Weak cryptographic hash function",
                    description=f"Use of MD5 or SHA1 detected in {file.name}",
                    affected_files=[str(file.relative_to(self.project_root))],
                    cwe="CWE-327: Use of Broken Crypto",
                    mitigation="Use SHA-256 or better (bcrypt for passwords)",
                    code_example="# Secure:\nimport hashlib\nhash = hashlib.sha256(data.encode()).hexdigest()"
                )

    def _check_a03_injection(self):
        """Check for injection vulnerabilities."""
        files = self._find_python_files()

        for file in files:
            content = self._read_file(file)
            if not content:
                continue

            # SQL Injection (if using DB)
            if re.search(r'execute\(["\'].*%s.*["\'].*%|execute\(["\'].*\+.*["\']|execute\(f["\']', content):
                self._add_vulnerability(
                    category=OWASPCategory.A03_INJECTION,
                    severity="HIGH",
                    title="Potential SQL injection",
                    description=f"SQL query uses string formatting instead of parameterization",
                    affected_files=[str(file.relative_to(self.project_root))],
                    cwe="CWE-89: SQL Injection",
                    mitigation="Use parameterized queries with placeholders",
                    code_example="# Secure:\ncursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
                )

            # Command Injection
            if re.search(r'subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True', content):
                self._add_vulnerability(
                    category=OWASPCategory.A03_INJECTION,
                    severity="HIGH",
                    title="Command injection risk with shell=True",
                    description=f"Subprocess call with shell=True can enable command injection",
                    affected_files=[str(file.relative_to(self.project_root))],
                    cwe="CWE-78: OS Command Injection",
                    mitigation="Avoid shell=True; use list arguments instead",
                    code_example="# Secure:\nsubprocess.run(['ls', '-la', directory])"
                )

    def _check_a04_insecure_design(self):
        """Check for insecure design patterns."""
        # Check if .env.example exists
        env_example = self.project_root / ".env.example"
        if not env_example.exists():
            env_file = self.project_root / ".env"
            if env_file.exists():
                self._add_vulnerability(
                    category=OWASPCategory.A04_INSECURE_DESIGN,
                    severity="LOW",
                    title="Missing .env.example template",
                    description=".env file exists but no .env.example template for developers",
                    affected_files=[".env"],
                    cwe="CWE-1188: Insecure Default Initialization",
                    mitigation="Create .env.example with placeholder values",
                    code_example="# .env.example:\nAPI_KEY=your_api_key_here\nDATABASE_URL=postgresql://localhost/dbname"
                )

    def _check_a05_security_misconfiguration(self):
        """Check for security misconfigurations."""
        # Check if .env is in .gitignore
        gitignore = self.project_root / ".gitignore"
        if gitignore.exists():
            gitignore_content = self._read_file(gitignore)
            if gitignore_content and '.env' not in gitignore_content:
                self._add_vulnerability(
                    category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                    severity="HIGH",
                    title=".env file not in .gitignore",
                    description="Secrets in .env could be committed to version control",
                    affected_files=[".gitignore"],
                    cwe="CWE-538: File and Directory Information Exposure",
                    mitigation="Add .env to .gitignore immediately",
                    code_example="# Add to .gitignore:\n.env\n*.env.local\n.env.*.local"
                )

        # Check for debug mode in production
        files = self._find_python_files()
        for file in files:
            content = self._read_file(file)
            if re.search(r'debug\s*=\s*True|DEBUG\s*=\s*True', content):
                self._add_vulnerability(
                    category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                    severity="MEDIUM",
                    title="Debug mode may be enabled",
                    description=f"Hardcoded debug=True found in {file.name}",
                    affected_files=[str(file.relative_to(self.project_root))],
                    cwe="CWE-489: Active Debug Code",
                    mitigation="Use environment variable for debug flag",
                    code_example="# Secure:\nimport os\nDEBUG = os.getenv('DEBUG', 'false').lower() == 'true'"
                )

    def _check_a07_authentication_failures(self):
        """Check for authentication failures."""
        files = self._find_python_files()

        for file in files:
            content = self._read_file(file)
            if not content:
                continue

            # Check for authentication logic
            if re.search(r'def\s+login|def\s+authenticate|class.*Auth', content):
                # Check for password in plaintext comparison
                if re.search(r'password\s*==\s*["\']|if.*password.*==', content):
                    self._add_vulnerability(
                        category=OWASPCategory.A07_AUTHENTICATION_FAILURES,
                        severity="HIGH",
                        title="Plaintext password comparison",
                        description=f"Password comparison without hashing in {file.name}",
                        affected_files=[str(file.relative_to(self.project_root))],
                        cwe="CWE-256: Plaintext Storage of Password",
                        mitigation="Hash passwords with bcrypt or argon2",
                        code_example="# Secure:\nimport bcrypt\nbcrypt.checkpw(password.encode(), stored_hash)"
                    )

    def _check_a08_data_integrity_failures(self):
        """Check for data integrity failures."""
        files = self._find_python_files()

        for file in files:
            content = self._read_file(file)
            if not content:
                continue

            # Check for insecure deserialization
            if re.search(r'\bpickle\.loads?\(|yaml\.load\((?!.*Loader)', content):
                self._add_vulnerability(
                    category=OWASPCategory.A08_DATA_INTEGRITY_FAILURES,
                    severity="HIGH",
                    title="Insecure deserialization",
                    description=f"Use of pickle or unsafe yaml.load in {file.name}",
                    affected_files=[str(file.relative_to(self.project_root))],
                    cwe="CWE-502: Deserialization of Untrusted Data",
                    mitigation="Use JSON or yaml.safe_load() instead",
                    code_example="# Secure:\nimport yaml\ndata = yaml.safe_load(content)"
                )

    def _check_a09_logging_failures(self):
        """Check for logging failures."""
        files = self._find_python_files()

        # Check if logging is configured at all
        has_logging = any(
            self._file_contains_pattern(f, r'import logging|from logging')
            for f in files
        )

        if not has_logging:
            self._add_vulnerability(
                category=OWASPCategory.A09_LOGGING_FAILURES,
                severity="LOW",
                title="No logging configured",
                description="Application has no logging for security events",
                affected_files=["(project-wide)"],
                cwe="CWE-778: Insufficient Logging",
                mitigation="Implement logging for auth events, errors, and security-relevant actions",
                code_example="# Add logging:\nimport logging\nlogger = logging.getLogger(__name__)\nlogger.info('User login attempt', extra={'user': username})"
            )

        # Check for sensitive data in logs
        for file in files:
            content = self._read_file(file)
            if re.search(r'log.*password|log.*token|log.*secret|print.*password', content, re.IGNORECASE):
                self._add_vulnerability(
                    category=OWASPCategory.A09_LOGGING_FAILURES,
                    severity="HIGH",
                    title="Sensitive data in logs",
                    description=f"Logging potentially contains passwords/tokens in {file.name}",
                    affected_files=[str(file.relative_to(self.project_root))],
                    cwe="CWE-532: Information Exposure Through Log Files",
                    mitigation="Sanitize sensitive fields before logging",
                    code_example="# Secure:\ndef sanitize(data):\n    safe = data.copy()\n    for key in ['password', 'token', 'secret']:\n        if key in safe:\n            safe[key] = '[REDACTED]'\n    return safe"
                )

    def _check_a10_ssrf(self):
        """Check for Server-Side Request Forgery."""
        files = self._find_python_files()

        for file in files:
            content = self._read_file(file)
            if not content:
                continue

            # Check for URL fetching with user input
            if re.search(r'requests\.(get|post)\([^)]*input|requests\.(get|post)\([^)]*request\.|urllib\.request\.urlopen', content):
                self._add_vulnerability(
                    category=OWASPCategory.A10_SSRF,
                    severity="MEDIUM",
                    title="Potential SSRF vulnerability",
                    description=f"HTTP request uses user-controlled URL in {file.name}",
                    affected_files=[str(file.relative_to(self.project_root))],
                    cwe="CWE-918: Server-Side Request Forgery",
                    mitigation="Validate URLs against allowlist; block private IPs",
                    code_example="# Secure:\nfrom urllib.parse import urlparse\nallowed_hosts = ['api.example.com']\nparsed = urlparse(url)\nif parsed.hostname not in allowed_hosts:\n    raise ValueError('Invalid URL')"
                )

    def _add_vulnerability(self, category: OWASPCategory, severity: str,
                          title: str, description: str, affected_files: List[str],
                          cwe: str, mitigation: str, code_example: str = None):
        """Add a vulnerability to the list."""
        vuln_id = f"VULN-{self.vuln_counter:03d}"
        self.vuln_counter += 1

        vuln = Vulnerability(
            id=vuln_id,
            category=category,
            severity=severity,
            title=title,
            description=description,
            affected_files=affected_files,
            line_numbers=[],  # Could be enhanced to track exact lines
            cwe=cwe,
            mitigation=mitigation,
            code_example=code_example
        )

        self.vulnerabilities.append(vuln)

    def _find_python_files(self) -> List[Path]:
        """Find all Python files in project."""
        python_files = list(self.project_root.rglob("*.py"))
        excluded = {'__pycache__', '.venv', 'venv', 'env', 'build', 'dist'}

        return [
            f for f in python_files
            if not any(part in excluded for part in f.parts)
        ]

    def _read_file(self, filepath: Path) -> str:
        """Read file content safely."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception:
            return None

    def _file_contains_pattern(self, filepath: Path, pattern: str) -> bool:
        """Check if file contains regex pattern."""
        content = self._read_file(filepath)
        if content:
            return bool(re.search(pattern, content))
        return False


if __name__ == "__main__":
    import sys

    project_root = sys.argv[1] if len(sys.argv) > 1 else "."

    scanner = OWASPScanner(project_root)
    vulns = scanner.scan()

    print(f"OWASP Top 10 Scan Results")
    print(f"=========================")
    print(f"Found {len(vulns)} vulnerabilities\n")

    # Group by severity
    by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
    for v in vulns:
        by_severity[v.severity].append(v)

    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if by_severity[severity]:
            print(f"\n{severity} Severity ({len(by_severity[severity])})")
            print("=" * 40)
            for v in by_severity[severity]:
                print(f"{v.id}: {v.title}")
                print(f"  Category: {v.category.value}")
                print(f"  Files: {', '.join(v.affected_files)}")
                print(f"  CWE: {v.cwe}")
                print()
```

**Step 3: Test OWASP scanner**

Run: `python3 ~/.claude/skills/agents/agent-security/threat_models/owasp.py /Users/nissim/dev/PelotonRacer`

Expected: Should identify OWASP vulnerabilities

**Step 4: Commit**

```bash
git add ~/.claude/skills/agents/agent-security/threat_models/owasp.py
git commit -m "feat: add OWASP Top 10 vulnerability scanner (Phase 3)"
```

---

### Task 8: Create configuration file scanner

**Files:**
- Create: `~/.claude/skills/agents/agent-security/scanners/config_scanner.py`

**Step 1: Write config scanner**

```python
"""
Configuration file security scanner.
Checks .env, .gitignore, and other config files for security issues.
"""

from pathlib import Path
from typing import List, Dict, Tuple
from dataclasses import dataclass


@dataclass
class ConfigIssue:
    """Represents a configuration security issue."""
    severity: str
    file: str
    issue: str
    recommendation: str
    auto_fixable: bool = False


class ConfigScanner:
    """Scans configuration files for security issues."""

    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.issues: List[ConfigIssue] = []

    def scan(self) -> List[ConfigIssue]:
        """
        Scan configuration files for security issues.

        Returns:
            List of configuration issues
        """
        self.issues = []

        self._check_gitignore()
        self._check_env_files()
        self._check_requirements()

        return self.issues

    def _check_gitignore(self):
        """Check .gitignore for security patterns."""
        gitignore_path = self.project_root / ".gitignore"

        if not gitignore_path.exists():
            self.issues.append(ConfigIssue(
                severity="MEDIUM",
                file=".gitignore",
                issue="No .gitignore file found",
                recommendation="Create .gitignore to prevent committing sensitive files",
                auto_fixable=True
            ))
            return

        with open(gitignore_path, 'r') as f:
            content = f.read()

        # Check for critical patterns
        required_patterns = {
            '.env': 'Environment files with secrets',
            '*.pem': 'Private keys',
            '*.key': 'Key files',
            '.DS_Store': 'macOS system files',
            '__pycache__': 'Python cache',
        }

        missing = []
        for pattern, description in required_patterns.items():
            if pattern not in content:
                missing.append((pattern, description))

        if missing:
            self.issues.append(ConfigIssue(
                severity="HIGH",
                file=".gitignore",
                issue=f"Missing {len(missing)} security patterns: {', '.join(p for p, _ in missing)}",
                recommendation="Add patterns to prevent committing sensitive files",
                auto_fixable=True
            ))

    def _check_env_files(self):
        """Check .env file security."""
        env_path = self.project_root / ".env"
        env_example_path = self.project_root / ".env.example"

        # Check if .env exists
        if env_path.exists():
            # Check if .env.example exists
            if not env_example_path.exists():
                self.issues.append(ConfigIssue(
                    severity="MEDIUM",
                    file=".env",
                    issue=".env exists but no .env.example template",
                    recommendation="Create .env.example with placeholder values for documentation",
                    auto_fixable=True
                ))

            # Check .env permissions (Unix only)
            try:
                import stat
                mode = env_path.stat().st_mode
                if mode & stat.S_IRGRP or mode & stat.S_IROTH:
                    self.issues.append(ConfigIssue(
                        severity="HIGH",
                        file=".env",
                        issue=".env file is readable by group or others",
                        recommendation="Set permissions to 600 (chmod 600 .env)",
                        auto_fixable=False
                    ))
            except Exception:
                pass

            # Check for actual secrets in .env (basic heuristic)
            with open(env_path, 'r') as f:
                env_content = f.read()

            if 'your_' in env_content.lower() or 'placeholder' in env_content.lower():
                self.issues.append(ConfigIssue(
                    severity="LOW",
                    file=".env",
                    issue=".env may contain placeholder values",
                    recommendation="Ensure .env has actual credentials configured",
                    auto_fixable=False
                ))

    def _check_requirements(self):
        """Check requirements.txt for known issues."""
        req_path = self.project_root / "requirements.txt"

        if not req_path.exists():
            return

        with open(req_path, 'r') as f:
            requirements = f.readlines()

        # Check for unpinned versions
        unpinned = []
        for line in requirements:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Check if version is pinned
            if '==' not in line and '>=' not in line:
                package = line.split('[')[0].strip()  # Handle extras like package[extra]
                unpinned.append(package)

        if unpinned:
            self.issues.append(ConfigIssue(
                severity="LOW",
                file="requirements.txt",
                issue=f"{len(unpinned)} packages without version pins: {', '.join(unpinned[:5])}{'...' if len(unpinned) > 5 else ''}",
                recommendation="Pin package versions to ensure reproducible builds",
                auto_fixable=False
            ))

    def auto_fix_issues(self) -> List[str]:
        """
        Automatically fix issues that are auto-fixable.

        Returns:
            List of files that were modified
        """
        fixed_files = []

        for issue in self.issues:
            if not issue.auto_fixable:
                continue

            if issue.file == ".gitignore":
                if "No .gitignore" in issue.issue:
                    self._create_gitignore()
                    fixed_files.append(".gitignore")
                elif "Missing" in issue.issue:
                    self._update_gitignore()
                    fixed_files.append(".gitignore")

            elif issue.file == ".env" and ".env.example" in issue.issue:
                self._create_env_example()
                fixed_files.append(".env.example")

        return list(set(fixed_files))

    def _create_gitignore(self):
        """Create a basic .gitignore file."""
        gitignore_content = """# Environment variables
.env
.env.local
.env.*.local
*.env

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual environments
venv/
env/
ENV/
.venv

# IDEs
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Keys and secrets
*.pem
*.key
*.p12
*.pfx
*.cer
*.crt

# Logs
*.log

# Coverage
.coverage
htmlcov/
.pytest_cache/
coverage.json
"""
        gitignore_path = self.project_root / ".gitignore"
        with open(gitignore_path, 'w') as f:
            f.write(gitignore_content)

    def _update_gitignore(self):
        """Add missing patterns to .gitignore."""
        gitignore_path = self.project_root / ".gitignore"

        with open(gitignore_path, 'r') as f:
            content = f.read()

        additions = []
        required = {'.env', '*.pem', '*.key', '.DS_Store', '__pycache__'}

        for pattern in required:
            if pattern not in content:
                additions.append(pattern)

        if additions:
            with open(gitignore_path, 'a') as f:
                f.write('\n# Security patterns (auto-added)\n')
                for pattern in additions:
                    f.write(f'{pattern}\n')

    def _create_env_example(self):
        """Create .env.example from .env."""
        env_path = self.project_root / ".env"
        env_example_path = self.project_root / ".env.example"

        with open(env_path, 'r') as f:
            env_lines = f.readlines()

        example_lines = []
        for line in env_lines:
            line = line.strip()
            if not line or line.startswith('#'):
                example_lines.append(line)
                continue

            # Replace values with placeholders
            if '=' in line:
                key, _ = line.split('=', 1)
                example_lines.append(f"{key}=your_{key.lower()}_here")
            else:
                example_lines.append(line)

        with open(env_example_path, 'w') as f:
            f.write('\n'.join(example_lines))


if __name__ == "__main__":
    import sys

    project_root = sys.argv[1] if len(sys.argv) > 1 else "."

    scanner = ConfigScanner(project_root)
    issues = scanner.scan()

    print(f"Configuration Security Scan")
    print(f"===========================")
    print(f"Found {len(issues)} issues\n")

    for issue in issues:
        print(f"[{issue.severity}] {issue.file}")
        print(f"  Issue: {issue.issue}")
        print(f"  Fix: {issue.recommendation}")
        print(f"  Auto-fixable: {'Yes' if issue.auto_fixable else 'No'}")
        print()

    # Ask about auto-fix
    auto_fixable = [i for i in issues if i.auto_fixable]
    if auto_fixable:
        print(f"\n{len(auto_fixable)} issues can be auto-fixed.")
        response = input("Apply auto-fixes? (y/n): ")
        if response.lower() == 'y':
            fixed = scanner.auto_fix_issues()
            print(f"Fixed files: {', '.join(fixed)}")
```

**Step 2: Test config scanner**

Run: `python3 ~/.claude/skills/agents/agent-security/scanners/config_scanner.py /Users/nissim/dev/PelotonRacer`

Expected: Should identify config security issues

**Step 3: Commit**

```bash
git add ~/.claude/skills/agents/agent-security/scanners/config_scanner.py
git commit -m "feat: add configuration file security scanner (Phase 3)"
```

---

## Phase 4: Security Agent Enhancements

### Task 9: Create dependency vulnerability scanner

**Files:**
- Create: `~/.claude/skills/agents/agent-security/scanners/dependency_scanner.py`

**Step 1: Write dependency scanner**

```python
"""
Dependency vulnerability scanner using pip-audit or safety.
"""

import subprocess
import json
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class VulnerableDependency:
    """Represents a vulnerable package."""
    package: str
    installed_version: str
    vulnerability_id: str  # CVE or PYSEC ID
    severity: str
    description: str
    fixed_version: Optional[str]


class DependencyScanner:
    """Scans Python dependencies for known vulnerabilities."""

    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.requirements_file = self.project_root / "requirements.txt"

    def scan(self) -> List[VulnerableDependency]:
        """
        Scan dependencies for vulnerabilities.

        Uses pip-audit if available, otherwise provides basic checks.

        Returns:
            List of vulnerable dependencies
        """
        if not self.requirements_file.exists():
            return []

        # Try pip-audit first (most comprehensive)
        try:
            return self._scan_with_pip_audit()
        except Exception:
            # Fall back to basic version checking
            return self._scan_basic()

    def _scan_with_pip_audit(self) -> List[VulnerableDependency]:
        """Scan using pip-audit (if installed)."""
        try:
            result = subprocess.run(
                ['pip-audit', '--requirement', str(self.requirements_file), '--format', 'json'],
                capture_output=True,
                text=True,
                cwd=self.project_root,
                timeout=60
            )

            if result.returncode == 0:
                data = json.loads(result.stdout)
                return self._parse_pip_audit_results(data)
            else:
                # pip-audit not installed or failed
                raise Exception("pip-audit failed")

        except FileNotFoundError:
            # pip-audit not installed
            raise Exception("pip-audit not found")

    def _parse_pip_audit_results(self, data: Dict) -> List[VulnerableDependency]:
        """Parse pip-audit JSON output."""
        vulnerabilities = []

        for vuln_entry in data.get('vulnerabilities', []):
            package = vuln_entry.get('name', 'unknown')
            version = vuln_entry.get('version', 'unknown')

            for vuln in vuln_entry.get('vulns', []):
                vulnerabilities.append(VulnerableDependency(
                    package=package,
                    installed_version=version,
                    vulnerability_id=vuln.get('id', 'UNKNOWN'),
                    severity=self._map_severity(vuln.get('severity')),
                    description=vuln.get('description', 'No description'),
                    fixed_version=vuln.get('fix_versions', [None])[0]
                ))

        return vulnerabilities

    def _scan_basic(self) -> List[VulnerableDependency]:
        """
        Basic dependency check without pip-audit.
        Just checks for known problematic packages.
        """
        vulnerabilities = []

        # Read requirements
        with open(self.requirements_file, 'r') as f:
            requirements = f.readlines()

        # Known vulnerable package patterns (this is a simplified list)
        known_issues = {
            'requests': ('2.28.0', 'CVE-2023-32681', 'HIGH', 'Update to 2.31.0+'),
            'urllib3': ('1.26.0', 'CVE-2023-45803', 'MEDIUM', 'Update to 2.0.7+'),
            'pillow': ('9.0.0', 'CVE-2023-44271', 'HIGH', 'Update to 10.0.1+'),
        }

        for line in requirements:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Parse package and version
            if '==' in line:
                package, version = line.split('==')
                package = package.strip().lower()
                version = version.strip().split(';')[0].split('#')[0].strip()

                # Check against known issues
                if package in known_issues:
                    min_vuln_version, cve, severity, fix = known_issues[package]
                    # Simplified version comparison
                    if self._version_compare(version, min_vuln_version) <= 0:
                        vulnerabilities.append(VulnerableDependency(
                            package=package,
                            installed_version=version,
                            vulnerability_id=cve,
                            severity=severity,
                            description=f"Known vulnerability in {package}",
                            fixed_version=fix
                        ))

        return vulnerabilities

    def _map_severity(self, severity: Optional[str]) -> str:
        """Map various severity formats to standard levels."""
        if not severity:
            return "MEDIUM"

        severity_upper = severity.upper()

        if any(s in severity_upper for s in ['CRITICAL', 'URGENT']):
            return "CRITICAL"
        elif 'HIGH' in severity_upper:
            return "HIGH"
        elif 'LOW' in severity_upper:
            return "LOW"
        else:
            return "MEDIUM"

    def _version_compare(self, v1: str, v2: str) -> int:
        """
        Simple version comparison.
        Returns: -1 if v1 < v2, 0 if equal, 1 if v1 > v2
        """
        try:
            parts1 = [int(p) for p in v1.split('.')]
            parts2 = [int(p) for p in v2.split('.')]

            # Pad to same length
            max_len = max(len(parts1), len(parts2))
            parts1.extend([0] * (max_len - len(parts1)))
            parts2.extend([0] * (max_len - len(parts2)))

            for p1, p2 in zip(parts1, parts2):
                if p1 < p2:
                    return -1
                elif p1 > p2:
                    return 1

            return 0
        except Exception:
            return 0

    def check_outdated_packages(self) -> List[Dict[str, str]]:
        """Check for outdated packages using pip list --outdated."""
        try:
            result = subprocess.run(
                ['pip', 'list', '--outdated', '--format=json'],
                capture_output=True,
                text=True,
                cwd=self.project_root,
                timeout=30
            )

            if result.returncode == 0:
                data = json.loads(result.stdout)
                return [
                    {
                        'name': pkg['name'],
                        'current': pkg['version'],
                        'latest': pkg['latest_version']
                    }
                    for pkg in data
                ]
        except Exception:
            pass

        return []


if __name__ == "__main__":
    import sys

    project_root = sys.argv[1] if len(sys.argv) > 1 else "."

    scanner = DependencyScanner(project_root)

    print("Dependency Vulnerability Scan")
    print("=============================\n")

    vulns = scanner.scan()

    if vulns:
        print(f"Found {len(vulns)} vulnerable dependencies:\n")
        for v in vulns:
            print(f"[{v.severity}] {v.package} {v.installed_version}")
            print(f"  ID: {v.vulnerability_id}")
            print(f"  Description: {v.description}")
            if v.fixed_version:
                print(f"  Fix: Update to {v.fixed_version}")
            print()
    else:
        print("No known vulnerabilities found.")

    print("\nChecking for outdated packages...")
    outdated = scanner.check_outdated_packages()
    if outdated:
        print(f"Found {len(outdated)} outdated packages:")
        for pkg in outdated[:10]:
            print(f"  - {pkg['name']}: {pkg['current']} -> {pkg['latest']}")
    else:
        print("All packages are up to date (or pip list failed).")
```

**Step 2: Test dependency scanner**

Run: `python3 ~/.claude/skills/agents/agent-security/scanners/dependency_scanner.py /Users/nissim/dev/PelotonRacer`

Expected: Should check dependencies for vulnerabilities

**Step 3: Commit**

```bash
git add ~/.claude/skills/agents/agent-security/scanners/dependency_scanner.py
git commit -m "feat: add dependency vulnerability scanner (Phase 4)"
```

---

### Task 10: Create security agent skill definition

**Files:**
- Create: `~/.claude/skills/agents/agent-security/skill.md`

**Step 1: Write security agent skill**

```markdown
---
name: agent:security
description: Security threat modeling and vulnerability scanning agent using STRIDE and OWASP Top 10
---

# Security Agent

You are a security agent that performs comprehensive threat modeling and vulnerability scanning on codebases.

## Your Capabilities

1. **STRIDE Threat Modeling**: Identify architecture-level threats
2. **OWASP Top 10 Scanning**: Detect implementation vulnerabilities
3. **Configuration Scanning**: Check .env, .gitignore, requirements.txt
4. **Dependency Scanning**: Identify vulnerable packages
5. **Auto-Hardening**: Fix configuration issues automatically
6. **Reporting**: Generate JSON + Markdown threat models

## Operating Modes

### Semi-Autonomous Operation

- **Automatically**: Modify config files (.gitignore, .env.example)
- **Ask for approval**: Before modifying production code
- **Never**: Make destructive changes without clear justification

## Workflow

When invoked, follow these steps:

### 1. Parse Arguments

Handle these flags:
- `--quick`: Quick scan (OWASP only, no STRIDE)
- `--full`: Deep analysis with dependency audit
- `--file <path>`: Target specific file or directory
- No arguments: Sensible defaults (STRIDE + OWASP + config)

### 2. Run STRIDE Threat Modeling

Use the STRIDE analyzer to identify design-level threats:

```python
from threat_models.stride import STRIDEAnalyzer

stride = STRIDEAnalyzer(project_root)
stride_threats = stride.analyze(target_path=args.file if args.file else None)

print(f"🛡️ Running STRIDE threat modeling...")
print(f"✅ Identified {len(stride_threats)} architectural threats")
```

### 3. Run OWASP Code Scanning

Use the OWASP scanner for implementation vulnerabilities:

```python
from threat_models.owasp import OWASPScanner

owasp = OWASPScanner(project_root)
owasp_vulns = owasp.scan(target_path=args.file if args.file else None)

print(f"🔒 Running OWASP Top 10 code analysis...")
print(f"⚠️ Found {len(owasp_vulns)} vulnerabilities")
```

### 4. Scan Configuration Files

Check security configuration:

```python
from scanners.config_scanner import ConfigScanner

config_scanner = ConfigScanner(project_root)
config_issues = config_scanner.scan()

print(f"📋 Scanning configuration files...")
print(f"⚠️ Found {len(config_issues)} configuration issues")
```

### 5. Scan Dependencies (if --full)

Check for vulnerable packages:

```python
if args.full:
    from scanners.dependency_scanner import DependencyScanner

    dep_scanner = DependencyScanner(project_root)
    dep_vulns = dep_scanner.scan()
    outdated = dep_scanner.check_outdated_packages()

    print(f"📦 Scanning dependencies...")
    print(f"⚠️ Found {len(dep_vulns)} vulnerable packages")
    print(f"📅 Found {len(outdated)} outdated packages")
```

### 6. Auto-Fix Configuration Issues

Offer to fix auto-fixable issues:

```python
auto_fixable = [issue for issue in config_issues if issue.auto_fixable]

if auto_fixable:
    print(f"\n💡 {len(auto_fixable)} issues can be auto-fixed:")
    for issue in auto_fixable:
        print(f"  - {issue.file}: {issue.issue}")

    # In autonomous mode, just do it
    # In interactive mode, ask first
    response = input("\nApply auto-fixes? (y/n): ")
    if response.lower() == 'y':
        fixed_files = config_scanner.auto_fix_issues()
        print(f"✅ Fixed: {', '.join(fixed_files)}")
```

### 7. Generate Reports

Create structured threat model and vulnerability reports:

```python
from shared.report_generator import ReportGenerator
from datetime import datetime

generator = ReportGenerator(project_root, "security")

# Combine all findings
all_threats = []

# Add STRIDE threats
for threat in stride_threats:
    all_threats.append({
        "id": threat.id,
        "category": threat.category.value,
        "severity": threat.severity.value,
        "title": threat.title,
        "description": threat.description,
        "affected_files": threat.affected_files,
        "attack_scenario": threat.attack_scenario,
        "mitigation": threat.mitigation,
        "impact": threat.impact,
        "likelihood": threat.likelihood,
        "status": threat.status,
        "cwe": threat.cwe,
        "test_coverage": threat.test_coverage
    })

# Add OWASP vulnerabilities
for vuln in owasp_vulns:
    all_threats.append({
        "id": vuln.id,
        "category": vuln.category.value,
        "severity": vuln.severity,
        "title": vuln.title,
        "description": vuln.description,
        "affected_files": vuln.affected_files,
        "attack_scenario": "",
        "mitigation": vuln.mitigation,
        "impact": "",
        "likelihood": "",
        "status": vuln.status,
        "cwe": vuln.cwe,
        "code_example": vuln.code_example,
        "test_coverage": []
    })

# Build report data
report_data = {
    "timestamp": datetime.now().isoformat(),
    "project": project_name,
    "scope": ["src/", "app.py", "requirements.txt"],
    "summary": {
        "total_threats": len(all_threats),
        "critical": len([t for t in all_threats if t['severity'] == 'CRITICAL']),
        "high": len([t for t in all_threats if t['severity'] == 'HIGH']),
        "medium": len([t for t in all_threats if t['severity'] == 'MEDIUM']),
        "low": len([t for t in all_threats if t['severity'] == 'LOW']),
        "mitigated": len([t for t in all_threats if t['status'] == 'mitigated']),
        "open": len([t for t in all_threats if t['status'] == 'open'])
    },
    "threats": all_threats,
    "attack_surface": {
        "entry_points": ["Streamlit UI", "API calls", "File system", "Environment variables"],
        "trust_boundaries": ["User → App", "App → External API", "App → File System", "Env → App"],
        "sensitive_data": ["API tokens", "Credentials", "User data"]
    },
    "dependencies": {
        "vulnerable": [
            {
                "package": v.package,
                "version": v.installed_version,
                "cve": v.vulnerability_id,
                "severity": v.severity,
                "fix": f"Update to {v.fixed_version}" if v.fixed_version else "No fix available"
            }
            for v in dep_vulns
        ] if args.full else [],
        "outdated": [f"{p['name']} {p['current']} -> {p['latest']}" for p in outdated[:10]] if args.full else []
    },
    "recommendations": []
}

# Generate recommendations
if report_data['summary']['critical'] > 0:
    report_data['recommendations'].append("URGENT: Address all CRITICAL severity threats immediately")
if report_data['summary']['high'] > 0:
    report_data['recommendations'].append("Address all HIGH severity threats before deployment")
if len(config_issues) > 0:
    report_data['recommendations'].append("Fix configuration security issues")
if args.full and len(dep_vulns) > 0:
    report_data['recommendations'].append("Update vulnerable dependencies")

json_path, md_path = generator.generate_report(report_data)

print(f"\n📝 Writing reports...")
print(f"✅ {json_path}")
print(f"✅ {md_path}")
```

### 8. Provide Summary

End with actionable summary:

```
=== Security Threat Model Summary ===

🔴 {critical} Critical | 🟠 {high} High | 🟡 {medium} Medium | 🟢 {low} Low
Status: {open} Open, {mitigated} Mitigated

Top Priority Threats:
1. [THREAT-001] Hardcoded credentials in source code (CRITICAL)
2. [VULN-003] Path traversal vulnerability (HIGH)
3. [THREAT-005] Missing authorization checks (HIGH)

Configuration Issues:
- .env not in .gitignore (auto-fixed)
- Missing .env.example (auto-fixed)

Dependencies:
- 2 vulnerable packages found
- 5 outdated packages

Reports saved to:
- JSON: docs/security/2026-02-07-threat-model.json
- Markdown: docs/security/2026-02-07-threat-model.md
```

## Integration with Testing Agent

When critical threats are found, optionally invoke testing agent to create security tests:

```python
# For high/critical threats, generate security tests
critical_threats = [t for t in all_threats if t['severity'] in ['CRITICAL', 'HIGH']]

if critical_threats and invoke_testing:
    print(f"\n🧪 Generating security tests for {len(critical_threats)} critical threats...")

    # This would invoke /agent:test with security specifications
    # For now, just recommend it
    print("💡 Recommendation: Run /agent:test to generate security regression tests")
```

## Tools and Modules

### STRIDE Analysis
```python
from threat_models.stride import STRIDEAnalyzer
analyzer = STRIDEAnalyzer(project_root)
threats = analyzer.analyze()
```

### OWASP Scanning
```python
from threat_models.owasp import OWASPScanner
scanner = OWASPScanner(project_root)
vulns = scanner.scan()
```

### Config Scanning
```python
from scanners.config_scanner import ConfigScanner
scanner = ConfigScanner(project_root)
issues = scanner.scan()
fixed = scanner.auto_fix_issues()
```

### Dependency Scanning
```python
from scanners.dependency_scanner import DependencyScanner
scanner = DependencyScanner(project_root)
vulns = scanner.scan()
outdated = scanner.check_outdated_packages()
```

### Report Generation
```python
from shared.report_generator import ReportGenerator
generator = ReportGenerator(project_root, "security")
json_path, md_path = generator.generate_report(data)
```

## Now Begin

You have been invoked with these arguments: {args}

Follow the workflow above to perform comprehensive security analysis and produce threat model reports.
```

**Step 2: Commit**

```bash
git add ~/.claude/skills/agents/agent-security/skill.md
git commit -m "feat: add security agent skill definition (Phase 4)"
```

---

### Task 11: Create agent README and finalize structure

**Files:**
- Create: `~/.claude/skills/agents/README.md`

**Step 1: Write main README**

```markdown
# Multi-Agent System: Testing & Security Agents

Cross-project Claude Code skills for automated testing and security auditing.

## Agents

### `/agent:test` - Testing Agent

Framework-agnostic test generation, execution, and reporting.

**Capabilities:**
- Auto-detect pytest or unittest
- Generate comprehensive test suites
- Execute tests with coverage analysis
- Identify untested code
- Generate mocks for APIs
- Support Streamlit component testing

**Usage:**
```bash
/agent:test              # Full test generation and execution
/agent:test --quick      # Test recently changed files only
/agent:test --full       # Comprehensive with coverage
/agent:test --file path  # Target specific file/directory
```

### `/agent:security` - Security Agent

STRIDE threat modeling and OWASP Top 10 vulnerability scanning.

**Capabilities:**
- STRIDE architectural threat modeling
- OWASP Top 10 code scanning
- Configuration security checks
- Dependency vulnerability scanning
- Auto-fix security misconfigurations

**Usage:**
```bash
/agent:security              # Full threat model + scan
/agent:security --quick      # OWASP scan only
/agent:security --full       # Deep analysis with dependencies
/agent:security --file path  # Target specific file/directory
```

## Architecture

```
~/.claude/skills/agents/
├── agent-test/              # Testing Agent
│   ├── skill.md             # Agent definition
│   ├── analyzers/           # Code analysis
│   │   ├── framework_detector.py
│   │   ├── gap_analyzer.py
│   │   └── coverage_analyzer.py
│   ├── templates/           # Test generation
│   │   ├── pytest_template.py
│   │   ├── unittest_template.py
│   │   └── streamlit_fixture.py
│   └── utils/               # Test execution
│       ├── test_runner.py
│       └── mock_generator.py
│
├── agent-security/          # Security Agent
│   ├── skill.md             # Agent definition
│   ├── threat_models/       # Threat modeling
│   │   ├── stride.py
│   │   └── owasp.py
│   ├── scanners/            # Vulnerability scanning
│   │   ├── config_scanner.py
│   │   └── dependency_scanner.py
│   └── utils/               # Security utilities
│
└── shared/                  # Shared utilities
    └── report_generator.py  # JSON/Markdown reports
```

## Output

Both agents generate structured reports:

**Testing Reports:**
- `docs/testing/YYYY-MM-DD-test-report.json`
- `docs/testing/YYYY-MM-DD-test-report.md`

**Security Reports:**
- `docs/security/YYYY-MM-DD-threat-model.json`
- `docs/security/YYYY-MM-DD-threat-model.md`

## Installation

These skills work out-of-the-box with Claude Code. Optional dependencies for enhanced features:

```bash
# For enhanced coverage analysis
pip install pytest pytest-cov

# For dependency vulnerability scanning
pip install pip-audit
```

## Workflow Examples

### Initial Project Security Assessment

```bash
# Run full security audit
/agent:security --full

# Auto-fix configuration issues
# (agent will prompt)

# Generate comprehensive test suite
/agent:test --full
```

### During Development

```bash
# Test new feature
/agent:test --file src/new_feature.py

# Security check for auth changes
/agent:security --file src/auth/
```

### Pre-Deployment

```bash
# Full security + testing check
/agent:security --full
/agent:test --full
```

## Agent Coordination

Security agent findings can trigger security-focused test generation:

1. Security agent identifies threat (e.g., "THREAT-001: Credential leakage")
2. Security agent notes need for security test
3. User runs `/agent:test` which generates tests for security threats
4. Tests validate mitigations

## Development Status

**Phase 1-2: Testing Agent** ✅
- Framework detection
- Gap analysis
- Test generation
- Coverage analysis
- Streamlit support
- API mocking

**Phase 3-4: Security Agent** ✅
- STRIDE threat modeling
- OWASP Top 10 scanning
- Configuration scanning
- Dependency scanning
- Auto-hardening

**Phase 5: Agent Coordination** 🔄 (Future)
- Automatic security test generation
- Cross-referencing threats and tests
- Status tracking

**Phase 6: Multi-Language** 🔄 (Future)
- JavaScript/TypeScript support
- Go support

## Contributing

These skills are designed to be portable across projects. Contributions welcome for:
- Additional test templates
- New security patterns
- Language support
- Framework integrations
```

**Step 2: Commit**

```bash
git add ~/.claude/skills/agents/README.md
git commit -m "docs: add agent system README (Phase 4 complete)"
```

---

## Final Tasks

### Task 12: Update plan with completion status

**Step 1: Mark plan as complete**

Update the plan document header:

```bash
git add docs/plans/2026-02-07-agent-implementation-phases-1-4.md
git commit -m "docs: implementation plan for agent system phases 1-4 complete"
```

**Step 2: Update task tracking**

Mark implementation task as complete.

---

## Deliverables Summary

**Phase 1: Testing Agent Foundation** ✅
- gap_analyzer.py: AST-based untested code detection
- coverage_analyzer.py: pytest-cov integration
- Updated skill.md with analyzer integration

**Phase 2: Testing Agent Enhancements** ✅
- streamlit_fixture.py: Streamlit test generators
- mock_generator.py: API client mock generation

**Phase 3: Security Agent Foundation** ✅
- stride.py: STRIDE threat modeling
- owasp.py: OWASP Top 10 scanner
- config_scanner.py: Configuration security checks

**Phase 4: Security Agent Enhancements** ✅
- dependency_scanner.py: Vulnerability scanning
- skill.md: Security agent definition
- README.md: Complete agent system documentation

All agents are now ready for use with `/agent:test` and `/agent:security` commands!
