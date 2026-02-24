# Agent Security Extraction Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extract and parameterize security scanning logic from PelotonRacer into four generic, reusable modules in `~/.claude/skills/agent-security/`.

**Architecture:** Four modules in dependency order: `severity_calculator.py` (standalone constants/functions) → `code_scanner.py` (standalone regex scanner) → `mitigation_suggester.py` (imports severity_calculator) → `security_reporter.py` (imports both utils). All project-specific strings replaced with `project_name` parameter. Source reference: `/Users/nissim/dev/PelotonRacer/scripts/generate_security_reports.py`.

**Tech Stack:** Python 3.10+, pytest, re, dataclasses, pathlib, jinja2, json, datetime

---

## Task 1: `utils/severity_calculator.py`

**Files:**
- Create: `~/.claude/skills/agent-security/utils/severity_calculator.py`
- Create: `~/.claude/skills/agent-security/tests/test_severity_calculator.py`

### Step 1: Write the failing tests

```python
# ~/.claude/skills/agent-security/tests/test_severity_calculator.py
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.severity_calculator import (
    SEVERITY_ORDER, SEVERITY_EMOJI, calculate_posture, sort_by_severity
)


def test_severity_order_values():
    assert SEVERITY_ORDER["CRITICAL"] < SEVERITY_ORDER["HIGH"]
    assert SEVERITY_ORDER["HIGH"] < SEVERITY_ORDER["MEDIUM"]
    assert SEVERITY_ORDER["MEDIUM"] < SEVERITY_ORDER["LOW"]


def test_severity_emoji_keys():
    for key in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        assert key in SEVERITY_EMOJI


def test_calculate_posture_critical():
    label, short = calculate_posture({"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0})
    assert short == "CRITICAL"
    assert "NOT PRODUCTION READY" in label


def test_calculate_posture_high():
    label, short = calculate_posture({"CRITICAL": 0, "HIGH": 2, "MEDIUM": 0, "LOW": 0})
    assert short == "HIGH"
    assert "HIGH-SEVERITY" in label


def test_calculate_posture_medium():
    label, short = calculate_posture({"CRITICAL": 0, "HIGH": 0, "MEDIUM": 3, "LOW": 0})
    assert short == "MEDIUM"
    assert "MODERATE" in label


def test_calculate_posture_low():
    label, short = calculate_posture({"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 2})
    assert short == "LOW"
    assert "LOW RISK" in label


def test_calculate_posture_clean():
    label, short = calculate_posture({"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0})
    assert short == "CLEAN"
    assert "CLEAN" in label


def test_sort_by_severity_orders_correctly():
    findings = [
        {"severity": "LOW", "file": "a.py"},
        {"severity": "CRITICAL", "file": "b.py"},
        {"severity": "MEDIUM", "file": "c.py"},
        {"severity": "HIGH", "file": "d.py"},
    ]
    result = sort_by_severity(findings)
    assert [f["severity"] for f in result] == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def test_sort_by_severity_stable_by_file():
    findings = [
        {"severity": "HIGH", "file": "z.py"},
        {"severity": "HIGH", "file": "a.py"},
    ]
    result = sort_by_severity(findings)
    assert result[0]["file"] == "a.py"
    assert result[1]["file"] == "z.py"


def test_sort_by_severity_custom_key():
    findings = [
        {"sev": "LOW", "file": "a.py"},
        {"sev": "HIGH", "file": "b.py"},
    ]
    result = sort_by_severity(findings, severity_key="sev")
    assert result[0]["sev"] == "HIGH"
```

### Step 2: Run test to verify it fails

```bash
pytest ~/.claude/skills/agent-security/tests/test_severity_calculator.py -v
```
Expected: `ModuleNotFoundError` or `ImportError` — module does not exist yet.

### Step 3: Implement `severity_calculator.py`

```python
# ~/.claude/skills/agent-security/utils/severity_calculator.py
"""
Severity constants, sorting, and security posture assessment.

Extracted from generate_security_reports.py posture logic and constants.
"""

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}


def calculate_posture(sev_counts: dict) -> tuple[str, str]:
    """
    Calculate security posture from severity counts.

    Args:
        sev_counts: dict with keys CRITICAL, HIGH, MEDIUM, LOW and int values

    Returns:
        (posture_label, posture_short) e.g.:
        ("⚠️ NOT PRODUCTION READY — Critical vulnerabilities...", "CRITICAL")
        ("✅ CLEAN — No issues detected", "CLEAN")
    """
    total = sum(sev_counts.values())
    if sev_counts.get("CRITICAL", 0) > 0:
        return (
            "⚠️ **NOT PRODUCTION READY** — Critical vulnerabilities require immediate attention",
            "CRITICAL",
        )
    elif sev_counts.get("HIGH", 0) > 0:
        return (
            "🟠 **HIGH-SEVERITY ISSUES FOUND** — Fix before production deployment",
            "HIGH",
        )
    elif sev_counts.get("MEDIUM", 0) > 0:
        return (
            "🟡 **MODERATE RISK** — Address in development roadmap",
            "MEDIUM",
        )
    elif total > 0:
        return (
            "🟢 **LOW RISK** — Minor informational issues only",
            "LOW",
        )
    else:
        return ("✅ **CLEAN** — No issues detected", "CLEAN")


def sort_by_severity(findings: list, severity_key: str = "severity") -> list:
    """Sort findings by severity (CRITICAL first) then by file."""
    return sorted(
        findings,
        key=lambda g: (SEVERITY_ORDER.get(g.get(severity_key, "LOW"), 9), g.get("file", "")),
    )


if __name__ == "__main__":
    counts = {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 1, "LOW": 3}
    label, short = calculate_posture(counts)
    print(f"Posture: {label}")
    print(f"Short:   {short}")
```

### Step 4: Run tests to verify they pass

```bash
pytest ~/.claude/skills/agent-security/tests/test_severity_calculator.py -v
```
Expected: `9 passed`

### Step 5: Commit

```bash
git add ~/.claude/skills/agent-security/utils/severity_calculator.py \
        ~/.claude/skills/agent-security/tests/test_severity_calculator.py
git commit -m "feat: add severity_calculator.py — constants, posture, and sort"
```

---

## Task 2: `scanners/code_scanner.py`

**Files:**
- Create: `~/.claude/skills/agent-security/scanners/code_scanner.py`
- Create: `~/.claude/skills/agent-security/tests/test_code_scanner.py`

### Step 1: Write the failing tests

```python
# ~/.claude/skills/agent-security/tests/test_code_scanner.py
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanners.code_scanner import CodeScanner, ScanPattern, CodeFinding, BUILTIN_PATTERNS


# ── helpers ──────────────────────────────────────────────────────────────────

def _make_project(files: dict[str, str]) -> Path:
    """Create a temp project tree with given {rel_path: content} files."""
    tmp = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        path = tmp / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return tmp


# ── BUILTIN_PATTERNS ─────────────────────────────────────────────────────────

def test_builtin_patterns_are_scan_pattern_instances():
    for p in BUILTIN_PATTERNS:
        assert isinstance(p, ScanPattern)


def test_builtin_patterns_have_required_fields():
    for p in BUILTIN_PATTERNS:
        assert p.id and p.pattern and p.severity and p.title and p.cwe and p.owasp


def test_builtin_patterns_include_expected_ids():
    ids = {p.id for p in BUILTIN_PATTERNS}
    assert "SRC-INFO-LEAK" in ids
    assert "SRC-JWT-NOSIG" in ids
    assert "SRC-CRED-ENV" in ids


# ── source dir detection ──────────────────────────────────────────────────────

def test_detects_src_dir():
    root = _make_project({"src/api/client.py": "x = 1"})
    scanner = CodeScanner(str(root))
    assert scanner._detect_source_dir() == root / "src"


def test_detects_app_dir_when_no_src():
    root = _make_project({"app/main.py": "x = 1"})
    scanner = CodeScanner(str(root))
    assert scanner._detect_source_dir() == root / "app"


def test_falls_back_to_root_when_no_candidate():
    root = _make_project({"main.py": "x = 1"})
    scanner = CodeScanner(str(root))
    assert scanner._detect_source_dir() == root


def test_target_path_overrides_detection():
    root = _make_project({
        "src/a.py": "x = 1",
        "custom/b.py": "x = 1",
    })
    scanner = CodeScanner(str(root))
    results = scanner.scan(target_path=str(root / "custom"))
    # should scan custom/ not src/
    assert all("custom" in f.file for f in results) or len(results) == 0


# ── pattern detection ─────────────────────────────────────────────────────────

def test_detects_src_info_leak():
    code = (
        "try:\n"
        "    do_thing()\n"
        "except Exception as e:\n"
        '    print(f"Error: {e}")\n'
    )
    root = _make_project({"src/app.py": code})
    scanner = CodeScanner(str(root))
    findings = scanner.scan()
    ids = [f.id for f in findings]
    assert "SRC-INFO-LEAK" in ids


def test_detects_jwt_nosig():
    code = 'options = {"verify_signature": False}\n'
    root = _make_project({"src/auth.py": code})
    scanner = CodeScanner(str(root))
    findings = scanner.scan()
    assert any(f.id == "SRC-JWT-NOSIG" for f in findings)


def test_detects_src_cred_env():
    code = "password = os.getenv('DB_PASSWORD')\n"
    root = _make_project({"src/config.py": code})
    scanner = CodeScanner(str(root))
    findings = scanner.scan()
    assert any(f.id == "SRC-CRED-ENV" for f in findings)


def test_no_false_positive_on_clean_code():
    code = (
        "def add(a, b):\n"
        "    return a + b\n"
    )
    root = _make_project({"src/math.py": code})
    scanner = CodeScanner(str(root))
    findings = scanner.scan()
    assert findings == []


# ── CodeFinding shape ─────────────────────────────────────────────────────────

def test_finding_has_correct_fields():
    code = 'options = {"verify_signature": False}\n'
    root = _make_project({"src/auth.py": code})
    scanner = CodeScanner(str(root))
    findings = scanner.scan()
    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, CodeFinding)
    assert f.id == "SRC-JWT-NOSIG"
    assert f.severity == "MEDIUM"
    assert f.file.endswith("auth.py")
    assert f.line == 1
    assert "verify_signature" in f.code_snippet


# ── extra_patterns ────────────────────────────────────────────────────────────

def test_extra_patterns_are_applied():
    custom = ScanPattern(
        id="CUSTOM-001",
        pattern=r"eval\(",
        severity="HIGH",
        title="Use of eval",
        cwe="CWE-95",
        owasp="A03:2021 - Injection",
    )
    code = "result = eval(user_input)\n"
    root = _make_project({"src/app.py": code})
    scanner = CodeScanner(str(root), extra_patterns=[custom])
    findings = scanner.scan()
    assert any(f.id == "CUSTOM-001" for f in findings)
```

### Step 2: Run test to verify it fails

```bash
pytest ~/.claude/skills/agent-security/tests/test_code_scanner.py -v
```
Expected: `ImportError` — module does not exist yet.

### Step 3: Implement `code_scanner.py`

```python
# ~/.claude/skills/agent-security/scanners/code_scanner.py
"""
Source code security scanner.

Scans Python source files with regex patterns to detect security anti-patterns
that complement bandit — specifically patterns that require understanding of how
code uses a feature, not just that the feature is present.

Design decision: complement to bandit, not a replacement
  bandit handles: B-series checks (eval, pickle, hardcoded passwords, subprocess, etc.)
  this scanner handles: patterns requiring semantic context bandit doesn't check

Current patterns:
  SRC-INFO-LEAK — exception details in user-facing output (bandit catches bare
                  except, not the print-with-format-string case)
  SRC-JWT-NOSIG — JWT signature verification disabled (bandit has no JWT checks)
  SRC-CRED-ENV  — credentials in environment variables (bandit catches hardcoded
                  strings, not env-var assignment patterns)

Future enhancement path: add patterns by appending to BUILTIN_PATTERNS.
  Each pattern is a ScanPattern dataclass — no changes to scanning logic required.
  Candidates: hardcoded AWS region strings, debug flags left enabled,
  timing-unsafe string comparison in auth code, CORS wildcard allowlist.
"""

import re
from dataclasses import dataclass
from pathlib import Path

# Source directory candidates checked in priority order
_SOURCE_DIR_CANDIDATES = ["src", "app", "lib"]


@dataclass
class ScanPattern:
    id: str           # e.g. "SRC-INFO-LEAK"
    pattern: str      # regex string
    severity: str     # CRITICAL / HIGH / MEDIUM / LOW
    title: str
    cwe: str          # e.g. "CWE-209"
    owasp: str        # e.g. "A05:2021 - Security Misconfiguration"


@dataclass
class CodeFinding:
    id: str
    title: str
    severity: str
    cwe: str
    owasp: str
    file: str
    line: int
    code_snippet: str


BUILTIN_PATTERNS: list[ScanPattern] = [
    ScanPattern(
        id="SRC-INFO-LEAK",
        pattern=r"except\s+Exception\s+as\s+\w+.*?print\(.*?\{.*?\}",
        severity="HIGH",
        title="Exception details in user-facing output",
        cwe="CWE-209",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    ScanPattern(
        id="SRC-JWT-NOSIG",
        pattern=r"verify_signature.*?False",
        severity="MEDIUM",
        title="JWT signature verification disabled",
        cwe="CWE-347",
        owasp="A07:2021 - Authentication Failures",
    ),
    ScanPattern(
        id="SRC-CRED-ENV",
        pattern=r"password.*?=.*?os\.getenv|\.env.*?password|PASSWORD",
        severity="MEDIUM",
        title="Credentials in environment variables",
        cwe="CWE-312",
        owasp="A02:2021 - Cryptographic Failures",
    ),
]


class CodeScanner:
    def __init__(self, project_root: str, extra_patterns: list[ScanPattern] = None):
        self.project_root = Path(project_root)
        self.patterns = BUILTIN_PATTERNS + (extra_patterns or [])

    def _detect_source_dir(self) -> Path:
        """Return source directory to scan, checking priority list then falling back to root."""
        for candidate in _SOURCE_DIR_CANDIDATES:
            path = self.project_root / candidate
            if path.is_dir():
                return path
        return self.project_root

    def scan(self, target_path: str = None) -> list[CodeFinding]:
        """
        Scan Python source files for security anti-patterns.

        Args:
            target_path: explicit path to scan (overrides auto-detection)

        Returns:
            list of CodeFinding instances
        """
        scan_root = Path(target_path) if target_path else self._detect_source_dir()
        findings = []
        for py_file in scan_root.rglob("*.py"):
            try:
                content = py_file.read_text()
            except Exception:
                continue
            try:
                rel_path = str(py_file.relative_to(self.project_root))
            except ValueError:
                rel_path = str(py_file)
            for pat in self.patterns:
                for match in re.finditer(pat.pattern, content, re.DOTALL):
                    line_num = content[: match.start()].count("\n") + 1
                    lines = content.splitlines()
                    snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                    findings.append(
                        CodeFinding(
                            id=pat.id,
                            title=pat.title,
                            severity=pat.severity,
                            cwe=pat.cwe,
                            owasp=pat.owasp,
                            file=rel_path,
                            line=line_num,
                            code_snippet=snippet,
                        )
                    )
        return findings


if __name__ == "__main__":
    import sys
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    scanner = CodeScanner(root)
    results = scanner.scan()
    print(f"Code Security Scan — {root}")
    print("=" * 40)
    print(f"Found {len(results)} findings\n")
    for f in results:
        print(f"[{f.severity}] {f.id}: {f.title}")
        print(f"  File: {f.file}:{f.line}")
        print(f"  Code: {f.code_snippet}")
        print()
```

### Step 4: Run tests to verify they pass

```bash
pytest ~/.claude/skills/agent-security/tests/test_code_scanner.py -v
```
Expected: `14 passed`

### Step 5: Commit

```bash
git add ~/.claude/skills/agent-security/scanners/code_scanner.py \
        ~/.claude/skills/agent-security/tests/test_code_scanner.py
git commit -m "feat: add code_scanner.py — regex-based complement to bandit"
```

---

## Task 3: `utils/mitigation_suggester.py`

**Files:**
- Create: `~/.claude/skills/agent-security/utils/mitigation_suggester.py`
- Create: `~/.claude/skills/agent-security/tests/test_mitigation_suggester.py`

### Step 1: Write the failing tests

```python
# ~/.claude/skills/agent-security/tests/test_mitigation_suggester.py
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.mitigation_suggester import (
    BANDIT_OWASP_MAP, FINDING_ENRICHMENT, DEP_ENRICHMENT,
    group_findings, get_enrichment,
)


# ── BANDIT_OWASP_MAP ──────────────────────────────────────────────────────────

def test_bandit_owasp_map_has_at_least_40_entries():
    assert len(BANDIT_OWASP_MAP) >= 40


def test_bandit_owasp_map_values_are_tuples():
    for k, v in BANDIT_OWASP_MAP.items():
        assert isinstance(v, tuple) and len(v) == 2, f"Bad value for {k}: {v}"


def test_bandit_owasp_map_covers_tier1_ids():
    tier1 = ["B105", "B106", "B107", "B301", "B303", "B311",
             "B501", "B502", "B506", "B602", "B603", "B605", "B608"]
    for bid in tier1:
        assert bid in BANDIT_OWASP_MAP, f"Missing {bid} in BANDIT_OWASP_MAP"


# ── FINDING_ENRICHMENT ────────────────────────────────────────────────────────

def test_finding_enrichment_has_tier1_ids():
    tier1 = ["B105", "B106", "B107", "B301", "B303", "B311",
             "B501", "B502", "B506", "B602", "B603", "B605", "B608",
             "SRC-INFO-LEAK", "SRC-JWT-NOSIG", "SRC-CRED-ENV"]
    for fid in tier1:
        assert fid in FINDING_ENRICHMENT, f"Missing {fid} in FINDING_ENRICHMENT"


def test_finding_enrichment_entries_have_required_keys():
    required = {"analytical_title", "description", "impact", "attack_scenario", "remediation", "stride"}
    for fid, entry in FINDING_ENRICHMENT.items():
        for key in required:
            assert key in entry, f"Missing '{key}' in FINDING_ENRICHMENT['{fid}']"


def test_finding_enrichment_no_hardcoded_project_name():
    """Verify no PelotonRacer-specific strings leak through."""
    forbidden = ["PelotonRacer", "peloton_client", "mock_data.py", "PELOTON_BEARER"]
    for fid, entry in FINDING_ENRICHMENT.items():
        for key, val in entry.items():
            if isinstance(val, str):
                for term in forbidden:
                    assert term not in val, (
                        f"Project-specific term '{term}' found in "
                        f"FINDING_ENRICHMENT['{fid}']['{key}']"
                    )


# ── DEP_ENRICHMENT ────────────────────────────────────────────────────────────

def test_dep_enrichment_has_templates():
    assert "description_template" in DEP_ENRICHMENT
    assert "remediation_template" in DEP_ENRICHMENT
    assert "impact" in DEP_ENRICHMENT


def test_dep_enrichment_templates_format_correctly():
    dep = {"package": "requests", "version": "2.20.0", "cve": "CVE-2023-1234", "fix_version": "2.31.0"}
    desc = DEP_ENRICHMENT["description_template"].format(**dep)
    assert "requests" in desc
    assert "CVE-2023-1234" in desc
    fix = DEP_ENRICHMENT["remediation_template"].format(**dep)
    assert "2.31.0" in fix


# ── group_findings ────────────────────────────────────────────────────────────

def _bandit_result(test_id, filename, line, severity="MEDIUM", code="x = 1"):
    return {
        "test_id": test_id,
        "filename": filename,
        "line_number": line,
        "issue_severity": severity,
        "issue_text": f"Test {test_id}",
        "issue_cwe": {"id": "200", "link": "https://cwe.mitre.org/data/definitions/200.html"},
        "issue_confidence": "HIGH",
        "more_info": "",
        "code": code,
    }


def test_group_findings_deduplicates_bandit_same_file():
    bandit = {"results": [
        _bandit_result("B311", "src/mock.py", 10),
        _bandit_result("B311", "src/mock.py", 20),
        _bandit_result("B311", "src/mock.py", 30),
    ]}
    grouped = group_findings(bandit, [], [])
    b311_groups = [g for g in grouped if g["test_id"] == "B311"]
    assert len(b311_groups) == 1
    assert len(b311_groups[0]["lines"]) == 3


def test_group_findings_keeps_different_files_separate():
    bandit = {"results": [
        _bandit_result("B311", "src/a.py", 10),
        _bandit_result("B311", "src/b.py", 20),
    ]}
    grouped = group_findings(bandit, [], [])
    b311_groups = [g for g in grouped if g["test_id"] == "B311"]
    assert len(b311_groups) == 2


def test_group_findings_sorts_by_severity():
    bandit = {"results": [
        _bandit_result("B311", "src/a.py", 1, severity="LOW"),
        _bandit_result("B301", "src/b.py", 1, severity="HIGH"),
        _bandit_result("B608", "src/c.py", 1, severity="MEDIUM"),
    ]}
    grouped = group_findings(bandit, [], [])
    sevs = [g["severity"] for g in grouped]
    assert sevs == sorted(sevs, key=lambda s: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(s, 9))


def test_group_findings_includes_dep_vulns():
    dep = {"package": "requests", "version": "2.20.0", "cve": "CVE-2023-1", "fix_version": "2.31.0", "description": ""}
    grouped = group_findings({"results": []}, [dep], [])
    deps = [g for g in grouped if g["source"] == "dep"]
    assert len(deps) == 1
    assert deps[0]["test_id"] == "CVE-2023-1"


def test_group_findings_includes_source_findings():
    src = [{"id": "SRC-INFO-LEAK", "title": "Info leak", "severity": "HIGH",
            "cwe": "CWE-209", "owasp": "A05:2021", "file": "src/app.py",
            "line": 42, "code_snippet": "print(f'{e}')"}]
    grouped = group_findings({"results": []}, [], src)
    src_groups = [g for g in grouped if g["source"] == "source-scan"]
    assert len(src_groups) == 1
    assert src_groups[0]["test_id"] == "SRC-INFO-LEAK"


# ── get_enrichment ────────────────────────────────────────────────────────────

def test_get_enrichment_tier1_returns_full_entry():
    entry = get_enrichment("B311")
    assert "analytical_title" in entry
    assert "attack_scenario" in entry
    assert "remediation" in entry


def test_get_enrichment_tier2_fallback_uses_bandit_owasp_map():
    # B101 is in BANDIT_OWASP_MAP but not FINDING_ENRICHMENT
    entry = get_enrichment("B101")
    assert "analytical_title" in entry


def test_get_enrichment_unknown_id_returns_id_as_title():
    entry = get_enrichment("B999-UNKNOWN")
    assert entry.get("analytical_title") == "B999-UNKNOWN"
```

### Step 2: Run test to verify it fails

```bash
pytest ~/.claude/skills/agent-security/tests/test_mitigation_suggester.py -v
```
Expected: `ImportError` — module does not exist yet.

### Step 3: Implement `mitigation_suggester.py`

```python
# ~/.claude/skills/agent-security/utils/mitigation_suggester.py
"""
Finding enrichment and deduplication for security reports.

Two responsibilities:
1. Maps raw tool findings to OWASP categories and enriches them with attack
   scenarios, remediation guidance, and STRIDE classification.
2. Deduplicates multiple instances of the same finding type in the same file
   into a single grouped entry.

Finding enrichment tiers:
  Tier 1 — Full enrichment: analytical_title, description, impact,
            attack_scenario, remediation, stride, risk_note
            Covers: B105, B106, B107, B301, B303, B311, B501, B502, B506,
                    B602, B603, B605, B608, SRC-INFO-LEAK, SRC-JWT-NOSIG, SRC-CRED-ENV
  Tier 2 — Fallback: title + OWASP category from BANDIT_OWASP_MAP.
            Reports are never blank for any bandit finding.

Future enhancement path: add entries to FINDING_ENRICHMENT for any bandit ID.
  The tier-2 fallback means the system degrades gracefully until enrichment
  is written. A future enhancement could auto-generate tier-1 enrichment using
  Claude for finding IDs not yet in the dict, caching the result.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.severity_calculator import SEVERITY_ORDER


BANDIT_OWASP_MAP = {
    "B101": ("A05:2021 - Security Misconfiguration", "Use of assert statements"),
    "B102": ("A05:2021 - Security Misconfiguration", "Use of exec()"),
    "B103": ("A05:2021 - Security Misconfiguration", "Permissive file permissions"),
    "B104": ("A05:2021 - Security Misconfiguration", "Binding to all interfaces"),
    "B105": ("A02:2021 - Cryptographic Failures", "Hardcoded password string"),
    "B106": ("A02:2021 - Cryptographic Failures", "Hardcoded password as argument"),
    "B107": ("A02:2021 - Cryptographic Failures", "Hardcoded password default"),
    "B108": ("A01:2021 - Broken Access Control", "Hardcoded /tmp path"),
    "B110": ("A05:2021 - Security Misconfiguration", "Try-except-pass pattern"),
    "B112": ("A05:2021 - Security Misconfiguration", "Try-except-continue pattern"),
    "B201": ("A03:2021 - Injection", "Use of Flask debug mode"),
    "B301": ("A08:2021 - Software Integrity Failures", "Use of pickle"),
    "B302": ("A08:2021 - Software Integrity Failures", "Use of marshal"),
    "B303": ("A02:2021 - Cryptographic Failures", "Insecure hash function (MD5/SHA1)"),
    "B304": ("A02:2021 - Cryptographic Failures", "Insecure cipher"),
    "B305": ("A02:2021 - Cryptographic Failures", "Insecure cipher mode"),
    "B306": ("A05:2021 - Security Misconfiguration", "Use of mktemp"),
    "B307": ("A03:2021 - Injection", "Use of eval()"),
    "B308": ("A03:2021 - Injection", "Use of mark_safe()"),
    "B310": ("A10:2021 - SSRF", "URL open audit"),
    "B311": ("A02:2021 - Cryptographic Failures", "Non-cryptographic random generator"),
    "B312": ("A10:2021 - SSRF", "Telnet usage"),
    "B320": ("A03:2021 - Injection", "XML parsing vulnerability"),
    "B321": ("A10:2021 - SSRF", "FTP usage"),
    "B323": ("A02:2021 - Cryptographic Failures", "SSL/TLS verification disabled"),
    "B324": ("A02:2021 - Cryptographic Failures", "Insecure hash function"),
    "B501": ("A02:2021 - Cryptographic Failures", "SSL/TLS verify=False"),
    "B502": ("A02:2021 - Cryptographic Failures", "SSL with bad version"),
    "B503": ("A02:2021 - Cryptographic Failures", "SSL with bad defaults"),
    "B504": ("A02:2021 - Cryptographic Failures", "SSL without SNI"),
    "B505": ("A02:2021 - Cryptographic Failures", "Weak cryptographic key"),
    "B506": ("A05:2021 - Security Misconfiguration", "YAML load unsafe"),
    "B507": ("A02:2021 - Cryptographic Failures", "SSH no host key verification"),
    "B601": ("A03:2021 - Injection", "Shell injection via paramiko"),
    "B602": ("A03:2021 - Injection", "Subprocess with shell=True"),
    "B603": ("A03:2021 - Injection", "Subprocess without shell"),
    "B604": ("A03:2021 - Injection", "Function call with shell=True"),
    "B605": ("A03:2021 - Injection", "Start process with shell"),
    "B606": ("A03:2021 - Injection", "Start process with no shell"),
    "B607": ("A03:2021 - Injection", "Start process with partial path"),
    "B608": ("A03:2021 - Injection", "SQL injection via string formatting"),
    "B609": ("A03:2021 - Injection", "Wildcard injection"),
    "B610": ("A03:2021 - Injection", "Django extra() SQL injection"),
    "B611": ("A03:2021 - Injection", "Django RawSQL injection"),
    "B701": ("A03:2021 - Injection", "Jinja2 autoescape disabled"),
    "B702": ("A03:2021 - Injection", "Mako template injection"),
    "B703": ("A03:2021 - Injection", "Django mark_safe XSS"),
}


FINDING_ENRICHMENT = {
    "B105": {
        "analytical_title": "Hardcoded Password String",
        "description": (
            "A password is hardcoded as a string literal in the source code. "
            "Hardcoded credentials are visible to anyone with code access, cannot be "
            "rotated without a code change, and are frequently committed to version control."
        ),
        "impact": (
            "- Credentials exposed to all developers and anyone with repo access\n"
            "- Cannot rotate without redeployment\n"
            "- Frequently leaked via git history, code reviews, or error messages\n"
            "- Static analysis tools flag this; attackers scan public repos for these patterns"
        ),
        "attack_scenario": (
            "1. Attacker discovers repository (public or via breach)\n"
            "2. Searches for hardcoded strings matching password patterns\n"
            "3. Uses credentials to authenticate to the target system\n"
            "4. Credentials remain valid until manually rotated"
        ),
        "remediation": (
            "Replace hardcoded credentials with environment variables:\n\n"
            "```python\n"
            "import os\n\n"
            "# Instead of: password = 'mysecretpassword'\n"
            "password = os.environ['DB_PASSWORD']\n"
            "```\n\n"
            "Or use a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.)."
        ),
        "stride": "Information Disclosure",
        "risk_note": "Credential exposure risk",
    },
    "B106": {
        "analytical_title": "Hardcoded Password as Function Argument",
        "description": (
            "A password is passed as a hardcoded string literal in a function call. "
            "This pattern often appears in test setup or default credentials for development "
            "environments that accidentally ship to production."
        ),
        "impact": (
            "- Same as B105: credential visible in source, cannot rotate without code change\n"
            "- Often appears in test helpers that get called in production paths"
        ),
        "attack_scenario": (
            "1. Developer copies test helper into production code\n"
            "2. Hardcoded credential shipped with application\n"
            "3. Attacker reads binary or decompiled source to extract credential"
        ),
        "remediation": (
            "```python\n"
            "# Instead of: connect(host='db', password='hardcoded')\n"
            "connect(host='db', password=os.environ['DB_PASSWORD'])\n"
            "```"
        ),
        "stride": "Information Disclosure",
        "risk_note": "Credential exposure risk",
    },
    "B107": {
        "analytical_title": "Hardcoded Password as Default Argument",
        "description": (
            "A hardcoded password is used as a default argument value. "
            "Default arguments are common in development/testing helpers that sometimes "
            "get promoted to production use."
        ),
        "impact": (
            "- Default credentials may be used in production if caller doesn't override\n"
            "- Visible in function signature, often overlooked in code review"
        ),
        "attack_scenario": (
            "1. Caller omits the password argument, relying on the default\n"
            "2. Default credential used for authentication in production\n"
            "3. Credential is readable in source code"
        ),
        "remediation": (
            "```python\n"
            "# Instead of: def connect(host, password='default123'):\n"
            "def connect(host, password=None):\n"
            "    if password is None:\n"
            "        password = os.environ['DB_PASSWORD']\n"
            "```"
        ),
        "stride": "Information Disclosure",
        "risk_note": "Credential exposure via default argument",
    },
    "B301": {
        "analytical_title": "Unsafe Deserialization with pickle",
        "description": (
            "The application uses Python's `pickle` module to deserialize data. "
            "Pickle can execute arbitrary Python code during deserialization — any untrusted "
            "pickled data is equivalent to allowing arbitrary code execution."
        ),
        "impact": (
            "- Remote Code Execution if attacker can control pickled input\n"
            "- Full server compromise from a single malicious payload\n"
            "- No safe way to filter malicious pickle data before deserialization"
        ),
        "attack_scenario": (
            "1. Attacker crafts a malicious pickle payload:\n"
            "   ```python\n"
            "   import pickle, os\n"
            "   class Exploit(object):\n"
            "       def __reduce__(self):\n"
            "           return (os.system, ('id > /tmp/pwned',))\n"
            "   payload = pickle.dumps(Exploit())\n"
            "   ```\n"
            "2. Payload is submitted via any input that gets deserialized\n"
            "3. `pickle.loads(payload)` executes the OS command"
        ),
        "remediation": (
            "Replace pickle with a safe format:\n\n"
            "```python\n"
            "import json\n\n"
            "# Instead of: data = pickle.loads(user_input)\n"
            "data = json.loads(user_input)  # Safe for structured data\n"
            "```\n\n"
            "If pickle is required (e.g., for numpy arrays), authenticate the data "
            "with HMAC before deserializing and only deserialize data from trusted sources."
        ),
        "stride": "Tampering",
        "risk_note": "RCE risk if attacker controls pickled data",
    },
    "B303": {
        "analytical_title": "Weak Hash Function (MD5 or SHA-1)",
        "description": (
            "The application uses MD5 or SHA-1 for hashing. Both algorithms are "
            "cryptographically broken: MD5 collisions can be computed in seconds, "
            "and SHA-1 was demonstrated to be breakable in 2017 (SHAttered attack)."
        ),
        "impact": (
            "- If used for password hashing: rainbow table and GPU attacks are trivial\n"
            "- If used for data integrity: collision attacks allow undetected tampering\n"
            "- If used for digital signatures: forgery is possible"
        ),
        "attack_scenario": (
            "For password storage:\n"
            "1. Attacker obtains MD5 hash database via SQL injection or breach\n"
            "2. Cracks hashes using GPU (10 billion MD5/sec on commodity hardware)\n"
            "3. Recovers plaintext passwords in minutes"
        ),
        "remediation": (
            "```python\n"
            "import hashlib\n\n"
            "# For data integrity:\n"
            "# Instead of: hashlib.md5(data).hexdigest()\n"
            "hashlib.sha256(data).hexdigest()\n\n"
            "# For passwords — use bcrypt, not raw SHA:\n"
            "import bcrypt\n"
            "hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n"
            "```"
        ),
        "stride": "Tampering",
        "risk_note": "MD5/SHA-1 are cryptographically broken",
    },
    "B311": {
        "analytical_title": "Non-Cryptographic Random Number Generator",
        "description": (
            "The application uses Python's `random` module which produces predictable "
            "pseudo-random numbers. These generators are not suitable for security-sensitive "
            "operations such as token generation, password creation, or cryptographic key derivation."
        ),
        "impact": (
            "- If used in security-sensitive code: tokens are predictable and forgeable\n"
            "- If used in test/mock code only: risk is minimal — see risk_note\n"
            "- Mersenne Twister state can be recovered from 624 consecutive outputs"
        ),
        "attack_scenario": (
            "If `random` is used for security tokens:\n"
            "1. Attacker observes several generated tokens\n"
            "2. Seeds the Mersenne Twister with observed values\n"
            "3. Predicts future tokens with high accuracy\n"
            "4. Gains unauthorized access using predicted tokens"
        ),
        "remediation": (
            "For test/mock data generation, `random` is acceptable — add `# nosec B311` "
            "to acknowledge this is intentional.\n\n"
            "For any security-sensitive code, replace with:\n\n"
            "```python\n"
            "import secrets\n\n"
            "# Instead of: random.randint(0, 999999)\n"
            "token = secrets.randbelow(1000000)\n\n"
            "# Instead of: random.choice(items)\n"
            "item = secrets.choice(items)\n"
            "```"
        ),
        "stride": "Spoofing",
        "risk_note": "Verify usage context — informational if in test/mock code only",
    },
    "B501": {
        "analytical_title": "SSL/TLS Certificate Verification Disabled",
        "description": (
            "SSL/TLS certificate verification is disabled (`verify=False`). "
            "This disables the entire chain of trust for HTTPS connections, making them "
            "vulnerable to man-in-the-middle attacks."
        ),
        "impact": (
            "- All HTTPS traffic is vulnerable to interception\n"
            "- Attacker between client and server can read and modify all data\n"
            "- Credentials, tokens, and session data transmitted in cleartext to attacker"
        ),
        "attack_scenario": (
            "1. Attacker positions themselves on the network path (coffee shop WiFi, VPN, etc.)\n"
            "2. Presents a self-signed certificate for the target domain\n"
            "3. Application accepts it because verify=False\n"
            "4. Attacker decrypts and reads all traffic including credentials"
        ),
        "remediation": (
            "```python\n"
            "# Remove verify=False entirely — it defaults to True\n"
            "response = requests.get(url)  # Correct\n\n"
            "# If using a custom CA (e.g., internal PKI):\n"
            "response = requests.get(url, verify='/path/to/ca-bundle.crt')\n"
            "```\n\n"
            "Never disable SSL verification in production code."
        ),
        "stride": "Information Disclosure",
        "risk_note": "MITM attack fully enables credential theft",
    },
    "B502": {
        "analytical_title": "Outdated SSL/TLS Protocol Version",
        "description": (
            "The application explicitly specifies an outdated SSL/TLS protocol version "
            "(SSLv2, SSLv3, TLSv1, TLSv1.1). These versions have known cryptographic "
            "weaknesses (POODLE, BEAST, DROWN) and should not be used."
        ),
        "impact": (
            "- POODLE attack can decrypt SSLv3/TLSv1 traffic\n"
            "- BEAST attack targets TLSv1.0 CBC ciphers\n"
            "- Server may downgrade to vulnerable protocol if client offers it"
        ),
        "attack_scenario": (
            "1. Attacker intercepts connection and forces downgrade to SSLv3\n"
            "2. Uses POODLE attack to decrypt session cookies\n"
            "3. Hijacks authenticated session"
        ),
        "remediation": (
            "```python\n"
            "import ssl\n\n"
            "# Use TLSv1.2 minimum or let Python choose the latest:\n"
            "context = ssl.create_default_context()\n"
            "context.minimum_version = ssl.TLSVersion.TLSv1_2\n"
            "```"
        ),
        "stride": "Information Disclosure",
        "risk_note": "Outdated TLS versions have known exploitable weaknesses",
    },
    "B506": {
        "analytical_title": "Unsafe YAML Deserialization",
        "description": (
            "The application calls `yaml.load()` without specifying a safe Loader. "
            "The default Loader can construct arbitrary Python objects, "
            "including ones that execute code during construction."
        ),
        "impact": (
            "- Remote Code Execution if attacker can control YAML input\n"
            "- Full server compromise from a single malicious YAML document\n"
            "- yaml.load() with full Loader is equivalent to pickle for this attack class"
        ),
        "attack_scenario": (
            "1. Attacker submits a malicious YAML document:\n"
            "   ```yaml\n"
            "   !!python/object/apply:os.system\n"
            "   args: ['id > /tmp/pwned']\n"
            "   ```\n"
            "2. `yaml.load(payload)` executes the OS command"
        ),
        "remediation": (
            "```python\n"
            "import yaml\n\n"
            "# Instead of: yaml.load(data)\n"
            "yaml.safe_load(data)  # Never executes code\n\n"
            "# Or explicitly:\n"
            "yaml.load(data, Loader=yaml.SafeLoader)\n"
            "```"
        ),
        "stride": "Tampering",
        "risk_note": "RCE risk if attacker controls YAML input",
    },
    "B602": {
        "analytical_title": "Shell Injection via subprocess shell=True",
        "description": (
            "A subprocess is launched with `shell=True`, which passes the command string "
            "to the OS shell. If any part of the command string is derived from user input, "
            "an attacker can inject arbitrary shell commands."
        ),
        "impact": (
            "- Arbitrary OS command execution with application's privileges\n"
            "- Full system compromise if application runs as root/admin\n"
            "- Data exfiltration, file deletion, backdoor installation"
        ),
        "attack_scenario": (
            "1. Application constructs: `cmd = f'ls {user_input}'`\n"
            "2. Attacker provides: `user_input = '; rm -rf /important'`\n"
            "3. Shell executes: `ls ; rm -rf /important`"
        ),
        "remediation": (
            "```python\n"
            "import subprocess\n\n"
            "# Instead of: subprocess.run(f'ls {user_path}', shell=True)\n"
            "subprocess.run(['ls', user_path], shell=False)  # Safe\n\n"
            "# Never concatenate user input into shell commands\n"
            "```"
        ),
        "stride": "Elevation of Privilege",
        "risk_note": "shell=True with user input is command injection",
    },
    "B603": {
        "analytical_title": "subprocess Call Without shell=True",
        "description": (
            "A subprocess call was detected. While `shell=False` (the default) is safer "
            "than `shell=True`, passing user-controlled data as arguments can still lead "
            "to unintended command execution in some contexts."
        ),
        "impact": (
            "- Lower risk than B602 but still warrants review\n"
            "- Path traversal or argument injection may be possible depending on the command"
        ),
        "attack_scenario": (
            "1. Application calls `subprocess.run(['git', 'clone', user_url])`\n"
            "2. Attacker provides a URL with embedded options: `--upload-pack=malicious`\n"
            "3. Command-specific option injection occurs"
        ),
        "remediation": (
            "```python\n"
            "# Validate and sanitize all arguments:\n"
            "import shlex\n"
            "safe_path = shlex.quote(user_path)\n"
            "subprocess.run(['ls', safe_path])  # Still use list form\n"
            "```"
        ),
        "stride": "Elevation of Privilege",
        "risk_note": "Review all subprocess calls with user-controlled arguments",
    },
    "B605": {
        "analytical_title": "Process Started with Shell Command",
        "description": (
            "The application starts a process using `os.system()`, `os.popen()`, or "
            "similar shell-invocation functions. These functions pass the command to "
            "the OS shell, creating shell injection risk."
        ),
        "impact": (
            "- Shell injection if any user input reaches the command string\n"
            "- Same severity as B602 — arbitrary OS command execution"
        ),
        "attack_scenario": (
            "Same as B602: attacker injects shell metacharacters into command string."
        ),
        "remediation": (
            "```python\n"
            "# Instead of: os.system(f'process {user_input}')\n"
            "import subprocess\n"
            "subprocess.run(['process', user_input], shell=False)\n"
            "```"
        ),
        "stride": "Elevation of Privilege",
        "risk_note": "Replace os.system/popen with subprocess list form",
    },
    "B608": {
        "analytical_title": "SQL Injection via String Formatting",
        "description": (
            "SQL queries are constructed using string formatting or concatenation with "
            "variable data. This is the classic SQL injection pattern — if any variable "
            "contains user input, the entire database is at risk."
        ),
        "impact": (
            "- Read all data in the database (authentication bypass, data theft)\n"
            "- Modify or delete data (UPDATE/DELETE injection)\n"
            "- In some databases: OS command execution via xp_cmdshell or similar\n"
            "- OWASP #3 — one of the most common and impactful vulnerabilities"
        ),
        "attack_scenario": (
            "1. Application builds: `query = f\"SELECT * FROM users WHERE id={user_id}\"`\n"
            "2. Attacker provides: `user_id = '1 OR 1=1'`\n"
            "3. Query becomes: `SELECT * FROM users WHERE id=1 OR 1=1` — returns all users"
        ),
        "remediation": (
            "Use parameterized queries:\n\n"
            "```python\n"
            "# Instead of:\n"
            "cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")\n\n"
            "# Use parameterized:\n"
            "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))\n"
            "# Or with SQLAlchemy: session.query(User).filter(User.id == user_id)\n"
            "```"
        ),
        "stride": "Tampering",
        "risk_note": "Parameterize all queries — never format user input into SQL",
    },
    "SRC-INFO-LEAK": {
        "analytical_title": "Sensitive Exception Information Disclosure",
        "description": (
            "The application exposes detailed error messages, stack traces, and potentially "
            "sensitive internal information in exception handlers. When exceptions occur, "
            "the full exception message (which may contain file paths, library versions, "
            "API responses, or credential fragments) is printed to user-facing output."
        ),
        "impact": (
            "- Exposes internal file paths and application structure\n"
            "- Reveals library versions and Python internals\n"
            "- May leak partial API responses or credential information\n"
            "- Aids attackers in reconnaissance for targeted exploitation\n"
            "- Violates the principle of least information"
        ),
        "attack_scenario": (
            "1. Attacker triggers an intentional error (malformed input, invalid token)\n"
            "2. Application prints full exception details to the UI\n"
            "3. Exception reveals: file paths, library versions, API endpoint URLs\n"
            "4. Attacker uses this information to craft targeted attacks\n\n"
            "```python\n"
            "# What the attacker sees:\n"
            "# \"Error: ConnectionError: Failed to connect to api.example.com:443\n"
            "#  File '/home/app/src/api/client.py', line 183\n"
            "#  requests.exceptions.SSLError: certificate verify failed\"\n"
            "```"
        ),
        "remediation": (
            "Replace detailed exception output with generic user-facing messages. "
            "Log full details server-side only:\n\n"
            "```python\n"
            "import logging\n"
            "logger = logging.getLogger(__name__)\n\n"
            "try:\n"
            "    response = self._make_request(url)\n"
            "except Exception as e:\n"
            "    # Log details for debugging (not user-visible)\n"
            "    logger.error(f\"API request failed: {e}\", exc_info=True)\n"
            "    # Show generic message to user\n"
            "    raise ApplicationError(\"Unable to complete request. Please try again.\")\n"
            "```"
        ),
        "stride": "Information Disclosure",
        "risk_note": "Leaks internal application details that aid attackers",
    },
    "SRC-JWT-NOSIG": {
        "analytical_title": "JWT Signature Verification Disabled",
        "description": (
            "JWT signature verification is explicitly disabled (`verify_signature: False`). "
            "While other validation checks (expiration, required claims) may still apply, "
            "disabling signature verification means the application cannot locally detect "
            "forged or tampered tokens."
        ),
        "impact": (
            "- Cannot locally detect forged JWT tokens\n"
            "- Relies entirely on downstream API for token validation\n"
            "- If API validation is bypassed or cached, forged tokens succeed\n"
            "- Reduced defense-in-depth for authentication"
        ),
        "attack_scenario": (
            "1. Attacker crafts a JWT with `{\"alg\": \"none\"}` and arbitrary claims\n"
            "2. Application accepts token without checking signature\n"
            "3. Other validation (expiration, claims) still applies\n"
            "4. Token is sent to downstream API, which may or may not reject it\n\n"
            "**Note:** Partially mitigated by expiration checks and API-side validation, "
            "but signature verification adds another layer of defense."
        ),
        "remediation": (
            "If the token issuer publishes a JWKS endpoint, enable signature verification:\n\n"
            "```python\n"
            "options = {\n"
            "    \"verify_signature\": True,  # Enable when key is available\n"
            "    \"verify_exp\": True,\n"
            "    \"require\": [\"exp\", \"user_id\"],\n"
            "}\n"
            "```\n\n"
            "If no public key is available, document this as an accepted risk and ensure "
            "compensating controls (expiration, API verification) remain in place."
        ),
        "stride": "Spoofing",
        "risk_note": "Partially mitigated by expiration checks and API-side validation",
    },
    "SRC-CRED-ENV": {
        "analytical_title": "Plaintext Credential Storage in Environment Variables",
        "description": (
            "The application reads authentication credentials from environment variables. "
            "While using environment variables is better than hardcoding, credentials are "
            "stored in plaintext on the filesystem (typically in `.env` files), accessible "
            "to any process running as the same user."
        ),
        "impact": (
            "- Credentials stored in plaintext on filesystem\n"
            "- Accessible to any process running as the same OS user\n"
            "- Risk of accidental inclusion in backups, logs, or version control\n"
            "- No credential rotation mechanism"
        ),
        "attack_scenario": (
            "1. Attacker gains filesystem access (malware, shared system, backup exposure)\n"
            "2. Reads `.env` file containing `API_TOKEN=...`\n"
            "3. Uses stolen token to access the victim's account\n"
            "4. No audit trail of credential theft"
        ),
        "remediation": (
            "For local-only applications, environment variables are a reasonable approach. "
            "To improve security:\n\n"
            "1. **Set restrictive permissions:** `chmod 600 .env`\n"
            "2. **Use OS keyring** for sensitive values (macOS Keychain, Windows Credential Manager)\n"
            "3. **Rotate credentials** regularly\n"
            "4. **Pre-commit hooks** to prevent `.env` from being committed\n\n"
            "```python\n"
            "import keyring\n"
            "token = keyring.get_password('YourApp', 'api_token')\n"
            "```"
        ),
        "stride": "Information Disclosure",
        "risk_note": "Standard pattern for local apps; consider OS keyring for improvement",
    },
}


DEP_ENRICHMENT = {
    "description_template": (
        "The installed version of `{package}` ({version}) has a known vulnerability "
        "tracked as {cve}."
    ),
    "impact": (
        "Vulnerable dependencies can be exploited by attackers to compromise the "
        "application, escalate privileges, or cause denial of service. The specific "
        "impact depends on the vulnerability."
    ),
    "remediation_template": (
        "Upgrade `{package}` to the fixed version:\n\n"
        "```bash\npip install \"{package}>={fix_version}\"\n```\n\n"
        "After upgrading, verify the application still works correctly and re-run "
        "`pip-audit` to confirm the vulnerability is resolved."
    ),
}


def get_enrichment(test_id: str) -> dict:
    """
    Get enrichment for a finding ID.

    Tier 1: full enrichment from FINDING_ENRICHMENT dict.
    Tier 2: fallback from BANDIT_OWASP_MAP (analytical_title from description).
    Tier 3: unknown ID — return id as analytical_title.
    """
    if test_id in FINDING_ENRICHMENT:
        return FINDING_ENRICHMENT[test_id]
    if test_id in BANDIT_OWASP_MAP:
        owasp_cat, desc = BANDIT_OWASP_MAP[test_id]
        return {"analytical_title": desc, "owasp": owasp_cat}
    return {"analytical_title": test_id}


def group_findings(bandit_data: dict, dep_vulns: list, source_findings: list) -> list[dict]:
    """
    Group raw findings into logical vulnerabilities.

    Deduplicates by (test_id, file): instead of 20 identical random.randint()
    entries, produces one finding with a list of affected locations.

    Returns a list of grouped findings sorted by severity then file.
    """
    groups = {}

    # Group bandit results by (test_id, file)
    for r in bandit_data.get("results", []):
        test_id = r.get("test_id", "unknown")
        filename = r.get("filename", "unknown")
        key = (test_id, filename)
        if key not in groups:
            cwe = r.get("issue_cwe", {})
            owasp_cat, owasp_desc = BANDIT_OWASP_MAP.get(test_id, ("Uncategorized", test_id))
            groups[key] = {
                "source": "bandit",
                "test_id": test_id,
                "severity": r["issue_severity"].upper(),
                "title": r["issue_text"],
                "file": filename,
                "lines": [],
                "code_snippets": [],
                "cwe_id": cwe.get("id"),
                "cwe_link": cwe.get("link", ""),
                "owasp": owasp_cat,
                "owasp_desc": owasp_desc,
                "confidence": r.get("issue_confidence", ""),
                "more_info": r.get("more_info", ""),
            }
        groups[key]["lines"].append(r["line_number"])
        if r.get("code"):
            groups[key]["code_snippets"].append(r["code"].strip())

    # Group source findings by (id, file)
    for f in source_findings:
        key = (f["id"], f.get("file", "unknown"))
        if key not in groups:
            groups[key] = {
                "source": "source-scan",
                "test_id": f["id"],
                "severity": f["severity"].upper(),
                "title": f["title"],
                "file": f.get("file", "N/A"),
                "lines": [],
                "code_snippets": [],
                "cwe_id": f.get("cwe", "").replace("CWE-", "") if f.get("cwe") else None,
                "cwe_link": "",
                "owasp": f.get("owasp", ""),
                "owasp_desc": "",
                "confidence": "",
                "more_info": "",
            }
        groups[key]["lines"].append(f.get("line", 0))
        if f.get("code_snippet"):
            groups[key]["code_snippets"].append(f["code_snippet"])

    grouped = list(groups.values())

    # Add dependency vulnerabilities as individual findings
    for v in dep_vulns:
        grouped.append({
            "source": "dep",
            "test_id": v["cve"],
            "severity": "HIGH",
            "title": f"Vulnerable dependency: {v['package']}",
            "file": "requirements.txt",
            "lines": [],
            "code_snippets": [],
            "cwe_id": None,
            "cwe_link": "",
            "owasp": "A06:2021 - Vulnerable and Outdated Components",
            "owasp_desc": "",
            "confidence": "",
            "more_info": "",
            "dep_info": v,
        })

    grouped.sort(key=lambda g: (SEVERITY_ORDER.get(g["severity"], 9), g["file"]))
    return grouped
```

### Step 4: Run tests to verify they pass

```bash
pytest ~/.claude/skills/agent-security/tests/test_mitigation_suggester.py -v
```
Expected: `17 passed`

### Step 5: Commit

```bash
git add ~/.claude/skills/agent-security/utils/mitigation_suggester.py \
        ~/.claude/skills/agent-security/tests/test_mitigation_suggester.py
git commit -m "feat: add mitigation_suggester.py — OWASP map, 15 enrichments, finding dedup"
```

---

## Task 4: `utils/security_reporter.py`

**Files:**
- Create: `~/.claude/skills/agent-security/utils/security_reporter.py`
- Create: `~/.claude/skills/agent-security/tests/test_security_reporter.py`

### Step 1: Write the failing tests

```python
# ~/.claude/skills/agent-security/tests/test_security_reporter.py
import json
import sys
import tempfile
from datetime import datetime
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.security_reporter import SecurityReporter


# ── helpers ───────────────────────────────────────────────────────────────────

def _empty_audit_inputs():
    return dict(
        bandit_data={"results": [], "metrics": {"_totals": {"loc": 0}}},
        pytest_data={"passed": 0, "failed": 0, "total": 0, "test_names": [], "failures": []},
        dep_vulns=[],
        secrets_data={"results": {}},
        source_findings=[],
    )


def _reporter(project_name="TestApp"):
    root = Path(tempfile.mkdtemp())
    return SecurityReporter(str(root), project_name=project_name), root


# ── constructor ───────────────────────────────────────────────────────────────

def test_project_name_from_arg():
    reporter, _ = _reporter("MyProject")
    assert reporter.project_name == "MyProject"


def test_project_name_auto_detected():
    root = Path(tempfile.mkdtemp()) / "cool-project"
    root.mkdir()
    reporter = SecurityReporter(str(root))
    assert reporter.project_name == "cool-project"


# ── generate_threat_model ─────────────────────────────────────────────────────

def test_generate_threat_model_creates_json_and_md():
    reporter, root = _reporter()
    data = {
        "threats": [],
        "attack_surface": {"entry_points": [], "trust_boundaries": [], "sensitive_data": []},
        "dependencies": {},
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "open": 0, "mitigated": 0},
        "timestamp": datetime.now().isoformat(),
    }
    json_path, md_path = reporter.generate_threat_model(data)
    assert json_path.exists()
    assert md_path.exists()
    assert json_path.suffix == ".json"
    assert md_path.suffix == ".md"


def test_generate_threat_model_output_in_docs_security():
    reporter, root = _reporter()
    data = {"threats": [], "timestamp": datetime.now().isoformat()}
    json_path, md_path = reporter.generate_threat_model(data)
    assert "docs" in str(json_path)
    assert "security" in str(json_path)


def test_generate_threat_model_filename_has_date():
    reporter, root = _reporter()
    data = {"threats": [], "timestamp": datetime.now().isoformat()}
    json_path, md_path = reporter.generate_threat_model(data)
    today = datetime.now().strftime("%Y-%m-%d")
    assert today in json_path.name


def test_generate_threat_model_json_has_project_name():
    reporter, root = _reporter("WidgetApp")
    data = {"threats": [], "timestamp": datetime.now().isoformat()}
    json_path, _ = reporter.generate_threat_model(data)
    content = json.loads(json_path.read_text())
    assert content.get("project") == "WidgetApp"


def test_generate_threat_model_md_contains_project_name():
    reporter, root = _reporter("WidgetApp")
    data = {"threats": [], "timestamp": datetime.now().isoformat()}
    _, md_path = reporter.generate_threat_model(data)
    assert "WidgetApp" in md_path.read_text()


# ── generate_audit ────────────────────────────────────────────────────────────

def test_generate_audit_returns_three_paths():
    reporter, root = _reporter()
    audit_dir = root / "audits" / "test-run"
    paths = reporter.generate_audit(audit_dir, **_empty_audit_inputs())
    assert len(paths) == 3


def test_generate_audit_creates_all_three_files():
    reporter, root = _reporter()
    audit_dir = root / "audits" / "test-run"
    paths = reporter.generate_audit(audit_dir, **_empty_audit_inputs())
    names = {p.name for p in paths}
    assert "audit-report.md" in names
    assert "vulnerabilities.md" in names
    assert "remediation-roadmap.md" in names
    for p in paths:
        assert p.exists()


def test_generate_audit_audit_report_contains_project_name():
    reporter, root = _reporter("WidgetApp")
    audit_dir = root / "audits" / "test-run"
    paths = reporter.generate_audit(audit_dir, **_empty_audit_inputs())
    audit = next(p for p in paths if p.name == "audit-report.md")
    assert "WidgetApp" in audit.read_text()


def test_generate_audit_no_hardcoded_pelotonracer():
    reporter, root = _reporter("WidgetApp")
    audit_dir = root / "audits" / "test-run"
    paths = reporter.generate_audit(audit_dir, **_empty_audit_inputs())
    for p in paths:
        assert "PelotonRacer" not in p.read_text(), f"'PelotonRacer' found in {p.name}"


def test_generate_audit_footer_references_agent_command():
    reporter, root = _reporter()
    audit_dir = root / "audits" / "test-run"
    paths = reporter.generate_audit(audit_dir, **_empty_audit_inputs())
    audit = next(p for p in paths if p.name == "audit-report.md")
    assert "/agent:security" in audit.read_text()


def test_generate_audit_roadmap_no_peloton_risk_blockers():
    reporter, root = _reporter()
    audit_dir = root / "audits" / "test-run"
    paths = reporter.generate_audit(audit_dir, **_empty_audit_inputs())
    roadmap = next(p for p in paths if p.name == "remediation-roadmap.md")
    content = roadmap.read_text()
    assert "Peloton may change" not in content


def test_generate_audit_with_bandit_findings_deduplicates():
    reporter, root = _reporter()
    audit_dir = root / "audits" / "test-run"
    bandit_data = {"results": [
        {"test_id": "B311", "filename": "src/mock.py", "line_number": 10,
         "issue_severity": "LOW", "issue_text": "random", "issue_cwe": {},
         "issue_confidence": "HIGH", "more_info": "", "code": "random.randint()"},
        {"test_id": "B311", "filename": "src/mock.py", "line_number": 20,
         "issue_severity": "LOW", "issue_text": "random", "issue_cwe": {},
         "issue_confidence": "HIGH", "more_info": "", "code": "random.choice()"},
    ], "metrics": {"_totals": {"loc": 500}}}
    inputs = _empty_audit_inputs()
    inputs["bandit_data"] = bandit_data
    paths = reporter.generate_audit(audit_dir, **inputs)
    audit = next(p for p in paths if p.name == "vulnerabilities.md")
    content = audit.read_text()
    # Deduplicated: one entry for B311 in src/mock.py, not two
    assert content.count("LOW-001:") == 1
```

### Step 2: Run test to verify it fails

```bash
pytest ~/.claude/skills/agent-security/tests/test_security_reporter.py -v
```
Expected: `ImportError` — module does not exist yet.

### Step 3: Implement `security_reporter.py`

Source reference: `/Users/nissim/dev/PelotonRacer/scripts/generate_security_reports.py`

Parameterization from original:
- `"PelotonRacer"` (10+ occurrences) → `self.project_name`
- `./scripts/run_security_audit.sh --report` in footers → `/agent:security --full`
- Risk blockers section "Peloton may change authentication" → generic dependency conflicts section only
- Output paths use `project_root / "docs" / "security"` instead of hardcoded

```python
# ~/.claude/skills/agent-security/utils/security_reporter.py
"""
Security report generator.

Two modes:
  generate_threat_model(data) — STRIDE/OWASP threat model report
    Output: docs/security/YYYY-MM-DD-threat-model.{json,md}
    Source: migrated from shared/report_generator.py _generate_security_markdown()

  generate_audit(audit_dir, ...) — Full tool-based audit, three reports
    Output: audit_dir/{audit-report.md, vulnerabilities.md, remediation-roadmap.md}
    Source: migrated from scripts/generate_security_reports.py

Parameterization: all "PelotonRacer" references replaced with self.project_name.
"""

import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from jinja2 import Template
from utils.severity_calculator import SEVERITY_ORDER, SEVERITY_EMOJI, calculate_posture
from utils.mitigation_suggester import (
    BANDIT_OWASP_MAP, FINDING_ENRICHMENT, DEP_ENRICHMENT, group_findings, get_enrichment,
)


class SecurityReporter:
    def __init__(self, project_root: str, project_name: str = None):
        self.project_root = Path(project_root)
        self.project_name = project_name or self.project_root.name

    # ── Threat Model Report ────────────────────────────────────────────────────

    def generate_threat_model(self, data: dict) -> tuple[Path, Path]:
        """
        Generate STRIDE/OWASP threat model report.

        Args:
            data: structured threat data with keys:
                  threats, attack_surface, dependencies, summary, timestamp

        Returns:
            (json_path, md_path)
        """
        output_dir = self.project_root / "docs" / "security"
        output_dir.mkdir(parents=True, exist_ok=True)

        date_str = datetime.now().strftime("%Y-%m-%d")
        json_path = output_dir / f"{date_str}-threat-model.json"
        md_path = output_dir / f"{date_str}-threat-model.md"

        data["project"] = self.project_name
        if "timestamp" not in data:
            data["timestamp"] = datetime.now().isoformat()

        with open(json_path, "w") as f:
            json.dump(data, f, indent=2, default=str)

        md_path.write_text(self._render_threat_model_markdown(data))
        return json_path, md_path

    def _render_threat_model_markdown(self, data: dict) -> str:
        template = Template(r"""# Security Threat Model - {{ project }}

**Generated:** {{ timestamp }}

## Executive Summary

{% if summary %}
{% if summary.critical > 0 %}🔴 {{ summary.critical }} Critical{% endif %}{% if summary.high > 0 %} | 🟠 {{ summary.high }} High{% endif %}{% if summary.medium > 0 %} | 🟡 {{ summary.medium }} Medium{% endif %}{% if summary.low > 0 %} | 🟢 {{ summary.low }} Low{% endif %}
**Status:** {{ summary.open }} Open, {{ summary.mitigated }} Mitigated
{% endif %}

## Threat Overview

{% set critical_threats = threats | selectattr('severity', 'equalto', 'CRITICAL') | list %}
{% set high_threats = threats | selectattr('severity', 'equalto', 'HIGH') | list %}
{% set medium_threats = threats | selectattr('severity', 'equalto', 'MEDIUM') | list %}
{% set low_threats = threats | selectattr('severity', 'equalto', 'LOW') | list %}

{% if critical_threats %}
### 🔴 Critical Threats

{% for threat in critical_threats %}
#### {{ threat.id }}: {{ threat.title }}

**Category:** {{ threat.category }}
**Files:** {{ threat.affected_files | join(', ') }}
**Status:** {{ threat.status }}

{{ threat.description }}

**Attack Scenario:**
{{ threat.attack_scenario }}

**Mitigation:**
{{ threat.mitigation }}

{% if threat.test_coverage %}**Test Coverage:** {{ threat.test_coverage | join(', ') }}{% endif %}

---
{% endfor %}
{% endif %}

{% if high_threats %}
### 🟠 High Severity Threats

{% for threat in high_threats %}
#### {{ threat.id }}: {{ threat.title }}

**Category:** {{ threat.category }}
**Files:** {{ threat.affected_files | join(', ') }}
**Status:** {{ threat.status }}

{{ threat.description }}

**Attack Scenario:**
{{ threat.attack_scenario }}

**Mitigation:**
{{ threat.mitigation }}

{% if threat.test_coverage %}**Test Coverage:** {{ threat.test_coverage | join(', ') }}{% endif %}

---
{% endfor %}
{% endif %}

{% if medium_threats %}
### 🟡 Medium Severity Threats

{% for threat in medium_threats %}
#### {{ threat.id }}: {{ threat.title }}

**Category:** {{ threat.category }} | **Status:** {{ threat.status }}

{{ threat.description }}

**Mitigation:** {{ threat.mitigation }}

---
{% endfor %}
{% endif %}

{% if low_threats %}
### 🟢 Low Severity Threats

{% for threat in low_threats %}
- **{{ threat.id }}:** {{ threat.title }} ({{ threat.category }})
{% endfor %}
{% endif %}

{% if attack_surface %}
## Attack Surface

**Entry Points:** {{ attack_surface.entry_points | join(', ') }}

**Trust Boundaries:**
{% for boundary in attack_surface.trust_boundaries %}
- {{ boundary }}
{% endfor %}

**Sensitive Data:**
{% for item in attack_surface.sensitive_data %}
- {{ item }}
{% endfor %}
{% endif %}

{% if dependencies and (dependencies.vulnerable or dependencies.outdated) %}
## Dependencies

{% if dependencies.vulnerable %}
### Vulnerable Packages
{% for dep in dependencies.vulnerable %}
- **{{ dep.package }}** {{ dep.version }}: {{ dep.cve }} ({{ dep.severity }})
  - Fix: {{ dep.fix }}
{% endfor %}
{% endif %}

{% if dependencies.outdated %}
### Outdated Packages
{% for dep in dependencies.outdated %}
- {{ dep }}
{% endfor %}
{% endif %}
{% endif %}

{% if recommendations %}
## Recommendations

{% for rec in recommendations %}
{{ loop.index }}. {{ rec }}
{% endfor %}
{% endif %}

---

*Generated by `/agent:security`*
""")
        return template.render(
            project=data.get("project", "Unknown"),
            timestamp=data.get("timestamp", datetime.now().isoformat()),
            summary=type("S", (), data.get("summary", {}))() if data.get("summary") else None,
            threats=data.get("threats", []),
            attack_surface=data.get("attack_surface", {}),
            dependencies=data.get("dependencies", {}),
            recommendations=data.get("recommendations", []),
        )

    # ── Full Audit Report ──────────────────────────────────────────────────────

    def generate_audit(
        self,
        audit_dir: Path,
        bandit_data: dict,
        pytest_data: dict,
        dep_vulns: list,
        secrets_data: dict,
        source_findings: list,
    ) -> list[Path]:
        """
        Generate full tool-based audit: three reports.

        Args:
            audit_dir:       directory to write reports into
            bandit_data:     parsed bandit JSON output
            pytest_data:     parsed pytest results
            dep_vulns:       list of dependency vulnerabilities (from pip-audit)
            secrets_data:    parsed detect-secrets output
            source_findings: list of CodeFinding dicts from CodeScanner

        Returns:
            list of [audit-report.md, vulnerabilities.md, remediation-roadmap.md] paths
        """
        audit_dir = Path(audit_dir)
        audit_dir.mkdir(parents=True, exist_ok=True)

        # Convert CodeFinding dataclasses to dicts if needed
        source_dicts = []
        for f in source_findings:
            if hasattr(f, "__dataclass_fields__"):
                source_dicts.append({
                    "id": f.id, "title": f.title, "severity": f.severity,
                    "cwe": f.cwe, "owasp": f.owasp, "file": f.file,
                    "line": f.line, "code_snippet": f.code_snippet,
                })
            else:
                source_dicts.append(f)

        grouped = group_findings(bandit_data, dep_vulns, source_dicts)
        git_info = self._get_git_info()

        reports = [
            ("audit-report.md",
             self._generate_audit_report(audit_dir, grouped, pytest_data, dep_vulns,
                                         secrets_data, git_info, bandit_data)),
            ("vulnerabilities.md",
             self._generate_vulnerabilities_report(grouped, dep_vulns)),
            ("remediation-roadmap.md",
             self._generate_remediation_roadmap(grouped, dep_vulns, pytest_data)),
        ]

        paths = []
        for name, content in reports:
            path = audit_dir / name
            path.write_text(content)
            paths.append(path)
        return paths

    def _get_git_info(self) -> dict:
        try:
            branch = subprocess.check_output(
                ["git", "branch", "--show-current"], text=True, stderr=subprocess.DEVNULL,
                cwd=str(self.project_root)
            ).strip()
        except Exception:
            branch = "unknown"
        try:
            commit = subprocess.check_output(
                ["git", "rev-parse", "--short", "HEAD"], text=True, stderr=subprocess.DEVNULL,
                cwd=str(self.project_root)
            ).strip()
        except Exception:
            commit = "unknown"
        return {"branch": branch, "commit": commit}

    def _count_grouped(self, grouped: list, source: str) -> int:
        return sum(1 for g in grouped if g["source"] == source)

    def _generate_audit_report(self, audit_dir, grouped_findings, pytest_data, dep_vulns,
                                secrets_data, git_info, bandit_data) -> str:
        now = datetime.now().strftime("%B %d, %Y")
        now_full = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        totals = bandit_data.get("metrics", {}).get("_totals", {})
        lines_scanned = totals.get("loc", 0)
        secrets_count = sum(len(v) for v in secrets_data.get("results", {}).values())

        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for g in grouped_findings:
            sev = g["severity"]
            if sev in sev_counts:
                sev_counts[sev] += 1
        total_findings = sum(sev_counts.values())

        posture, posture_short = calculate_posture(sev_counts)

        key_findings_by_sev = {"CRITICAL": [], "HIGH": [], "MEDIUM": []}
        for g in grouped_findings:
            sev = g["severity"]
            if sev not in key_findings_by_sev:
                continue
            enrichment = get_enrichment(g["test_id"])
            title = enrichment.get("analytical_title", g["title"])
            locations = len(g["lines"])
            loc_note = f" ({locations} locations)" if locations > 1 else ""
            file_note = f" in `{g['file']}`" if g.get("file") else ""
            key_findings_by_sev[sev].append(f"**{title}**{loc_note}{file_note}")

        stride_summary = {}
        for g in grouped_findings:
            enrichment = get_enrichment(g["test_id"])
            stride_cat = enrichment.get("stride")
            if not stride_cat:
                cwe = g.get("cwe_id")
                if cwe:
                    cwe = int(cwe) if str(cwe).isdigit() else 0
                    if cwe in (287, 290, 295, 330, 347, 798):
                        stride_cat = "Spoofing"
                    elif cwe in (20, 22, 78, 79, 89, 94, 502):
                        stride_cat = "Tampering"
                    elif cwe in (209, 215, 312, 319, 532):
                        stride_cat = "Information Disclosure"
                    elif cwe in (400, 770):
                        stride_cat = "Denial of Service"
                    elif cwe in (250, 269, 272):
                        stride_cat = "Elevation of Privilege"
            if stride_cat:
                stride_summary.setdefault(stride_cat, []).append(g)

        owasp_summary = {}
        for g in grouped_findings:
            cat = g.get("owasp", "Uncategorized")
            if cat and cat != "Uncategorized":
                owasp_summary.setdefault(cat, []).append(g)

        test_files = {}
        for t in pytest_data["test_names"]:
            parts = t.split("::")
            fname = parts[0] if parts else t
            test_files.setdefault(fname, []).append(parts[-1] if len(parts) > 1 else t)

        report = f"""# Security Audit Report — {self.project_name}

**Audit Date:** {now}
**Generated:** {now_full}
**Auditor:** Automated Security Analysis (bandit, pip-audit, detect-secrets, pytest)
**Application:** {self.project_name}
**Branch:** {git_info['branch']}
**Commit:** {git_info['commit']}
**Scope:** Full application security assessment

---

## Executive Summary

This security audit of {self.project_name} scanned **{lines_scanned:,} lines** of source code \
and identified **{total_findings} unique security finding(s)** across the application.

### Severity Distribution

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | {sev_counts['CRITICAL']} | {SEVERITY_EMOJI['CRITICAL']} Requires immediate fix |
| HIGH | {sev_counts['HIGH']} | {SEVERITY_EMOJI['HIGH']} Fix before production |
| MEDIUM | {sev_counts['MEDIUM']} | {SEVERITY_EMOJI['MEDIUM']} Address in roadmap |
| LOW | {sev_counts['LOW']} | {SEVERITY_EMOJI['LOW']} Informational |
| **TOTAL** | **{total_findings}** | |

"""
        report += "### Key Findings\n\n"
        for sev in ["CRITICAL", "HIGH", "MEDIUM"]:
            items = key_findings_by_sev.get(sev, [])
            if items:
                report += f"**{sev} Issues:**\n"
                for i, desc in enumerate(items, 1):
                    report += f"{i}. {desc}\n"
                report += "\n"

        report += f"""### Risk Assessment

**Current Security Posture:** {posture}

"""
        if posture_short in ("CRITICAL", "HIGH"):
            report += (
                "The application contains vulnerabilities that should be addressed before "
                "production deployment or handling real user data. See the remediation roadmap "
                "(`remediation-roadmap.md`) for a prioritized fix plan.\n\n"
            )
        elif posture_short == "MEDIUM":
            report += (
                "The application has moderate security issues that should be addressed "
                "in the development roadmap. No critical or high-severity issues were found.\n\n"
            )

        report += f"""### Security Test Results

| Metric | Value |
|--------|-------|
| Security tests executed | {pytest_data['total']} |
| Tests passed | {pytest_data['passed']} |
| Tests failed | {pytest_data['failed']} |
| Dependency vulnerabilities | {len(dep_vulns)} |
| Secrets detected | {secrets_count} |

---

## Methodology

### Frameworks Applied

1. **STRIDE Threat Modeling** — findings classified by threat type
2. **OWASP Top 10 (2021)** — findings mapped to OWASP categories
3. **CWE (Common Weakness Enumeration)** — standardized vulnerability classification

### Tools Used

| Tool | Purpose | Findings |
|------|---------|----------|
| **bandit** | Static security analysis of Python source | {len(bandit_data.get('results', []))} raw ({self._count_grouped(grouped_findings, 'bandit')} grouped) |
| **pip-audit** | Dependency vulnerability scanning (CVE database) | {len(dep_vulns)} |
| **detect-secrets** | Secrets/credential leak detection | {secrets_count} |
| **pytest -m security** | Security-specific test suite | {pytest_data['passed']} passed, {pytest_data['failed']} failed |
| **Source pattern scan** | Custom regex for security anti-patterns | {self._count_grouped(grouped_findings, 'source-scan')} |

---

## Detailed Findings

"""
        finding_num = 0
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            sev_findings = [g for g in grouped_findings if g["severity"] == sev]
            if not sev_findings:
                continue
            report += f"### {SEVERITY_EMOJI[sev]} {sev} ({len(sev_findings)})\n\n"
            for g in sev_findings:
                finding_num += 1
                enrichment = get_enrichment(g["test_id"])
                title = enrichment.get("analytical_title", g["title"])
                locations = len(g["lines"])
                cwe_str = f"CWE-{g['cwe_id']}" if g.get("cwe_id") else "N/A"
                risk_note = enrichment.get("risk_note", "")
                report += f"{finding_num}. **{title}**\n"
                if g.get("source") == "dep":
                    dep = g.get("dep_info", {})
                    report += f"   - Package: `{dep.get('package', '')}` {dep.get('version', '')} — {dep.get('cve', '')}\n"
                    report += f"   - Fix: upgrade to {dep.get('fix_version', 'latest')}\n"
                else:
                    report += f"   - File: `{g['file']}`"
                    if locations == 1:
                        report += f" (line {g['lines'][0]})"
                    elif locations <= 5:
                        report += f" (lines {', '.join(str(l) for l in g['lines'])})"
                    else:
                        report += f" ({locations} locations)"
                    report += f"\n   - CWE: {cwe_str}\n   - OWASP: {g.get('owasp', 'N/A')}\n"
                if risk_note:
                    report += f"   - Note: {risk_note}\n"
                report += "\n"

        if dep_vulns:
            report += f"### {SEVERITY_EMOJI['HIGH']} Dependency Vulnerabilities ({len(dep_vulns)})\n\n"
            report += "| Package | Version | CVE | Fix Version | Description |\n"
            report += "|---------|---------|-----|-------------|-------------|\n"
            for v in dep_vulns:
                desc_short = v.get("description", "")[:80]
                if len(v.get("description", "")) > 80:
                    desc_short += "..."
                report += f"| {v['package']} | {v['version']} | {v['cve']} | {v['fix_version']} | {desc_short} |\n"
            report += "\n"

        report += "---\n\n## STRIDE Threat Analysis\n\n"
        stride_categories = [
            ("Spoofing", "Attacks that allow an entity to pretend to be someone else"),
            ("Tampering", "Unauthorized modification of data or code"),
            ("Repudiation", "Ability to deny an action occurred without accountability"),
            ("Information Disclosure", "Exposure of information to unauthorized parties"),
            ("Denial of Service", "Attacks that degrade or deny service availability"),
            ("Elevation of Privilege", "Gaining capabilities beyond what is authorized"),
        ]
        stride_id_counter = {}
        for cat_name, cat_desc in stride_categories:
            items = stride_summary.get(cat_name, [])
            prefix = cat_name[0]
            report += f"### {cat_name} ({len(items)} finding{'s' if len(items) != 1 else ''})\n\n"
            report += f"*{cat_desc}*\n\n"
            if items:
                report += "| ID | Threat | Severity | Status |\n"
                report += "|----|--------|----------|--------|\n"
                for g in items:
                    stride_id_counter.setdefault(prefix, 0)
                    stride_id_counter[prefix] += 1
                    sid = f"{prefix}-{stride_id_counter[prefix]:03d}"
                    enrichment = get_enrichment(g["test_id"])
                    title = enrichment.get("analytical_title", g["title"])
                    report += f"| {sid} | {title} | {g['severity']} | Open |\n"
                report += "\n"
            else:
                report += "No findings in this category.\n\n"
            report += "---\n\n"

        report += "## OWASP Top 10 Mapping\n\n"
        report += "| OWASP Category | Findings | Severity Range |\n"
        report += "|----------------|----------|----------------|\n"
        for cat in sorted(owasp_summary.keys()):
            items = owasp_summary[cat]
            sevs = sorted(set(g["severity"] for g in items), key=lambda s: SEVERITY_ORDER.get(s, 9))
            sev_str = "/".join(sevs)
            names = []
            for g in items:
                e = get_enrichment(g["test_id"])
                names.append(e.get("analytical_title", g["title"]))
            names_str = ", ".join(dict.fromkeys(names))
            report += f"| {cat} | {names_str} | {sev_str} |\n"
        if not owasp_summary:
            report += "| No findings mapped | — | — |\n"
        report += f"\n**Coverage:** {len(owasp_summary)} OWASP categories with findings\n\n"

        report += "---\n\n## Security Test Coverage\n\n"
        report += f"**{pytest_data['passed']}** security-marked tests passed"
        if pytest_data["failed"]:
            report += f", **{pytest_data['failed']}** failed"
        report += ".\n\n"
        if test_files:
            report += "| Test File | Tests |\n"
            report += "|-----------|-------|\n"
            for fname, tests in sorted(test_files.items()):
                report += f"| `{fname}` | {len(tests)} |\n"
            report += "\n"

        report += "---\n\n## Recommendations\n\n### Immediate Actions\n\n"
        action_num = 0
        for g in grouped_findings:
            if g["severity"] in ("CRITICAL", "HIGH") and g["source"] != "dep":
                action_num += 1
                enrichment = get_enrichment(g["test_id"])
                title = enrichment.get("analytical_title", g["title"])
                report += f"{action_num}. **{title}** — `{g['file']}`\n"
        for v in dep_vulns:
            action_num += 1
            report += f"{action_num}. **Upgrade {v['package']}** — {v['cve']} (fix: {v['fix_version']})\n"
        if action_num == 0:
            report += "No immediate actions required.\n"
        report += "\n"

        medium_findings = [g for g in grouped_findings if g["severity"] == "MEDIUM"]
        if medium_findings:
            report += "### Short-Term Improvements\n\n"
            for i, g in enumerate(medium_findings, 1):
                enrichment = get_enrichment(g["test_id"])
                title = enrichment.get("analytical_title", g["title"])
                report += f"{i}. **{title}** — `{g['file']}`\n"
            report += "\n"

        report += """### Ongoing Security Practices

- Run security audit before major releases (`/agent:security --full`)
- Keep dependencies updated (`pip-audit` monthly)
- Review security test coverage when adding new features
- Conduct periodic manual security review

"""
        report += f"""---

## How to Re-run This Audit

```bash
/agent:security --full
```

---

**Document Version:** Auto-generated
**Last Updated:** {now_full}
**Next Review:** After remediation of {sev_counts.get('CRITICAL', 0) + sev_counts.get('HIGH', 0)} critical/high findings
"""
        return report

    def _generate_vulnerabilities_report(self, grouped_findings, dep_vulns) -> str:
        now = datetime.now().strftime("%B %d, %Y")
        now_full = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        report = f"""# Security Vulnerabilities — Detailed Documentation

This document provides in-depth technical details, attack scenarios, and remediation \
guidance for each security vulnerability identified in the {self.project_name} security audit.

**Audit Date:** {now}
**Document Version:** Auto-generated
**Total Findings:** {len(grouped_findings)} (deduplicated)

---

## Table of Contents

"""
        for i, g in enumerate(grouped_findings, 1):
            enrichment = get_enrichment(g["test_id"])
            title = enrichment.get("analytical_title", g["title"])
            sev = g["severity"]
            anchor = re.sub(r"[^a-z0-9-]", "", title.lower().replace(" ", "-"))
            report += f"- [{SEVERITY_EMOJI.get(sev, '')} {sev}-{i:03d}: {title}](#{sev.lower()}-{i:03d}-{anchor})\n"

        report += "\n---\n\n"

        for i, g in enumerate(grouped_findings, 1):
            sev = g["severity"]
            emoji = SEVERITY_EMOJI.get(sev, "")
            enrichment = get_enrichment(g["test_id"])
            title = enrichment.get("analytical_title", g["title"])

            report += f"## {emoji} {sev}-{i:03d}: {title}\n\n"
            report += f"**Category:** {g.get('owasp', 'N/A')}\n"

            if g["source"] == "dep":
                dep = g.get("dep_info", {})
                report += f"**CVE:** [{dep['cve']}](https://nvd.nist.gov/vuln/detail/{dep['cve']})\n\n"
            else:
                cwe_str = f"CWE-{g['cwe_id']}" if g.get("cwe_id") else "N/A"
                cwe_link = g.get("cwe_link", "")
                if cwe_link:
                    report += f"**CWE:** [{cwe_str}]({cwe_link})\n"
                else:
                    report += f"**CWE:** {cwe_str}\n"
                if g.get("test_id") and g["source"] == "bandit":
                    report += f"**Bandit ID:** {g['test_id']}\n"
                report += "\n"

            report += "### Description\n\n"
            if g["source"] == "dep":
                dep = g.get("dep_info", {})
                report += DEP_ENRICHMENT["description_template"].format(**dep) + "\n\n"
                if dep.get("description"):
                    report += f"{dep['description']}\n\n"
            elif enrichment.get("description"):
                report += enrichment["description"] + "\n\n"
            else:
                report += f"{g['title']}.\n\n"

            if g["source"] != "dep":
                report += "### Affected Code\n\n"
                report += f"**File:** `{g['file']}`\n\n"
                lines = g.get("lines", [])
                if len(lines) == 1:
                    report += f"**Line:** {lines[0]}\n\n"
                elif lines:
                    report += f"**Affected lines ({len(lines)}):** {', '.join(str(l) for l in sorted(lines))}\n\n"
                snippets = g.get("code_snippets", [])
                unique_snippets = list(dict.fromkeys(snippets))[:3]
                if unique_snippets:
                    report += "```python\n"
                    for snippet in unique_snippets:
                        report += snippet + "\n"
                    report += "```\n\n"

            report += "### Impact\n\n"
            if g["source"] == "dep":
                dep = g.get("dep_info", {})
                report += f"- **Package:** {dep['package']} {dep['version']}\n"
                report += f"- **Vulnerability:** {dep['cve']}\n"
                report += f"- **Fix available:** {dep['fix_version']}\n\n"
                report += DEP_ENRICHMENT["impact"] + "\n\n"
            elif enrichment.get("impact"):
                report += enrichment["impact"] + "\n\n"
            else:
                report += f"- **Severity:** {sev}\n- **OWASP:** {g.get('owasp', 'N/A')}\n\n"

            if enrichment.get("attack_scenario"):
                report += "### Attack Scenario\n\n"
                report += enrichment["attack_scenario"] + "\n\n"

            report += "### Remediation\n\n"
            if g["source"] == "dep":
                dep = g.get("dep_info", {})
                report += DEP_ENRICHMENT["remediation_template"].format(**dep) + "\n\n"
            elif enrichment.get("remediation"):
                report += enrichment["remediation"] + "\n\n"
            else:
                report += "Review the finding and apply the recommended fix."
                if g.get("more_info"):
                    report += f" See: {g['more_info']}"
                report += "\n\n"

            report += "### References\n\n"
            if g.get("cwe_id") and g.get("cwe_link"):
                report += f"- [CWE-{g['cwe_id']}]({g['cwe_link']})\n"
            elif g.get("cwe_id"):
                report += f"- [CWE-{g['cwe_id']}](https://cwe.mitre.org/data/definitions/{g['cwe_id']}.html)\n"
            if g.get("more_info"):
                report += f"- [Bandit {g['test_id']} Documentation]({g['more_info']})\n"
            if g["source"] == "dep":
                dep = g.get("dep_info", {})
                report += f"- [NVD: {dep['cve']}](https://nvd.nist.gov/vuln/detail/{dep['cve']})\n"
            report += "\n---\n\n"

        if not grouped_findings:
            report += "## No Findings\n\nNo vulnerabilities were detected by automated scanning tools.\n\n"

        report += f"\n---\n\n**Document Version:** Auto-generated\n**Last Updated:** {now_full}\n"
        return report

    def _generate_remediation_roadmap(self, grouped_findings, dep_vulns, pytest_data) -> str:
        now = datetime.now().strftime("%B %d, %Y")
        now_full = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        phases = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for g in grouped_findings:
            sev = g["severity"]
            if sev in phases:
                phases[sev].append(g)

        total = len(grouped_findings)
        _, risk_short = calculate_posture({k: len(v) for k, v in phases.items()})
        risk_labels = {
            "CRITICAL": "⚠️ **HIGH — NOT PRODUCTION READY**",
            "HIGH": "🟠 **ELEVATED — Fix high-severity issues before production**",
            "MEDIUM": "🟡 **MODERATE — Address in development roadmap**",
            "LOW": "🟢 **LOW — Minor items only**",
            "CLEAN": "🟢 **LOW — Minor items only**",
        }
        risk = risk_labels.get(risk_short, "🟢 **LOW — Minor items only**")

        report = f"""# Security Remediation Roadmap

**Document Version:** Auto-generated
**Last Updated:** {now_full}
**Audit Date:** {now}

---

## Executive Summary

This roadmap outlines a prioritized plan to address the **{total} security finding(s)** \
identified in the security audit. The plan is structured into phases by severity:

1. **Phase 1: Critical Fixes** — Immediate action required
2. **Phase 2: High-Priority Fixes** — Before production deployment
3. **Phase 3: Medium-Priority Improvements** — Development roadmap
4. **Phase 4: Low-Priority / Informational** — Opportunistic

### Current Risk Level

{risk}

### Vulnerability Summary

| Severity | Count | Phase |
|----------|-------|-------|
| {SEVERITY_EMOJI['CRITICAL']} CRITICAL | {len(phases['CRITICAL'])} | Phase 1 — Immediate |
| {SEVERITY_EMOJI['HIGH']} HIGH | {len(phases['HIGH'])} | Phase 2 — Before production |
| {SEVERITY_EMOJI['MEDIUM']} MEDIUM | {len(phases['MEDIUM'])} | Phase 3 — Development roadmap |
| {SEVERITY_EMOJI['LOW']} LOW | {len(phases['LOW'])} | Phase 4 — Opportunistic |
| **Total** | **{total}** | |

---

"""
        phase_info = [
            ("CRITICAL", "Phase 1: Critical Fixes", "Immediate",
             "Eliminate all CRITICAL vulnerabilities. Block other work if necessary."),
            ("HIGH", "Phase 2: High-Priority Fixes", "Before production",
             "Address HIGH severity issues to improve defense in depth."),
            ("MEDIUM", "Phase 3: Medium-Priority Improvements", "Development roadmap",
             "Harden the application with medium-priority security improvements."),
            ("LOW", "Phase 4: Low-Priority / Informational", "Opportunistic",
             "Address low-severity findings as time permits or during related refactoring."),
        ]
        task_num = 0
        for sev, title, timeline, goal in phase_info:
            items = phases[sev]
            report += f"## {title}\n\n**Timeline:** {timeline}\n**Goal:** {goal}\n\n"
            if not items:
                report += "No findings at this severity level. ✅\n\n---\n\n"
                continue
            by_file = {}
            for g in items:
                by_file.setdefault(g["file"], []).append(g)
            for file_path, file_items in sorted(by_file.items()):
                task_num += 1
                report += f"### Task {task_num}: `{file_path}`\n\n"
                for g in file_items:
                    enrichment = get_enrichment(g["test_id"])
                    analytic_title = enrichment.get("analytical_title", g["title"])
                    lines = g.get("lines", [])
                    if g["source"] == "dep":
                        dep = g.get("dep_info", {})
                        report += f"**Finding:** {analytic_title}\n\n"
                        report += "**Deliverables:**\n\n"
                        report += f"- [ ] Upgrade `{dep['package']}` to version {dep['fix_version']} or later\n"
                        report += f"- [ ] Verify application works with upgraded dependency\n"
                        report += f"- [ ] Re-run `pip-audit` to confirm fix\n\n"
                        report += f"**Fix:** `pip install \"{dep['package']}>={dep['fix_version']}\"`\n\n"
                    else:
                        if len(lines) == 1:
                            loc_str = f" (line {lines[0]})"
                        elif len(lines) <= 5:
                            loc_str = f" (lines {', '.join(str(l) for l in sorted(lines))})"
                        else:
                            loc_str = f" ({len(lines)} locations)"
                        report += f"**Finding:** {analytic_title}{loc_str}\n\n"
                        cwe_str = f"CWE-{g['cwe_id']}" if g.get("cwe_id") else ""
                        if cwe_str:
                            report += f"- CWE: {cwe_str}\n"
                        if enrichment.get("remediation"):
                            first_line = enrichment["remediation"].split("\n")[0].strip()
                            if len(first_line) > 120:
                                first_line = first_line[:117] + "..."
                            report += f"- Action: {first_line}\n"
                        report += f"- See: `vulnerabilities.md` for detailed guidance\n\n"
                report += "---\n\n"

        report += """## Milestone Reviews

After completing each phase:

1. Re-run the full security audit to verify fixes
2. Confirm no new vulnerabilities were introduced
3. Review test coverage for fixed areas
4. Update this roadmap with actual completion dates

"""
        report += f"""---

## Security Test Status

| Metric | Value |
|--------|-------|
| Security tests | {pytest_data['total']} |
| Passing | {pytest_data['passed']} |
| Failing | {pytest_data['failed']} |

"""
        if pytest_data["failed"]:
            report += "### Failing Tests (must fix)\n\n"
            for f in pytest_data["failures"]:
                report += f"- [ ] `{f}`\n"
            report += "\n"
        else:
            report += "All security tests passing. ✅\n\n"

        report += """---

## Risk Management

### Potential Blockers

1. **Dependency conflicts** — Upgrading packages may cause compatibility issues
   - Mitigation: Test thoroughly after upgrades, pin compatible versions

### Rollback Plan

If fixes cause regressions:

```bash
# Revert security changes
git revert <commit-range>

# Re-run tests to verify rollback
python -m pytest tests/ -v
```

---

## Testing Strategy

### After Each Fix

```bash
# Run security tests
python -m pytest tests/ -m security -v

# Run full test suite to catch regressions
python -m pytest tests/ -v

# Re-run full audit to verify
/agent:security --full
```

### Ongoing

- Run security audit before major releases
- Keep dependencies updated monthly
- Review security test coverage when adding features

"""
        report += f"\n---\n\n**Document Version:** Auto-generated\n**Last Updated:** {now_full}\n"
        return report


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python security_reporter.py <project_root> [project_name]")
        sys.exit(1)
    project_root = sys.argv[1]
    project_name = sys.argv[2] if len(sys.argv) > 2 else None
    reporter = SecurityReporter(project_root, project_name)
    print(f"SecurityReporter initialized for: {reporter.project_name}")
    print(f"Project root: {reporter.project_root}")
```

### Step 4: Run tests to verify they pass

```bash
pytest ~/.claude/skills/agent-security/tests/test_security_reporter.py -v
```
Expected: `13 passed`

### Step 5: Run all tests together

```bash
pytest ~/.claude/skills/agent-security/tests/ -v
```
Expected: all tests pass (no failures)

### Step 6: Commit

```bash
git add ~/.claude/skills/agent-security/utils/security_reporter.py \
        ~/.claude/skills/agent-security/tests/test_security_reporter.py
git commit -m "feat: add security_reporter.py — parameterized audit and threat model reports"
```

---

## Final Step: Smoke test against PelotonRacer

Verify the extracted modules work correctly against the project they were extracted from.

### Step 1: Run CodeScanner against PelotonRacer

```bash
python ~/.claude/skills/agent-security/scanners/code_scanner.py \
    /Users/nissim/dev/PelotonRacer
```
Expected: finds SRC-INFO-LEAK and/or SRC-CRED-ENV in PelotonRacer/src/ (same findings as original script)

### Step 2: Run all tests one final time

```bash
pytest ~/.claude/skills/agent-security/tests/ -v --tb=short
```
Expected: all tests pass

### Step 3: Final commit

```bash
git add ~/.claude/skills/agent-security/
git commit -m "feat: complete agent-security extraction — 4 modules, tests, smoke-tested against PelotonRacer"
```

---

## Directory structure after completion

```
~/.claude/skills/agent-security/
├── SKILL.md
├── scanners/
│   ├── code_scanner.py         ← NEW
│   ├── config_scanner.py
│   └── dependency_scanner.py
├── threat_models/
│   ├── owasp.py
│   └── stride.py
├── utils/
│   ├── mitigation_suggester.py ← NEW
│   ├── security_reporter.py    ← NEW
│   └── severity_calculator.py  ← NEW
└── tests/
    ├── test_code_scanner.py
    ├── test_mitigation_suggester.py
    ├── test_security_reporter.py
    └── test_severity_calculator.py
```
