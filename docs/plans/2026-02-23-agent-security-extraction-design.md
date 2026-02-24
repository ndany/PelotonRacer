# Agent Security: Extraction and Parameterization Design

**Date:** 2026-02-23
**Status:** Approved
**Scope:** Extract security scanning logic from PelotonRacer scripts into generic, reusable `agent-security` skill modules

---

## Background

The `agent-security` skill was implemented in Phases 3-4 with a `SKILL.md` orchestration file and four scanning modules (`stride.py`, `owasp.py`, `config_scanner.py`, `dependency_scanner.py`). The design doc identified six additional modules as gaps:

- `scanners/code_scanner.py`
- `utils/severity_calculator.py`
- `utils/mitigation_suggester.py`
- `utils/security_reporter.py` (report generation)
- `shared/project_analyzer.py` (out of scope here)
- `shared/coordination.py` (Phase 5, out of scope here)

In parallel, PelotonRacer developed production-quality security scripts (`scripts/generate_security_reports.py`, `scripts/run_security_audit.sh`) that implement the same capabilities with project-specific hardcoding. This design extracts and parameterizes that work to fill the four gaps above.

---

## Goals

1. Fill the four missing `agent-security` modules by extracting from PelotonRacer scripts
2. Remove all project-specific hardcoding — works on any Python project
3. Preserve the behavior and quality of the PelotonRacer scripts exactly
4. Document design decisions and future enhancement paths

---

## Module Layout

```
agent-security/
├── SKILL.md                          (existing — unchanged)
├── scanners/
│   ├── config_scanner.py             (existing — unchanged)
│   ├── dependency_scanner.py         (existing — unchanged)
│   └── code_scanner.py               (NEW — from scan_source_patterns())
├── threat_models/
│   ├── stride.py                     (existing — unchanged)
│   └── owasp.py                      (existing — unchanged)
└── utils/
    ├── severity_calculator.py        (NEW — from posture logic + constants)
    ├── mitigation_suggester.py       (NEW — from FINDING_ENRICHMENT + BANDIT_OWASP_MAP)
    └── security_reporter.py          (NEW — from generate_security_reports.py, parameterized)

shared/
└── report_generator.py               (existing — unchanged, testing reports only)
```

**Note:** `security_reporter.py` lives in `agent-security/utils/` rather than `shared/` because both report modes (`"security"` and `"audit"`) are purely security tooling with no overlap with functional test reporting.

---

## Module 1: `scanners/code_scanner.py`

### What it does

Scans Python source files with regex patterns to detect security anti-patterns that static analysis tools like bandit either miss or require project-specific tuning to catch.

### Design decision: complement to bandit, not a replacement

**Decision:** The scanner ships with 3-5 patterns that cover things bandit does not — specifically patterns that require understanding of how the code uses a feature, not just that the feature is present.

**Rationale:** The `run_security_audit.sh` script already runs bandit as a separate step. Duplicating bandit's coverage in the custom scanner would produce redundant findings without adding value. The custom scanner fills the gaps.

**Current patterns (extracted from PelotonRacer):**

| ID | Pattern | Severity | What bandit misses |
|----|---------|----------|-------------------|
| `SRC-INFO-LEAK` | `except Exception.*print.*{.*}` | HIGH | Bandit flags bare `except`, not the specific case of printing exception details to users |
| `SRC-JWT-NOSIG` | `verify_signature.*False` | MEDIUM | Bandit has no JWT-specific checks |
| `SRC-CRED-ENV` | `password.*os.getenv\|PASSWORD` | MEDIUM | Bandit's B105/106/107 catch hardcoded strings, not env-var credential patterns |

**Future enhancement path:** Additional patterns can be added by appending to the `BUILTIN_PATTERNS` list — each pattern is a `ScanPattern` dataclass with `id`, `pattern`, `severity`, `title`, `cwe`, `owasp`. No changes to scanning logic required. Candidates for future additions documented in module docstring.

### Source directory detection

Rather than hardcoding `src/`, the scanner checks a priority list of common conventions: `src/`, `app/`, `lib/`, then falls back to scanning the project root directly. A `target_path` argument overrides all of this.

### Interface

```python
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

class CodeScanner:
    def __init__(self, project_root: str, extra_patterns: list[ScanPattern] = None)
    def scan(self, target_path: str = None) -> list[CodeFinding]
```

---

## Module 2: `utils/severity_calculator.py`

### What it does

Provides severity constants, severity-ordered sorting, and security posture assessment. Extracted from the constants and posture logic in `generate_security_reports.py`.

### Interface

```python
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

def calculate_posture(sev_counts: dict) -> tuple[str, str]:
    """
    Returns (posture_label, posture_short) e.g.:
    ("⚠️ NOT PRODUCTION READY — Critical vulnerabilities require immediate attention", "CRITICAL")
    ("✅ CLEAN — No issues detected", "CLEAN")
    """

def sort_by_severity(findings: list, severity_key: str = "severity") -> list:
    """Sort findings list by severity then by file."""
```

---

## Module 3: `utils/mitigation_suggester.py`

### What it does

Two responsibilities:
1. Maps raw tool findings to OWASP categories and enriches them with attack scenarios, remediation guidance, and STRIDE classification
2. Deduplicates multiple instances of the same finding type in the same file into a single grouped entry

### Finding enrichment tiers

**Tier 1 — Full enrichment:** analytical title, description, impact, attack scenario, remediation code example, STRIDE category. Written for the ~15 most commonly encountered bandit IDs and all SRC-* patterns:

`B105`, `B106`, `B107` (hardcoded passwords), `B301` (pickle), `B303` (MD5/SHA1), `B311` (non-crypto random), `B501`, `B502` (SSL), `B602`, `B603`, `B605` (subprocess/shell injection), `B506` (yaml.load), `B608` (SQL injection), `SRC-INFO-LEAK`, `SRC-JWT-NOSIG`, `SRC-CRED-ENV`

**Tier 2 — Fallback enrichment:** for any finding ID not in the full dict, builds a minimal but structured entry from `BANDIT_OWASP_MAP` (title + OWASP category). Reports are never blank.

**Design decision: static enrichment over dynamic AI generation**

**Decision:** Enrichment text is static, pre-written per finding type. Real file paths, line numbers, and code snippets from the actual scan provide project-specific context.

**Rationale:** The PelotonRacer scripts proved this model works well — the developer sees their actual code alongside generic but accurate attack/remediation text. No extra AI call per finding. Consistent quality across runs. The "context" comes from showing real snippets, not from generating custom prose.

**Future enhancement path:** Full enrichment entries can be added for any bandit ID. The tier-2 fallback means the system degrades gracefully until enrichment is written. A future enhancement could auto-generate tier-1 enrichment using Claude for finding IDs not yet in the dict, caching the result.

### Key data structures

```python
BANDIT_OWASP_MAP: dict[str, tuple[str, str]]
# Maps bandit test ID → (owasp_category, description)
# 50+ entries, extracted as-is from PelotonRacer scripts

FINDING_ENRICHMENT: dict[str, dict]
# Maps finding ID → {analytical_title, description, impact,
#                    attack_scenario, remediation, stride, risk_note}
# Impact text rewritten to be project-neutral

DEP_ENRICHMENT: dict
# Generic templates for dependency vulnerability entries
# Extracted as-is — already fully generic in PelotonRacer

def group_findings(bandit_data, dep_vulns, source_findings) -> list[dict]:
    # Deduplicates by (test_id, file), collects all line numbers
    # Returns sorted list ready for report generation
```

---

## Module 4: `utils/security_reporter.py`

### What it does

Generates security reports in two modes. Extracted and parameterized from `generate_security_reports.py` and the `shared/report_generator.py` stub.

### Two modes, two methods

The input structures differ enough that separate methods are cleaner than a single `generate(report_type=...)` call:

```python
class SecurityReporter:
    def __init__(self, project_root: str, project_name: str = None):
        # project_name: auto-detected from Path(project_root).name if not provided

    def generate_threat_model(self, data: dict) -> tuple[Path, Path]:
        """
        STRIDE/OWASP threat model report.
        Input:  structured threat data (threats list, attack_surface, dependencies)
        Output: docs/security/YYYY-MM-DD-threat-model.{json,md}
        Source: migrated from shared/report_generator.py _generate_security_markdown()
        """

    def generate_audit(self, audit_dir: Path, bandit_data: dict, pytest_data: dict,
                       dep_vulns: list, secrets_data: dict,
                       source_findings: list) -> list[Path]:
        """
        Full tool-based audit — three reports.
        Input:  raw outputs from bandit, pytest, pip-audit, detect-secrets, code_scanner
        Output: audit_dir/{audit-report.md, vulnerabilities.md, remediation-roadmap.md}
        Source: migrated from generate_security_reports.py
        """
```

### Parameterization changes from PelotonRacer

| Hardcoded in original | Generic replacement |
|---|---|
| `"PelotonRacer"` (10+ occurrences) | `self.project_name` |
| `src/` in bandit coverage flag | Derived from discovered source directories |
| `./scripts/run_security_audit.sh --report` in footers | `"Re-run: /agent:security --full"` |
| Risk blockers: "Peloton may change authentication" | Section removed from roadmap template |
| `docs/security/audits/` output path | `project_root / "docs" / "security" / "audits"` |

### What is unchanged

The full report generation logic — `generate_audit_report()`, `generate_vulnerabilities_report()`, `generate_remediation_roadmap()` — is preserved exactly. The PelotonRacer scripts got the structure, deduplication, STRIDE table, OWASP mapping, and remediation roadmap right. Only string substitutions and constructor wiring change.

---

## Report outputs summary

| Mode | Method | Output files |
|------|--------|-------------|
| `threat_model` | `generate_threat_model()` | `docs/security/YYYY-MM-DD-threat-model.json` + `.md` |
| `audit` | `generate_audit()` | `docs/security/audits/YYYY-MM-DD_HHMM/audit-report.md` |
| | | `docs/security/audits/YYYY-MM-DD_HHMM/vulnerabilities.md` |
| | | `docs/security/audits/YYYY-MM-DD_HHMM/remediation-roadmap.md` |

---

## What is out of scope

- `shared/project_analyzer.py` — language/framework detection for multi-language support (Phase 6)
- `shared/coordination.py` — security agent → test agent communication (Phase 5)
- Pattern expansion beyond complement-to-bandit scope (documented as future enhancement in `code_scanner.py`)
- User-extensible custom patterns (documented as future enhancement in `code_scanner.py`)
- Auto-generation of missing `FINDING_ENRICHMENT` entries via Claude (documented as future enhancement in `mitigation_suggester.py`)

---

## Implementation notes

- All modules are standalone Python files runnable as `__main__` for testing, consistent with existing skill modules
- `security_reporter.py` depends on `severity_calculator.py` and `mitigation_suggester.py`; all other modules are independent
- `shared/report_generator.py` is unchanged — it continues to serve `agent-test` for testing reports
- The `run_security_audit.sh` orchestration pattern (run tools, gracefully skip if not installed) is already described in `SKILL.md` and does not need a new module
