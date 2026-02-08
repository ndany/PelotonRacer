#!/usr/bin/env python3
"""
Security Report Generator for PelotonRacer

Generates comprehensive, analytical security audit reports from tool outputs
(bandit, pip-audit, pytest, detect-secrets) and source code analysis.

Findings are grouped and deduplicated so each logical vulnerability appears
once with all affected locations, attack scenarios, and remediation guidance.

Produces three reports:
  - audit-report.md:        Executive summary, key findings, STRIDE & OWASP, recommendations
  - vulnerabilities.md:     Detailed per-finding docs with attack scenarios, PoC, remediation
  - remediation-roadmap.md: Phased plan with timelines, resources, acceptance criteria

Usage:
  python scripts/generate_security_reports.py <audit_dir>

Called automatically by: ./scripts/run_security_audit.sh --report
"""

import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path


# =============================================================================
# Data Collection
# =============================================================================

def load_bandit_results(audit_dir: Path) -> dict:
    """Load and parse bandit JSON results."""
    path = audit_dir / "bandit-results.json"
    if not path.exists():
        return {"results": [], "metrics": {"_totals": {}}}
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, KeyError):
        return {"results": [], "metrics": {"_totals": {}}}


def load_pytest_results(audit_dir: Path) -> dict:
    """Parse pytest output for test counts and details."""
    path = audit_dir / "pytest-security-results.txt"
    if not path.exists():
        return {"passed": 0, "failed": 0, "total": 0, "test_names": [], "failures": []}

    text = path.read_text()
    passed = int(m.group(1)) if (m := re.search(r"(\d+) passed", text)) else 0
    failed = int(m.group(1)) if (m := re.search(r"(\d+) failed", text)) else 0

    test_names = re.findall(r"(tests/\S+::\S+)\s+PASSED", text)
    failures = re.findall(r"(tests/\S+::\S+)\s+FAILED", text)

    return {
        "passed": passed,
        "failed": failed,
        "total": passed + failed,
        "test_names": test_names,
        "failures": failures,
    }


def load_dependency_audit(audit_dir: Path) -> list[dict]:
    """Parse pip-audit output for vulnerable dependencies."""
    path = audit_dir / "dependency-audit.txt"
    if not path.exists():
        return []

    text = path.read_text()
    if "not installed" in text.lower() or "No known vulnerabilities" in text:
        return []

    vulns = []
    for line in text.strip().splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 4 and parts[2].startswith("CVE-"):
            vulns.append({
                "package": parts[0],
                "version": parts[1],
                "cve": parts[2],
                "fix_version": parts[3],
                "description": parts[4] if len(parts) > 4 else "",
            })
    return vulns


def load_secrets_scan(audit_dir: Path) -> dict:
    """Parse detect-secrets scan results."""
    path = audit_dir / "secrets-scan.json"
    if not path.exists():
        return {"results": {}}
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, KeyError):
        return {"results": {}}


def scan_source_patterns(project_root: Path) -> list[dict]:
    """Scan source code for common security anti-patterns."""
    findings = []
    src_dir = project_root / "src"
    if not src_dir.exists():
        return findings

    patterns = [
        {
            "pattern": r"except\s+Exception\s+as\s+\w+.*?print\(.*?\{.*?\}",
            "id": "SRC-INFO-LEAK",
            "title": "Exception details in user-facing output",
            "severity": "HIGH",
            "cwe": "CWE-209",
            "owasp": "A05:2021 - Security Misconfiguration",
        },
        {
            "pattern": r"verify_signature.*?False",
            "id": "SRC-JWT-NOSIG",
            "title": "JWT signature verification disabled",
            "severity": "MEDIUM",
            "cwe": "CWE-347",
            "owasp": "A07:2021 - Authentication Failures",
        },
        {
            "pattern": r"password.*?=.*?os\.getenv|\.env.*?password|PASSWORD",
            "id": "SRC-CRED-ENV",
            "title": "Credentials in environment variables",
            "severity": "MEDIUM",
            "cwe": "CWE-312",
            "owasp": "A02:2021 - Cryptographic Failures",
        },
    ]

    for py_file in src_dir.rglob("*.py"):
        try:
            content = py_file.read_text()
        except Exception:
            continue
        rel_path = py_file.relative_to(project_root)
        for pat in patterns:
            for match in re.finditer(pat["pattern"], content, re.DOTALL):
                line_num = content[:match.start()].count("\n") + 1
                findings.append({
                    "id": pat["id"],
                    "title": pat["title"],
                    "severity": pat["severity"],
                    "cwe": pat["cwe"],
                    "owasp": pat["owasp"],
                    "file": str(rel_path),
                    "line": line_num,
                    "code_snippet": content.splitlines()[line_num - 1].strip() if line_num <= len(content.splitlines()) else "",
                })
    return findings


def get_git_info() -> dict:
    """Get current git branch and commit."""
    try:
        branch = subprocess.check_output(
            ["git", "branch", "--show-current"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        branch = "unknown"
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        commit = "unknown"
    return {"branch": branch, "commit": commit}


# =============================================================================
# Finding Grouping & Deduplication
# =============================================================================

def group_findings(bandit_data, dep_vulns, source_findings):
    """
    Group raw findings into logical vulnerabilities.

    Instead of 20 identical random.randint() entries, produces one finding
    with a list of affected locations. Returns a list of grouped findings
    sorted by severity.
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

    # Convert groups dict to list
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

    # Sort by severity then file
    grouped.sort(key=lambda g: (SEVERITY_ORDER.get(g["severity"], 9), g["file"]))
    return grouped


# =============================================================================
# Finding Enrichment — Rich content per finding type
# =============================================================================

FINDING_ENRICHMENT = {
    "B311": {
        "analytical_title": "Non-Cryptographic Random Number Generator",
        "description": (
            "The application uses Python's `random` module (e.g., `random.randint()`, "
            "`random.choice()`, `random.uniform()`) which produces predictable pseudo-random "
            "numbers. These generators are not suitable for security-sensitive operations such as "
            "token generation, password creation, or cryptographic key derivation."
        ),
        "impact": (
            "In this codebase, these calls occur in **mock data generation** (`mock_data.py`), "
            "which is used only for development/testing. The actual security risk is **minimal** "
            "since mock data does not protect real user accounts or sessions. However, if these "
            "patterns were copied into production authentication or session management code, "
            "they would enable prediction attacks."
        ),
        "attack_scenario": (
            "If `random` were used for security tokens:\n"
            "1. Attacker observes several generated tokens\n"
            "2. Seeds the Mersenne Twister with observed values\n"
            "3. Predicts future tokens with high accuracy\n"
            "4. Gains unauthorized access using predicted tokens"
        ),
        "remediation": (
            "For mock/test data generation, `random` is acceptable and no change is required. "
            "If any security-sensitive code uses `random`, replace with:\n\n"
            "```python\nimport secrets\n\n"
            "# Instead of: random.randint(0, 999999)\n"
            "token = secrets.randbelow(1000000)\n\n"
            "# Instead of: random.choice(items)\n"
            "item = secrets.choice(items)\n```\n\n"
            "**Recommendation:** Add a bandit suppression comment (`# nosec B311`) to mock_data.py "
            "to acknowledge this is intentional, or exclude the file from bandit scanning."
        ),
        "stride": "Spoofing",
        "risk_note": "Informational — current usage is in test data only",
    },
    "SRC-INFO-LEAK": {
        "analytical_title": "Sensitive Exception Information Disclosure",
        "description": (
            "The application exposes detailed error messages, stack traces, and potentially "
            "sensitive internal information in exception handlers. When exceptions occur, "
            "the full exception message (which may contain file paths, database details, "
            "API responses, or credential fragments) is printed to the user-facing output."
        ),
        "impact": (
            "- Exposes internal file paths (`/Users/.../PelotonRacer/src/...`)\n"
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
            "# \"Error: ConnectionError: Failed to connect to api.onepeloton.com:443\n"
            "#  File '/Users/dev/PelotonRacer/src/api/peloton_client.py', line 183\n"
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
            "    raise PelotonClientError(\"Unable to complete request. Please try again.\")\n"
            "```"
        ),
        "stride": "Information Disclosure",
        "risk_note": "Leaks internal application details that aid attackers",
    },
    "SRC-JWT-NOSIG": {
        "analytical_title": "JWT Signature Verification Disabled",
        "description": (
            "JWT signature verification is explicitly disabled (`verify_signature: False`). "
            "While the application implements other validation checks (expiration, required claims, "
            "API-side verification), disabling signature verification means the application cannot "
            "locally detect forged or tampered tokens."
        ),
        "impact": (
            "- Cannot locally detect forged JWT tokens\n"
            "- Relies entirely on Peloton API for token validation\n"
            "- If API validation is bypassed or cached, forged tokens succeed\n"
            "- Reduced defense-in-depth for authentication"
        ),
        "attack_scenario": (
            "1. Attacker crafts a JWT with `{\"alg\": \"none\"}` and arbitrary claims\n"
            "2. Application accepts token without checking signature\n"
            "3. Other validation (expiration, claims) still applies\n"
            "4. Token is sent to Peloton API, which may or may not reject it\n\n"
            "**Note:** This is partially mitigated by the existing expiration checks "
            "and API-side validation, but signature verification would add another "
            "layer of defense."
        ),
        "remediation": (
            "If Peloton publishes a JWKS endpoint, enable signature verification:\n\n"
            "```python\n"
            "options = {\n"
            "    \"verify_signature\": True,  # Enable when key is available\n"
            "    \"verify_exp\": True,\n"
            "    \"require\": [\"exp\", \"user_id\"],\n"
            "}\n"
            "```\n\n"
            "If no public key is available (common with third-party APIs), document this "
            "as an accepted risk and ensure compensating controls (expiration, API verification) "
            "remain in place."
        ),
        "stride": "Spoofing",
        "risk_note": "Partially mitigated by expiration checks and API-side validation",
    },
    "SRC-CRED-ENV": {
        "analytical_title": "Plaintext Credential Storage in Environment Variables",
        "description": (
            "The application reads authentication credentials from environment variables "
            "loaded from `.env` files. While `.env` is git-ignored, the credentials are "
            "stored in plaintext on the filesystem, accessible to any process running as "
            "the same user."
        ),
        "impact": (
            "- Credentials stored in plaintext on filesystem\n"
            "- Accessible to any process running as the same OS user\n"
            "- Risk of accidental inclusion in backups, logs, or version control\n"
            "- No credential rotation mechanism"
        ),
        "attack_scenario": (
            "1. Attacker gains filesystem access (malware, shared system, backup exposure)\n"
            "2. Reads `.env` file containing `PELOTON_BEARER_TOKEN=...`\n"
            "3. Uses stolen token to access victim's Peloton account\n"
            "4. No audit trail of credential theft"
        ),
        "remediation": (
            "For a local-only application, environment variables are a reasonable approach. "
            "To improve security:\n\n"
            "1. **Set restrictive permissions:** `chmod 600 .env`\n"
            "2. **Use OS keyring** for sensitive values (macOS Keychain, Windows Credential Manager)\n"
            "3. **Rotate credentials** regularly\n"
            "4. **Pre-commit hooks** to prevent `.env` from being committed\n\n"
            "```python\n"
            "import keyring\n"
            "token = keyring.get_password(\"PelotonRacer\", \"bearer_token\")\n"
            "```"
        ),
        "stride": "Information Disclosure",
        "risk_note": "Standard pattern for local apps; consider OS keyring for improvement",
    },
}

# Enrichment for dependency vulnerabilities (generic)
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


# =============================================================================
# OWASP / CWE Enrichment
# =============================================================================

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

SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


# =============================================================================
# Report: audit-report.md
# =============================================================================

def generate_audit_report(audit_dir, grouped_findings, pytest_data, dep_vulns,
                          secrets_data, git_info, bandit_data):
    """Generate the main audit-report.md with analytical content."""
    now = datetime.now().strftime("%B %d, %Y")
    now_full = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    totals = bandit_data.get("metrics", {}).get("_totals", {})
    lines_scanned = totals.get("loc", 0)
    secrets_count = sum(len(v) for v in secrets_data.get("results", {}).values())

    # Count by severity (using grouped findings — deduplicated)
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for g in grouped_findings:
        sev = g["severity"]
        if sev in sev_counts:
            sev_counts[sev] += 1
    total_findings = sum(sev_counts.values())

    # Security posture
    if sev_counts["CRITICAL"] > 0:
        posture = "⚠️ **NOT PRODUCTION READY** — Critical vulnerabilities require immediate attention"
        posture_short = "CRITICAL"
    elif sev_counts["HIGH"] > 0:
        posture = "🟠 **HIGH-SEVERITY ISSUES FOUND** — Fix before production deployment"
        posture_short = "HIGH"
    elif sev_counts["MEDIUM"] > 0:
        posture = "🟡 **MODERATE RISK** — Address in development roadmap"
        posture_short = "MEDIUM"
    elif total_findings > 0:
        posture = "🟢 **LOW RISK** — Minor informational issues only"
        posture_short = "LOW"
    else:
        posture = "✅ **CLEAN** — No issues detected"
        posture_short = "CLEAN"

    # Build key findings summary (named, not raw tool output)
    key_findings_by_sev = {"CRITICAL": [], "HIGH": [], "MEDIUM": []}
    for g in grouped_findings:
        sev = g["severity"]
        if sev not in key_findings_by_sev:
            continue
        enrichment = FINDING_ENRICHMENT.get(g["test_id"], {})
        title = enrichment.get("analytical_title", g["title"])
        locations = len(g["lines"])
        loc_note = f" ({locations} locations)" if locations > 1 else ""
        file_note = f" in `{g['file']}`" if g.get("file") else ""
        key_findings_by_sev[sev].append(f"**{title}**{loc_note}{file_note}")

    # STRIDE threat summary
    stride_summary = {}
    for g in grouped_findings:
        enrichment = FINDING_ENRICHMENT.get(g["test_id"], {})
        stride_cat = enrichment.get("stride")
        if not stride_cat:
            # Infer from CWE
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

    # OWASP mapping
    owasp_summary = {}
    for g in grouped_findings:
        cat = g.get("owasp", "Uncategorized")
        if cat and cat != "Uncategorized":
            owasp_summary.setdefault(cat, []).append(g)

    # Test files
    test_files = {}
    for t in pytest_data["test_names"]:
        parts = t.split("::")
        fname = parts[0] if parts else t
        test_files.setdefault(fname, []).append(parts[-1] if len(parts) > 1 else t)

    # --- Build report ---
    report = f"""# Security Audit Report — PelotonRacer

**Audit Date:** {now}
**Generated:** {now_full}
**Auditor:** Automated Security Analysis (bandit, pip-audit, detect-secrets, pytest)
**Application:** PelotonRacer
**Branch:** {git_info['branch']}
**Commit:** {git_info['commit']}
**Scope:** Full application security assessment

---

## Executive Summary

This security audit of PelotonRacer scanned **{lines_scanned:,} lines** of source code \
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

    # Key Findings narrative
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

    # Posture-specific narrative
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

1. **STRIDE Threat Modeling**
   Findings are classified by threat type: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.

2. **OWASP Top 10 (2021)**
   Findings are mapped to the OWASP Top 10 categories to assess coverage of the most critical web application security risks.

3. **CWE (Common Weakness Enumeration)**
   Each finding references its CWE identifier for standardized vulnerability classification.

### Tools Used

| Tool | Purpose | Findings |
|------|---------|----------|
| **bandit** | Static security analysis of Python source | {len(bandit_data.get('results', []))} raw ({_count_grouped(grouped_findings, 'bandit')} grouped) |
| **pip-audit** | Dependency vulnerability scanning (CVE database) | {len(dep_vulns)} |
| **detect-secrets** | Secrets/credential leak detection | {secrets_count} |
| **pytest -m security** | Security-specific test suite | {pytest_data['passed']} passed, {pytest_data['failed']} failed |
| **Source pattern scan** | Custom regex for security anti-patterns | {_count_grouped(grouped_findings, 'source-scan')} |

---

## Detailed Findings

"""

    # List each grouped finding concisely
    finding_num = 0
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        sev_findings = [g for g in grouped_findings if g["severity"] == sev]
        if not sev_findings:
            continue
        report += f"### {SEVERITY_EMOJI[sev]} {sev} ({len(sev_findings)})\n\n"
        for g in sev_findings:
            finding_num += 1
            enrichment = FINDING_ENRICHMENT.get(g["test_id"], {})
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
                report += "\n"
                report += f"   - CWE: {cwe_str}\n"
                report += f"   - OWASP: {g.get('owasp', 'N/A')}\n"
            if risk_note:
                report += f"   - Note: {risk_note}\n"
            report += "\n"

    # Dependency vulnerabilities table
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

    # --- STRIDE Threat Analysis ---
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
            for i, g in enumerate(items, 1):
                stride_id_counter.setdefault(prefix, 0)
                stride_id_counter[prefix] += 1
                sid = f"{prefix}-{stride_id_counter[prefix]:03d}"
                enrichment = FINDING_ENRICHMENT.get(g["test_id"], {})
                title = enrichment.get("analytical_title", g["title"])
                report += f"| {sid} | {title} | {g['severity']} | Open |\n"
            report += "\n"
        else:
            report += "No findings in this category.\n\n"
        report += "---\n\n"

    # --- OWASP Top 10 ---
    report += "## OWASP Top 10 Mapping\n\n"
    report += "| OWASP Category | Findings | Severity Range |\n"
    report += "|----------------|----------|----------------|\n"
    for cat in sorted(owasp_summary.keys()):
        items = owasp_summary[cat]
        sevs = sorted(set(g["severity"] for g in items), key=lambda s: SEVERITY_ORDER.get(s, 9))
        sev_str = "/".join(sevs)
        # Show finding names not counts
        names = []
        for g in items:
            e = FINDING_ENRICHMENT.get(g["test_id"], {})
            names.append(e.get("analytical_title", g["title"]))
        names_str = ", ".join(dict.fromkeys(names))  # deduplicate
        report += f"| {cat} | {names_str} | {sev_str} |\n"
    if not owasp_summary:
        report += "| No findings mapped | — | — |\n"
    report += f"\n**Coverage:** {len(owasp_summary)} OWASP categories with findings\n\n"

    # --- Security Test Coverage ---
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

    if pytest_data["failures"]:
        report += "### Failed Tests\n\n"
        for f in pytest_data["failures"]:
            report += f"- `{f}`\n"
        report += "\n"

    # --- Recommendations ---
    report += "---\n\n## Recommendations\n\n"
    report += "### Immediate Actions\n\n"
    action_num = 0
    for g in grouped_findings:
        if g["severity"] in ("CRITICAL", "HIGH") and g["source"] != "dep":
            action_num += 1
            enrichment = FINDING_ENRICHMENT.get(g["test_id"], {})
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
            enrichment = FINDING_ENRICHMENT.get(g["test_id"], {})
            title = enrichment.get("analytical_title", g["title"])
            report += f"{i}. **{title}** — `{g['file']}`\n"
        report += "\n"

    report += """### Ongoing Security Practices

- Run security audit before major releases (`./scripts/run_security_audit.sh --report`)
- Keep dependencies updated (`pip-audit` monthly)
- Review security test coverage when adding new features
- Conduct periodic manual security review

"""

    # --- Footer ---
    report += f"""---

## How to Re-run This Audit

```bash
# Quick security test run
./scripts/run_security_audit.sh

# Full audit with report generation
./scripts/run_security_audit.sh --report
```

---

**Document Version:** Auto-generated
**Last Updated:** {now_full}
**Next Review:** After remediation of {sev_counts.get('CRITICAL', 0) + sev_counts.get('HIGH', 0)} critical/high findings
"""
    return report


def _count_grouped(grouped_findings, source):
    return sum(1 for g in grouped_findings if g["source"] == source)


# =============================================================================
# Report: vulnerabilities.md
# =============================================================================

def generate_vulnerabilities_report(grouped_findings, dep_vulns):
    """Generate vulnerabilities.md with rich per-finding documentation."""
    now = datetime.now().strftime("%B %d, %Y")
    now_full = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = f"""# Security Vulnerabilities — Detailed Documentation

This document provides in-depth technical details, attack scenarios, and remediation \
guidance for each security vulnerability identified in the PelotonRacer security audit.

**Audit Date:** {now}
**Document Version:** Auto-generated
**Total Findings:** {len(grouped_findings)} (deduplicated)

---

## Table of Contents

"""
    # Build TOC
    for i, g in enumerate(grouped_findings, 1):
        enrichment = FINDING_ENRICHMENT.get(g["test_id"], {})
        title = enrichment.get("analytical_title", g["title"])
        sev = g["severity"]
        anchor = re.sub(r"[^a-z0-9-]", "", title.lower().replace(" ", "-"))
        report += f"- [{SEVERITY_EMOJI.get(sev, '')} {sev}-{i:03d}: {title}](#{sev.lower()}-{i:03d}-{anchor})\n"

    report += "\n---\n\n"

    # Detailed findings
    for i, g in enumerate(grouped_findings, 1):
        sev = g["severity"]
        emoji = SEVERITY_EMOJI.get(sev, "")
        enrichment = FINDING_ENRICHMENT.get(g["test_id"], {})
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

        # Description
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

        # Affected Code (with grouped locations)
        if g["source"] != "dep":
            report += "### Affected Code\n\n"
            report += f"**File:** `{g['file']}`\n\n"
            lines = g.get("lines", [])
            if len(lines) == 1:
                report += f"**Line:** {lines[0]}\n\n"
            elif lines:
                report += f"**Affected lines ({len(lines)}):** {', '.join(str(l) for l in sorted(lines))}\n\n"

            # Show a representative code snippet (first unique one, up to 3)
            snippets = g.get("code_snippets", [])
            unique_snippets = list(dict.fromkeys(snippets))[:3]
            if unique_snippets:
                report += "```python\n"
                for snippet in unique_snippets:
                    report += snippet + "\n"
                report += "```\n\n"

        # Impact
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
            report += f"- **Severity:** {sev}\n"
            report += f"- **OWASP:** {g.get('owasp', 'N/A')}\n\n"

        # Attack Scenario (if enrichment available)
        if enrichment.get("attack_scenario"):
            report += "### Attack Scenario\n\n"
            report += enrichment["attack_scenario"] + "\n\n"

        # Remediation
        report += "### Remediation\n\n"
        if g["source"] == "dep":
            dep = g.get("dep_info", {})
            report += DEP_ENRICHMENT["remediation_template"].format(**dep) + "\n\n"
        elif enrichment.get("remediation"):
            report += enrichment["remediation"] + "\n\n"
        else:
            report += f"Review the finding and apply the recommended fix."
            if g.get("more_info"):
                report += f" See: {g['more_info']}"
            report += "\n\n"

        # References
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

    report += f"""---

**Document Version:** Auto-generated
**Last Updated:** {now_full}
"""
    return report


# =============================================================================
# Report: remediation-roadmap.md
# =============================================================================

def generate_remediation_roadmap(grouped_findings, dep_vulns, pytest_data):
    """Generate remediation-roadmap.md with phased plan."""
    now = datetime.now().strftime("%B %d, %Y")
    now_full = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Categorize by severity
    phases = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for g in grouped_findings:
        sev = g["severity"]
        if sev in phases:
            phases[sev].append(g)

    total = len(grouped_findings)

    # Risk level
    if phases["CRITICAL"]:
        risk = "⚠️ **HIGH — NOT PRODUCTION READY**"
    elif phases["HIGH"]:
        risk = "🟠 **ELEVATED — Fix high-severity issues before production**"
    elif phases["MEDIUM"]:
        risk = "🟡 **MODERATE — Address in development roadmap**"
    else:
        risk = "🟢 **LOW — Minor items only**"

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
        report += f"## {title}\n\n"
        report += f"**Timeline:** {timeline}\n"
        report += f"**Goal:** {goal}\n\n"

        if not items:
            report += "No findings at this severity level. ✅\n\n---\n\n"
            continue

        # Group by file
        by_file = {}
        for g in items:
            by_file.setdefault(g["file"], []).append(g)

        for file_path, file_items in sorted(by_file.items()):
            task_num += 1
            report += f"### Task {task_num}: `{file_path}`\n\n"

            for g in file_items:
                enrichment = FINDING_ENRICHMENT.get(g["test_id"], {})
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
                    loc_str = ""
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

                    # Remediation summary
                    if enrichment.get("remediation"):
                        # Extract first sentence or line of remediation
                        first_line = enrichment["remediation"].split("\n")[0].strip()
                        if len(first_line) > 120:
                            first_line = first_line[:117] + "..."
                        report += f"- Action: {first_line}\n"
                    report += f"- See: `vulnerabilities.md` for detailed guidance\n\n"

            report += "---\n\n"

    # Milestone review
    report += """## Milestone Reviews

After completing each phase:

1. Re-run the full security audit to verify fixes
2. Confirm no new vulnerabilities were introduced
3. Review test coverage for fixed areas
4. Update this roadmap with actual completion dates

"""

    # Security test status
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

    # Risk management
    report += """---

## Risk Management

### Potential Blockers

1. **Third-party API changes** — Peloton may change their authentication system
   - Mitigation: Abstract auth logic, maintain compatibility layer

2. **Dependency conflicts** — Upgrading packages may cause compatibility issues
   - Mitigation: Test thoroughly after upgrades, pin compatible versions

### Rollback Plan

If fixes cause regressions:

```bash
# Revert security changes
git revert <commit-range>

# Re-run tests to verify rollback
python -m pytest tests/ -v
```

"""

    # Testing strategy
    report += """---

## Testing Strategy

### After Each Fix

```bash
# Run security tests
python -m pytest tests/ -m security -v

# Run full test suite to catch regressions
python -m pytest tests/ -v

# Re-run full audit to verify
./scripts/run_security_audit.sh --report
```

### Ongoing

- Run security audit before major releases
- Keep dependencies updated monthly
- Review security test coverage when adding features

"""

    report += f"""---

**Document Version:** Auto-generated
**Last Updated:** {now_full}
"""
    return report


# =============================================================================
# Main
# =============================================================================

def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/generate_security_reports.py <audit_dir>")
        sys.exit(1)

    audit_dir = Path(sys.argv[1])
    if not audit_dir.exists():
        print(f"Error: {audit_dir} does not exist")
        sys.exit(1)

    project_root = Path.cwd()
    git_info = get_git_info()

    print("Loading tool results...")
    bandit_data = load_bandit_results(audit_dir)
    pytest_data = load_pytest_results(audit_dir)
    dep_vulns = load_dependency_audit(audit_dir)
    secrets_data = load_secrets_scan(audit_dir)

    print("Scanning source code for security patterns...")
    source_findings = scan_source_patterns(project_root)

    print("Grouping and deduplicating findings...")
    grouped = group_findings(bandit_data, dep_vulns, source_findings)
    print(f"  {len(bandit_data.get('results', []))} raw bandit findings -> {_count_grouped(grouped, 'bandit')} grouped")
    print(f"  {len(source_findings)} source pattern findings -> {_count_grouped(grouped, 'source-scan')} grouped")
    print(f"  {len(dep_vulns)} dependency vulnerabilities")
    print(f"  {len(grouped)} total unique findings")

    print("Generating audit-report.md...")
    audit_report = generate_audit_report(
        audit_dir, grouped, pytest_data, dep_vulns, secrets_data, git_info, bandit_data
    )
    (audit_dir / "audit-report.md").write_text(audit_report)

    print("Generating vulnerabilities.md...")
    vuln_report = generate_vulnerabilities_report(grouped, dep_vulns)
    (audit_dir / "vulnerabilities.md").write_text(vuln_report)

    print("Generating remediation-roadmap.md...")
    roadmap = generate_remediation_roadmap(grouped, dep_vulns, pytest_data)
    (audit_dir / "remediation-roadmap.md").write_text(roadmap)

    print(f"\nReports generated in {audit_dir}/:")
    print(f"  - audit-report.md")
    print(f"  - vulnerabilities.md")
    print(f"  - remediation-roadmap.md")
    print(f"  Total unique findings: {len(grouped)}")


if __name__ == "__main__":
    main()
