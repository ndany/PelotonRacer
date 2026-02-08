#!/bin/bash
# Security Audit Script for PelotonRacer
#
# Runs security tests and optionally generates a full audit report
# with results saved to a timestamped folder under docs/security/audits/.
#
# Usage:
#   ./scripts/run_security_audit.sh                # Run security tests only
#   ./scripts/run_security_audit.sh --report       # Run tests + generate audit report
#   ./scripts/run_security_audit.sh --report -v    # Verbose + report
#   ./scripts/run_security_audit.sh --cov          # With coverage
#
# Reports are saved to: docs/security/audits/YYYY-MM-DD_HHMM/

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

# Project root (script can be invoked from anywhere)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Parse arguments
VERBOSE="-v"
GENERATE_REPORT=false
EXTRA_ARGS=""
for arg in "$@"; do
    case $arg in
        --report)
            GENERATE_REPORT=true
            ;;
        -v|--verbose)
            VERBOSE="-vv"
            ;;
        --cov|--coverage)
            EXTRA_ARGS="$EXTRA_ARGS --cov=src --cov-report=term-missing"
            ;;
        *)
            EXTRA_ARGS="$EXTRA_ARGS $arg"
            ;;
    esac
done

# ==============================================================================
# Setup report directory (if --report)
# ==============================================================================

if $GENERATE_REPORT; then
    TIMESTAMP=$(date +"%Y-%m-%d_%H%M")
    AUDIT_DIR="docs/security/audits/${TIMESTAMP}"
    mkdir -p "$AUDIT_DIR"
    echo -e "${BOLD}==================================="
    echo "PelotonRacer Security Audit Report"
    echo "==================================${NC}"
    echo ""
    echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Output:    ${AUDIT_DIR}/"
    echo ""
else
    echo "==================================="
    echo "PelotonRacer Security Audit"
    echo "==================================="
    echo ""
fi

# ==============================================================================
# 1. Security Tests (pytest -m security)
# ==============================================================================

echo -e "${BOLD}[1/4] Running security tests...${NC}"
echo ""

TESTS_PASSED=true
if $GENERATE_REPORT; then
    # Run tests and capture output for report
    set +e
    python -m pytest tests/ -m security $VERBOSE --tb=short $EXTRA_ARGS 2>&1 | tee "${AUDIT_DIR}/pytest-security-results.txt"
    PYTEST_EXIT=${PIPESTATUS[0]}
    set -e

    if [ $PYTEST_EXIT -ne 0 ]; then
        TESTS_PASSED=false
    fi
else
    # Run tests directly (original behavior)
    if ! python -m pytest tests/ -m security $VERBOSE --tb=short $EXTRA_ARGS; then
        echo ""
        echo -e "${RED}==================================${NC}"
        echo -e "${RED}Security audit FAILED${NC}"
        echo -e "${RED}==================================${NC}"
        echo ""
        echo "Review the failures above and fix before merging."
        exit 1
    fi
    echo ""
    echo -e "${GREEN}==================================${NC}"
    echo -e "${GREEN}Security audit PASSED${NC}"
    echo -e "${GREEN}==================================${NC}"
    exit 0
fi

# ==============================================================================
# The rest only runs in --report mode
# ==============================================================================

# ==============================================================================
# 2. Bandit - Static security analysis
# ==============================================================================

echo ""
echo -e "${BOLD}[2/4] Running bandit static analysis...${NC}"

BANDIT_AVAILABLE=true
if command -v bandit &> /dev/null; then
    set +e
    bandit -r src/ -ll -f json -o "${AUDIT_DIR}/bandit-results.json" 2>/dev/null
    BANDIT_EXIT=$?
    bandit -r src/ -ll 2>&1 | tee "${AUDIT_DIR}/bandit-results.txt"
    set -e
    echo -e "${GREEN}  bandit results saved${NC}"
else
    BANDIT_AVAILABLE=false
    echo -e "${YELLOW}  bandit not installed (pip install bandit) - skipping${NC}"
    echo "bandit not installed - skipping" > "${AUDIT_DIR}/bandit-results.txt"
fi

# ==============================================================================
# 3. pip-audit - Dependency vulnerability check
# ==============================================================================

echo ""
echo -e "${BOLD}[3/4] Running dependency vulnerability check...${NC}"

PIPAUDIT_AVAILABLE=true
if command -v pip-audit &> /dev/null; then
    set +e
    pip-audit --desc 2>&1 | tee "${AUDIT_DIR}/dependency-audit.txt"
    set -e
    echo -e "${GREEN}  pip-audit results saved${NC}"
elif command -v safety &> /dev/null; then
    set +e
    safety check 2>&1 | tee "${AUDIT_DIR}/dependency-audit.txt"
    set -e
    echo -e "${GREEN}  safety results saved${NC}"
else
    PIPAUDIT_AVAILABLE=false
    echo -e "${YELLOW}  pip-audit/safety not installed - skipping${NC}"
    echo "pip-audit and safety not installed - skipping" > "${AUDIT_DIR}/dependency-audit.txt"
fi

# ==============================================================================
# 4. detect-secrets - Secrets scanning
# ==============================================================================

echo ""
echo -e "${BOLD}[4/4] Running secrets scan...${NC}"

SECRETS_AVAILABLE=true
if command -v detect-secrets &> /dev/null; then
    set +e
    detect-secrets scan --all-files 2>&1 | tee "${AUDIT_DIR}/secrets-scan.json"
    set -e
    echo -e "${GREEN}  detect-secrets results saved${NC}"
else
    SECRETS_AVAILABLE=false
    echo -e "${YELLOW}  detect-secrets not installed - skipping${NC}"
    echo "{\"note\": \"detect-secrets not installed\"}" > "${AUDIT_DIR}/secrets-scan.json"
fi

# ==============================================================================
# Generate summary report
# ==============================================================================

echo ""
echo -e "${BOLD}Generating summary report...${NC}"

# Count test results from pytest output (macOS-compatible)
TESTS_TOTAL=$(grep -o '[0-9]* passed' "${AUDIT_DIR}/pytest-security-results.txt" | grep -o '[0-9]*' || echo "0")
TESTS_FAILED_COUNT=$(grep -o '[0-9]* failed' "${AUDIT_DIR}/pytest-security-results.txt" | grep -o '[0-9]*' || echo "0")

# Count bandit findings
if $BANDIT_AVAILABLE && [ -f "${AUDIT_DIR}/bandit-results.json" ]; then
    BANDIT_HIGH=$(python3 -c "import json; data=json.load(open('${AUDIT_DIR}/bandit-results.json')); print(sum(1 for r in data.get('results',[]) if r['issue_severity']=='HIGH'))" 2>/dev/null || echo "N/A")
    BANDIT_MEDIUM=$(python3 -c "import json; data=json.load(open('${AUDIT_DIR}/bandit-results.json')); print(sum(1 for r in data.get('results',[]) if r['issue_severity']=='MEDIUM'))" 2>/dev/null || echo "N/A")
    BANDIT_LOW=$(python3 -c "import json; data=json.load(open('${AUDIT_DIR}/bandit-results.json')); print(sum(1 for r in data.get('results',[]) if r['issue_severity']=='LOW'))" 2>/dev/null || echo "N/A")
else
    BANDIT_HIGH="N/A"
    BANDIT_MEDIUM="N/A"
    BANDIT_LOW="N/A"
fi

# Generate the markdown summary
cat > "${AUDIT_DIR}/audit-summary.md" << SUMMARY_EOF
# Security Audit Report - PelotonRacer

**Audit Date:** $(date '+%Y-%m-%d %H:%M:%S')
**Generated By:** scripts/run_security_audit.sh --report
**Branch:** $(git branch --show-current 2>/dev/null || echo "unknown")
**Commit:** $(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

---

## Summary

| Check | Status | Details |
|-------|--------|---------|
| Security Tests (pytest) | $(if $TESTS_PASSED; then echo "PASS"; else echo "**FAIL**"; fi) | ${TESTS_TOTAL} passed, ${TESTS_FAILED_COUNT} failed |
| Static Analysis (bandit) | $(if $BANDIT_AVAILABLE; then echo "Ran"; else echo "Skipped"; fi) | High: ${BANDIT_HIGH}, Medium: ${BANDIT_MEDIUM}, Low: ${BANDIT_LOW} |
| Dependency Audit | $(if $PIPAUDIT_AVAILABLE; then echo "Ran"; else echo "Skipped"; fi) | See dependency-audit.txt |
| Secrets Scan | $(if $SECRETS_AVAILABLE; then echo "Ran"; else echo "Skipped"; fi) | See secrets-scan.json |

## Files in This Audit

| File | Description |
|------|-------------|
| \`audit-summary.md\` | This summary report |
| \`pytest-security-results.txt\` | Full pytest output for security-marked tests |
| \`bandit-results.txt\` | Bandit static analysis output (human-readable) |
| \`bandit-results.json\` | Bandit results (machine-readable) |
| \`dependency-audit.txt\` | pip-audit or safety dependency check results |
| \`secrets-scan.json\` | detect-secrets scan results |

## How to Re-run

\`\`\`bash
# Quick security test run (no report)
./scripts/run_security_audit.sh

# Full audit with report generation
./scripts/run_security_audit.sh --report

# With verbose output
./scripts/run_security_audit.sh --report -v

# With coverage
./scripts/run_security_audit.sh --report --cov
\`\`\`

## Previous Audits

Browse \`docs/security/audits/\` for previous audit results.
Each folder is named with the date and time of the audit (YYYY-MM-DD_HHMM).

## Reference Documents

- [Security Setup Guide](../SECURITY_SETUP.md)
- [Security Procedures](../SECURITY_PROCEDURES.md)
- [Quick Reference](../QUICK_REFERENCE.md)
SUMMARY_EOF

echo -e "${GREEN}  Summary saved to ${AUDIT_DIR}/audit-summary.md${NC}"

# ==============================================================================
# Final status
# ==============================================================================

echo ""
echo "==================================="
echo "Audit Complete"
echo "==================================="
echo ""
echo "Reports saved to: ${AUDIT_DIR}/"
echo ""
ls -la "${AUDIT_DIR}/"
echo ""

if $TESTS_PASSED; then
    echo -e "${GREEN}Overall: Security tests PASSED${NC}"
    exit 0
else
    echo -e "${RED}Overall: Security tests FAILED - review ${AUDIT_DIR}/pytest-security-results.txt${NC}"
    exit 1
fi
