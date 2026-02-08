#!/bin/bash
# Security Setup Validation Script
# This script validates that all security monitoring components are properly configured

set -e

echo "==================================="
echo "Security Setup Validation"
echo "==================================="
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track overall status
ERRORS=0
WARNINGS=0

# Function to check file exists
check_file() {
    if [ -f "$1" ]; then
        echo -e "${GREEN}✓${NC} $1 exists"
        return 0
    else
        echo -e "${RED}✗${NC} $1 missing"
        ERRORS=$((ERRORS + 1))
        return 1
    fi
}

# Function to check directory exists
check_dir() {
    if [ -d "$1" ]; then
        echo -e "${GREEN}✓${NC} $1/ exists"
        return 0
    else
        echo -e "${RED}✗${NC} $1/ missing"
        ERRORS=$((ERRORS + 1))
        return 1
    fi
}

# Function to check Python package
check_package() {
    if python3 -m pip show "$1" &> /dev/null; then
        echo -e "${GREEN}✓${NC} $1 installed"
        return 0
    else
        echo -e "${YELLOW}⚠${NC} $1 not installed"
        WARNINGS=$((WARNINGS + 1))
        return 1
    fi
}

echo "1. Checking Configuration Files"
echo "--------------------------------"
check_file ".pre-commit-config.yaml"
check_file "requirements-security.txt"
check_file ".secrets.baseline"
check_file ".pylintrc"
check_file ".gitignore"
echo ""

echo "2. Checking GitHub Actions"
echo "-------------------------"
check_dir ".github/workflows"
check_file ".github/workflows/security-scan.yml"
echo ""

echo "3. Checking Documentation"
echo "------------------------"
check_dir "docs/security"
check_file "docs/security/README.md"
check_file "docs/security/SECURITY_PROCEDURES.md"
check_file "docs/security/SECURITY_SETUP.md"
check_file "docs/security/SECURITY_SUMMARY.md"
check_file "SECURITY_QUICKSTART.md"
echo ""

echo "4. Checking Security Tools Installation"
echo "---------------------------------------"
check_package "pre-commit"
check_package "detect-secrets"
check_package "bandit"
check_package "pip-audit"
echo ""

echo "5. Testing Security Tools"
echo "------------------------"
if command -v detect-secrets &> /dev/null; then
    if detect-secrets scan --baseline .secrets.baseline &> /dev/null; then
        echo -e "${GREEN}✓${NC} detect-secrets working"
    else
        echo -e "${RED}✗${NC} detect-secrets found issues"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo -e "${YELLOW}⚠${NC} detect-secrets not available"
    WARNINGS=$((WARNINGS + 1))
fi

if command -v bandit &> /dev/null; then
    if [ -d "src" ]; then
        bandit -r src/ -ll --exit-zero &> /dev/null
        echo -e "${GREEN}✓${NC} bandit working"
    else
        echo -e "${YELLOW}⚠${NC} src/ directory not found"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo -e "${YELLOW}⚠${NC} bandit not available"
    WARNINGS=$((WARNINGS + 1))
fi
echo ""

echo "==================================="
echo "Validation Summary"
echo "==================================="
echo ""

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo ""
    echo "Security monitoring is properly configured."
    echo ""
    echo "Next steps:"
    echo "  1. Read the docs: docs/security/README.md"
    echo "  2. Run a security audit: ./scripts/run_security_audit.sh --report"
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}⚠ Validation completed with $WARNINGS warning(s)${NC}"
    echo ""
    echo "Some optional components are missing but core setup is complete."
    echo ""
    echo "To install missing tools:"
    echo "  pip install -r requirements-security.txt"
    echo "  pre-commit install"
    exit 0
else
    echo -e "${RED}✗ Validation failed with $ERRORS error(s) and $WARNINGS warning(s)${NC}"
    echo ""
    echo "Please fix the errors above and run this script again."
    echo ""
    echo "For help, see: docs/security/SECURITY_SETUP.md"
    exit 1
fi
