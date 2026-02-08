#!/bin/bash
# Security Audit Script for PelotonRacer
# Runs all security-marked pytest tests and reports results
#
# Usage:
#   ./scripts/run_security_audit.sh          # Standard audit
#   ./scripts/run_security_audit.sh -v       # Verbose output
#   ./scripts/run_security_audit.sh --cov    # With coverage for security tests

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "==================================="
echo "PelotonRacer Security Audit"
echo "==================================="
echo ""

# Parse arguments
VERBOSE="-v"
EXTRA_ARGS=""
for arg in "$@"; do
    case $arg in
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

echo "Running security tests..."
echo ""

# Run security-marked tests
if python -m pytest tests/ -m security $VERBOSE --tb=short $EXTRA_ARGS; then
    echo ""
    echo -e "${GREEN}==================================${NC}"
    echo -e "${GREEN}Security audit PASSED${NC}"
    echo -e "${GREEN}==================================${NC}"
    exit 0
else
    echo ""
    echo -e "${RED}==================================${NC}"
    echo -e "${RED}Security audit FAILED${NC}"
    echo -e "${RED}==================================${NC}"
    echo ""
    echo "Review the failures above and fix before merging."
    exit 1
fi
