#!/bin/bash
# Generate test coverage report for PelotonRacer
# This script runs pytest with coverage and generates both HTML and markdown reports

set -e  # Exit on error

echo "🧪 Running test suite with coverage analysis..."
echo ""

# Run pytest with coverage
pytest tests/ -v \
    --cov=src \
    --cov-report=term-missing \
    --cov-report=html:htmlcov \
    --cov-report=json:.coverage.json

echo ""
echo "✅ Test suite complete!"
echo ""
echo "📊 Coverage Reports Generated:"
echo "   - HTML Report: htmlcov/index.html"
echo "   - JSON Report: .coverage.json"
echo "   - Terminal: See output above"
echo ""
echo "💡 To view HTML report:"
echo "   open htmlcov/index.html"
echo ""
echo "📝 Note: Markdown report generation coming soon"
echo "   For now, use the HTML report for detailed coverage analysis"
echo ""
