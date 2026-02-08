# Security Setup Guide

This guide helps you set up and use the security monitoring tools for PelotonRacer.

## Quick Start

### 1. Install Security Tools

```bash
# Install all security dependencies
pip install -r requirements-security.txt
```

### 2. Set Up Pre-commit Hooks

```bash
# Install pre-commit framework
pip install pre-commit

# Install the git hooks
pre-commit install

# (Optional) Run on all files to test
pre-commit run --all-files
```

### 3. Verify Installation

```bash
# Test pre-commit hooks
git add .
git commit -m "Test commit" --dry-run

# The hooks should run automatically
```

## Pre-commit Hooks

Pre-commit hooks run automatically before each commit to catch security issues early.

### What Gets Checked

1. **Secrets Detection** - Prevents committing credentials
2. **Security Linting** - Scans for common security issues
3. **Code Formatting** - Ensures consistent code style
4. **Private Key Detection** - Prevents committing SSH/SSL keys
5. **Large Files** - Prevents committing files > 1MB

### Running Manually

```bash
# Run all hooks on all files
pre-commit run --all-files

# Run specific hook
pre-commit run detect-secrets --all-files
pre-commit run bandit --all-files

# Skip hooks (emergency only)
git commit --no-verify -m "Emergency fix"
```

### Updating Hooks

```bash
# Update to latest versions
pre-commit autoupdate

# Clean and reinstall
pre-commit clean
pre-commit install
```

## Security Scanning Tools

### 1. Secrets Detection (detect-secrets)

Scans for hardcoded credentials, API keys, and tokens.

```bash
# Scan all files
detect-secrets scan

# Update baseline
detect-secrets scan > .secrets.baseline

# Audit findings
detect-secrets audit .secrets.baseline
```

**Common False Positives:**

If you get false positives, you can:
- Add inline comments: `# pragma: allowlist secret`
- Update the baseline file
- Use `detect-secrets audit` to mark as false positive

### 2. Security Linting (bandit)

Scans Python code for security issues.

```bash
# Scan with default settings
bandit -r src/

# Only show medium/high severity
bandit -r src/ -ll

# Generate JSON report
bandit -r src/ -f json -o bandit-report.json

# Scan specific file
bandit src/api/peloton_client.py
```

**Common Issues:**

- `B101`: Use of assert (test code only)
- `B201`: Flask debug mode
- `B301`: Pickle usage
- `B404`: Subprocess usage
- `B608`: SQL injection risks

### 3. Dependency Scanning (pip-audit)

Checks dependencies for known vulnerabilities.

```bash
# Scan all dependencies
pip-audit

# Show detailed descriptions
pip-audit --desc

# Output as JSON
pip-audit --format json

# Fix automatically (when possible)
pip-audit --fix
```

### 4. Alternative Dependency Scanner (safety)

Another dependency vulnerability checker.

```bash
# Basic scan
safety check

# JSON output
safety check --json

# Check requirements file
safety check -r requirements.txt
```

## GitHub Actions

Security scans run automatically on:
- Every pull request
- Every push to main
- Weekly (Sundays at midnight UTC)
- Manual trigger

### Viewing Results

1. Go to GitHub repository
2. Click "Actions" tab
3. Select "Security Scan" workflow
4. View job results

### Manual Trigger

1. Go to Actions → Security Scan
2. Click "Run workflow"
3. Select branch
4. Click "Run workflow" button

## Fixing Security Issues

### Secrets in Code

**Problem:** Detected hardcoded credentials

```python
# BAD
api_key = "sk_live_abc123xyz789"
password = "mypassword123"

# GOOD
import os
api_key = os.getenv("API_KEY")
password = os.getenv("PASSWORD")
```

**Solution:**
1. Move secrets to `.env` file
2. Load with `python-dotenv`
3. Update `.env.example` (without real values)
4. Commit the fix

### SQL Injection

**Problem:** Bandit detects SQL injection risk

```python
# BAD
query = f"SELECT * FROM users WHERE id = {user_id}"

# GOOD
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

### Vulnerable Dependencies

**Problem:** pip-audit finds CVE in dependency

```bash
# Update specific package
pip install --upgrade vulnerable-package

# Update requirements.txt
pip freeze > requirements.txt

# Verify fix
pip-audit
```

## Troubleshooting

### Pre-commit Hook Failures

**Issue:** Hooks fail on commit

```bash
# See what failed
git commit -m "Test"

# Fix formatting issues automatically
black .
isort .

# Re-run hooks
pre-commit run --all-files
```

### False Positives

**Issue:** Tool flags safe code

**detect-secrets:**
```python
# Add inline comment
token = get_test_token()  # pragma: allowlist secret
```

**bandit:**
```python
# Add nosec comment (use sparingly!)
subprocess.call(cmd)  # nosec B602
```

### Installation Issues

**Issue:** pre-commit install fails

```bash
# Ensure Python 3.10+
python --version

# Reinstall pre-commit
pip uninstall pre-commit
pip install pre-commit

# Check git hooks directory
ls -la .git/hooks/
```

## Best Practices

### Before Committing

1. Run `pre-commit run --all-files`
2. Fix any security issues
3. Update documentation if needed
4. Test your changes

### Adding New Dependencies

1. Research package security history
2. Check for known vulnerabilities
3. Add to `requirements.txt`
4. Run `pip-audit`
5. Document why it's needed

### Handling Secrets

1. Never commit real credentials
2. Use environment variables
3. Keep `.env` in `.gitignore`
4. Update `.env.example` for new vars
5. Rotate credentials if accidentally committed

### Code Reviews

1. Run security scan locally first
2. Address all findings before review
3. Use security checklist
4. Document security decisions
5. Test authentication flows

## Security Monitoring Schedule

- **Daily:** Pre-commit hooks on every commit
- **Weekly:** Automated dependency scans
- **Monthly:** Manual security review
- **Quarterly:** Comprehensive audit

## Additional Resources

- [Pre-commit Documentation](https://pre-commit.com/)
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [detect-secrets Documentation](https://github.com/Yelp/detect-secrets)
- [pip-audit Documentation](https://github.com/pypa/pip-audit)
- [Security Procedures](./SECURITY_PROCEDURES.md)

## Getting Help

If you encounter security issues or have questions:

1. Check this documentation
2. Review security procedures
3. Contact project maintainers
4. Report vulnerabilities privately

---

**Last Updated:** 2026-02-07
