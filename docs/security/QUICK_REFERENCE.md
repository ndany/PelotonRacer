# Security Tools Quick Reference

A one-page reference for PelotonRacer security tools.

## Installation

```bash
pip install -r requirements-security.txt
pre-commit install
```

## Daily Commands

| Task | Command |
|------|---------|
| Run security tests | `./scripts/run_security_audit.sh` |
| Full audit with report | `./scripts/run_security_audit.sh --report` |
| Run all security checks | `pre-commit run --all-files` |
| Scan for secrets | `detect-secrets scan` |
| Security lint code | `bandit -r src/ -ll` |
| Check dependencies | `pip-audit` |
| Validate setup | `bash scripts/validate_security_setup.sh` |

## Pre-commit Hooks

Automatically run before each commit:
- Secrets detection
- Security linting
- Code formatting
- Import sorting
- YAML/JSON validation
- Large file check
- Private key detection

**Skip hooks (emergency):**
```bash
git commit --no-verify -m "Message"
```

## Security Scanning Tools

### detect-secrets
```bash
detect-secrets scan                    # Scan all files
detect-secrets scan > .secrets.baseline  # Update baseline
detect-secrets audit .secrets.baseline   # Review findings
```

### bandit
```bash
bandit -r src/                  # Basic scan
bandit -r src/ -ll             # Medium/high severity only
bandit -r src/ -f json -o report.json  # JSON report
```

### pip-audit
```bash
pip-audit                # Check all dependencies
pip-audit --desc         # With descriptions
pip-audit --fix          # Auto-fix when possible
```

## Common Security Issues & Fixes

### Secrets in Code
```python
# BAD
api_key = "sk_live_abc123"

# GOOD
import os
api_key = os.getenv("API_KEY")
```

### SQL Injection
```python
# BAD
query = f"SELECT * FROM users WHERE id = {user_id}"

# GOOD
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

### Path Traversal
```python
# BAD
file_path = user_input

# GOOD
import os
file_path = os.path.join(safe_dir, os.path.basename(user_input))
```

## False Positives

### detect-secrets
```python
token = get_test_token()  # pragma: allowlist secret
```

### bandit
```python
subprocess.call(cmd)  # nosec B602
```

## GitHub Actions

- **Triggers**: Every PR, weekly (Sundays), manual
- **Location**: `.github/workflows/security-scan.yml`
- **View Results**: Actions tab on GitHub

## Severity Levels

| Level | Description | Action |
|-------|-------------|--------|
| **Critical** | Active exploit, credential leak | Immediate action |
| **High** | Exploitable vulnerability | Fix in current sprint |
| **Medium** | Potential vulnerability | Plan fix |
| **Low** | Best practice violation | Nice to have |

## Security Checklist for PRs

- [ ] No hardcoded credentials
- [ ] No sensitive data in logs
- [ ] Input validation present
- [ ] Proper error handling
- [ ] Pre-commit hooks passing
- [ ] No vulnerable dependencies
- [ ] Authentication checks in place

## Security Audit Reports

```bash
# Generate a full audit report (saved to timestamped folder)
./scripts/run_security_audit.sh --report

# Reports saved to: docs/security/audits/YYYY-MM-DD_HHMM/
# Browse that directory for historical audit results
```

## Monitoring Schedule

| Frequency | Activity |
|-----------|----------|
| Every commit | Pre-commit hooks |
| Every PR | GitHub Actions |
| Weekly | Dependency scan |
| Monthly | Manual review + `./scripts/run_security_audit.sh --report` |
| Quarterly | Full audit |

## Documentation

- **Setup**: [SECURITY_SETUP.md](./SECURITY_SETUP.md)
- **Procedures**: [SECURITY_PROCEDURES.md](./SECURITY_PROCEDURES.md)
- **Overview**: [README.md](./README.md)
- **Quick Start**: [/SECURITY_QUICKSTART.md](../../SECURITY_QUICKSTART.md)

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Pre-commit fails | Review hook output and fix flagged issues |
| False positive | Add inline comment or update baseline |
| Hook not running | `pre-commit install` |
| Tool not found | `pip install -r requirements-security.txt` |

## Emergency Contacts

**Report Security Issues:**
- DO NOT create public GitHub issue
- Email maintainers privately
- Include: description, steps to reproduce, impact

## Tool Versions

- pre-commit: ≥3.6.0
- detect-secrets: ≥1.4.0
- bandit: ≥1.7.5
- pip-audit: ≥2.6.0

---

**Print this page for quick reference!**

Last updated: 2026-02-08
