# Security Documentation

Welcome to the PelotonRacer security documentation. This directory contains all security-related procedures, guidelines, and setup instructions.

## Documentation Index

### [Security Setup Guide](./SECURITY_SETUP.md)
**Start here if you're setting up security tools for the first time.**

Learn how to:
- Install security tools
- Configure pre-commit hooks
- Run security scans manually
- Fix common security issues
- Troubleshoot problems

### [Security Procedures](./SECURITY_PROCEDURES.md)
**Reference for ongoing security operations.**

Includes:
- How to report vulnerabilities
- Security review checklist for PRs
- Incident response procedures
- Security monitoring schedule
- Security best practices

## Quick Reference

### Installation

```bash
# Install all security tools
pip install -r requirements-security.txt

# Set up pre-commit hooks
pre-commit install
```

### Daily Use

```bash
# Pre-commit hooks run automatically on commit
git commit -m "Your changes"

# Run manually on all files
pre-commit run --all-files
```

### Security Scans

```bash
# Scan for secrets
detect-secrets scan

# Security linting
bandit -r src/ -ll

# Check dependencies
pip-audit
```

## Security Tools Overview

### Automated Tools

| Tool | Purpose | When It Runs |
|------|---------|--------------|
| **detect-secrets** | Prevents credential commits | Every commit (pre-commit) |
| **bandit** | Python security linting | Every commit (pre-commit) |
| **pip-audit** | Dependency vulnerabilities | Weekly (GitHub Actions) |
| **safety** | Alternative dependency check | Weekly (GitHub Actions) |
| **flake8** | Code quality | Every commit (pre-commit) |

### GitHub Actions

- **Security Scan Workflow**: `.github/workflows/security-scan.yml`
  - Runs on every PR
  - Runs weekly on Sundays
  - Can be triggered manually
  - Reports sent to PR checks

### Configuration Files

- **`.pre-commit-config.yaml`**: Pre-commit hooks configuration
- **`.secrets.baseline`**: Detect-secrets baseline (known false positives)
- **`requirements-security.txt`**: Security tool dependencies

## Security Monitoring Schedule

| Frequency | Activity |
|-----------|----------|
| **Every Commit** | Pre-commit hooks |
| **Every PR** | GitHub Actions security scan |
| **Weekly** | Automated dependency scan |
| **Monthly** | Manual security review |
| **Quarterly** | Comprehensive security audit |

## Common Security Tasks

### Reporting a Vulnerability

1. **DO NOT** create a public issue
2. Email maintainers directly
3. Include:
   - Description
   - Steps to reproduce
   - Potential impact
   - Suggested fix (optional)

See [Security Procedures](./SECURITY_PROCEDURES.md#reporting-security-vulnerabilities) for details.

### Reviewing a Pull Request

Use the [Security Review Checklist](./SECURITY_PROCEDURES.md#security-review-checklist):

- [ ] No hardcoded credentials
- [ ] No sensitive data in logs
- [ ] Input validation present
- [ ] Proper error handling
- [ ] Dependencies from trusted sources
- [ ] Security tools passing

### Handling a Security Incident

Follow the [Incident Response Procedures](./SECURITY_PROCEDURES.md#incident-response-procedures):

1. **Detect & Assess** - Confirm and assess severity
2. **Contain** - Revoke credentials, patch vulnerabilities
3. **Recover** - Verify fix, monitor for issues
4. **Post-Incident** - Document lessons learned

## Security Best Practices

### Credentials

- ✅ Use environment variables (`.env`)
- ✅ Keep `.env` in `.gitignore`
- ✅ Use `.env.example` for templates
- ❌ Never commit real credentials
- ❌ Never hardcode API keys

### Dependencies

- ✅ Pin versions in `requirements.txt`
- ✅ Run `pip-audit` before adding
- ✅ Review package before installing
- ❌ Don't use unmaintained packages
- ❌ Don't ignore vulnerability warnings

### Code

- ✅ Validate all user inputs
- ✅ Use parameterized queries
- ✅ Handle errors gracefully
- ❌ Don't expose secrets in errors
- ❌ Don't log sensitive data

## Getting Help

### Documentation

1. [Security Setup Guide](./SECURITY_SETUP.md) - Tool setup and usage
2. [Security Procedures](./SECURITY_PROCEDURES.md) - Operational procedures
3. Main [Project README](../../README.md) - Project overview

### External Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Python Security](https://python.readthedocs.io/en/stable/library/security_warnings.html)
- [GitHub Security](https://docs.github.com/en/code-security)

### Support

- **General Questions**: Project maintainers
- **Security Issues**: Report privately to maintainers
- **Urgent Security**: Use emergency contact (see procedures)

## Contributing to Security

Help improve PelotonRacer security:

1. **Report Issues**: Share vulnerabilities privately
2. **Suggest Improvements**: Propose security enhancements
3. **Review Code**: Use security checklist on PRs
4. **Update Docs**: Keep security docs current
5. **Share Knowledge**: Help teammates learn security

## File Structure

```
docs/security/
├── README.md                    # This file - overview and index
├── SECURITY_SETUP.md           # Setup guide for security tools
└── SECURITY_PROCEDURES.md      # Operational security procedures

.github/workflows/
└── security-scan.yml           # Automated security scanning

Root directory:
├── .pre-commit-config.yaml     # Pre-commit hooks config
├── .secrets.baseline           # Detect-secrets baseline
├── requirements-security.txt   # Security tool dependencies
└── .gitignore                  # Includes security entries
```

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-02-07 | Initial security monitoring setup |

---

**Next Review:** 2026-05-07

For questions or concerns, contact the project maintainers.
