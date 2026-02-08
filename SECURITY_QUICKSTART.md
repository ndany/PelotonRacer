# Security Quick Start Guide

Get PelotonRacer's security tools up and running in 5 minutes.

## 1. Install Security Tools

```bash
pip install -r requirements-security.txt
```

This installs:
- Pre-commit hooks framework
- Secrets detection (detect-secrets)
- Security linting (bandit)
- Dependency scanning (pip-audit)

## 2. Set Up Pre-commit Hooks

```bash
pre-commit install
```

This configures Git to run security checks before every commit.

## 3. Test Your Setup

```bash
pre-commit run --all-files
```

This runs all security checks on your codebase. Fix any issues that are found.

## 4. You're Done!

Security hooks now run automatically on every commit. If they find issues:

1. Review the output
2. Fix the issues
3. Stage your fixes: `git add .`
4. Try committing again

## What Gets Checked Automatically

- ✅ **Secrets**: No API keys, passwords, or tokens in code
- ✅ **Security Issues**: Python security vulnerabilities
- ✅ **Code Quality**: Formatting and linting
- ✅ **Large Files**: Nothing over 1MB
- ✅ **Private Keys**: No SSH/SSL keys in commits

## Need Help?

- **Setup Issues**: See [docs/security/SECURITY_SETUP.md](docs/security/SECURITY_SETUP.md)
- **Security Procedures**: See [docs/security/SECURITY_PROCEDURES.md](docs/security/SECURITY_PROCEDURES.md)
- **Full Documentation**: See [docs/security/README.md](docs/security/README.md)

## Common Commands

```bash
# Run all security checks manually
pre-commit run --all-files

# Scan for secrets
detect-secrets scan

# Check for vulnerable dependencies
pip-audit

# Security lint your code
bandit -r src/ -ll

# Skip hooks in emergency (use sparingly!)
git commit --no-verify -m "Emergency fix"
```

## GitHub Actions

Security scans also run automatically:
- On every pull request
- Every week (Sundays)
- Can be triggered manually

View results in the "Actions" tab on GitHub.

---

**That's it!** Your security monitoring is now active.

For detailed information, see the [full security documentation](docs/security/README.md).
