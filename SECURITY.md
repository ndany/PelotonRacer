# Security Policy

## Development Status

⚠️ **PelotonRacer is currently under active development and is NOT production-ready.**

This application has undergone security testing and multiple vulnerabilities have been identified. **Do not deploy to public-facing production environments** without completing the security remediation roadmap.

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in PelotonRacer, please report it responsibly:

### How to Report

1. **DO NOT** open a public GitHub issue for security vulnerabilities
2. Contact the maintainers directly through:
   - GitHub private vulnerability reporting (preferred)
   - Email to the repository maintainers
   - Direct message on GitHub

### What to Include

Please include the following information in your report:

- **Description** of the vulnerability
- **Steps to reproduce** the issue
- **Potential impact** assessment
- **Suggested fix** (if available)
- **Your contact information** for follow-up questions

### Response Timeline

- **Initial Response:** Within 48 hours of report submission
- **Severity Assessment:** Within 1 week
- **Fix Timeline:**
  - CRITICAL: 7 days
  - HIGH: 14 days
  - MEDIUM: 30 days
  - LOW: 90 days

## Security Testing

This project includes comprehensive security testing:

- **196 automated tests** covering unit, integration, and security scenarios
- **STRIDE threat modeling** analysis
- **OWASP Top 10** vulnerability scanning
- **Pre-commit security hooks** for continuous validation
- **GitHub Actions CI/CD** security scanning

### Running Security Tests

```bash
# Run all tests including security tests
pytest tests/ -v

# Run only security-marked tests
pytest tests/ -m security -v

# Run security validation
pre-commit run --all-files

# Validate security setup
bash scripts/validate_security_setup.sh
```

## Known Security Issues

⚠️ **This application has identified vulnerabilities that are being addressed.**

For detailed security status and remediation plans:
- See `docs/security/audit-2026-02-07.md` for the full security audit report
- See `docs/security/remediation-roadmap.md` for the fix schedule
- See `docs/security/SECURITY_PROCEDURES.md` for incident response procedures

**Current Security Status:** Not production-ready

## Security Best Practices for Contributors

When contributing to this project:

1. **Never commit credentials** - Use environment variables or keyring
2. **Run security tests** before submitting PRs
3. **Enable pre-commit hooks** - `pre-commit install`
4. **Follow secure coding practices** - See `docs/security/SECURITY_SETUP.md`
5. **Review OWASP Top 10** - Be aware of common vulnerabilities
6. **Sanitize error messages** - Don't expose sensitive data in logs

## Security Features

### Current Implementations

- ✅ OAuth PKCE authentication flow
- ✅ Secure credential handling in authentication
- ✅ Input validation and sanitization
- ✅ Automated security scanning (pre-commit + CI/CD)
- ✅ Security test coverage
- ✅ Threat modeling documentation

### Planned Improvements

- 🔄 JWT signature validation (CRITICAL - In Progress)
- 🔄 Path traversal protection (CRITICAL - In Progress)
- 🔄 Secure token storage with OS keyring (HIGH - In Progress)
- 🔄 Rate limiting for API calls (MEDIUM - Planned)
- 🔄 Security headers implementation (LOW - Planned)

## Supported Versions

| Version | Supported          | Security Updates |
| ------- | ------------------ | ---------------- |
| main    | :white_check_mark: | Yes (development)|
| < 1.0   | :x:                | No (pre-release) |

**Note:** Version 1.0 will be the first production-ready release.

## Security Disclosure Policy

We follow responsible disclosure principles:

1. **Private Reporting:** Security issues are reported privately
2. **Fix Development:** Vulnerabilities are fixed before public disclosure
3. **Coordinated Disclosure:** Security advisories published after fixes are available
4. **Credit:** Security researchers are credited for their findings (with permission)

## Additional Resources

- **Security Setup Guide:** `docs/security/SECURITY_SETUP.md`
- **Security Procedures:** `docs/security/SECURITY_PROCEDURES.md`
- **Quick Reference:** `docs/security/QUICK_REFERENCE.md`
- **Quick Start:** `SECURITY_QUICKSTART.md`
- **Testing Guide:** `docs/testing/TESTING.md`

## Contact

For security concerns, please contact the maintainers through:
- GitHub Issues (non-sensitive questions only)
- Private vulnerability reporting (preferred for security issues)

---

**Last Updated:** February 7, 2026
**Security Audit Date:** February 7, 2026
**Next Audit:** TBD (After remediation of CRITICAL vulnerabilities)
