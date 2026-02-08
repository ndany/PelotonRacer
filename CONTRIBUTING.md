# Contributing to PelotonRacer

Guidelines for human contributors and AI agents working on this codebase.

## Development Workflow

### Before You Start

```bash
pip install -r requirements.txt
pip install -r requirements-security.txt
pre-commit install
```

### Before Every Commit

1. **Run the full test suite** and verify all tests pass:
   ```bash
   pytest tests/ -v --cov=src --cov-report=term-missing
   ```
2. **Run security tests** if you touched `src/api/` or `src/services/`:
   ```bash
   pytest tests/ -m security -v
   ```
3. Pre-commit hooks run automatically on `git commit` (secrets detection, bandit, formatting).

### Before Every PR

- All 307+ tests pass with 97%+ coverage
- No new CRITICAL or HIGH security findings introduced
- Run `./scripts/run_security_audit.sh` to verify

## Code Conventions

### Python

- Dataclasses with `from_dict()`/`to_dict()` for models
- Static methods for stateless analysis (`race_analyzer.py`)
- `ThreadPoolExecutor` for parallel API calls
- Environment variables via `.env` for credentials (never hardcode)

### Security

- **Thresholds:** Zero CRITICAL, <=2 HIGH findings (established in issue #18)
- **No secrets in code or docs:** Use `.env` files, gitignored
- **No vulnerability details in checked-in files:** Run `./scripts/run_security_audit.sh --report` to generate reports locally (output is gitignored in `docs/security/audits/`)
- **Sanitize error messages:** No file paths, stack traces, or internal details in user-facing exceptions (CWE-209)
- **Validate file paths:** All file operations must check against allowed directories

#### Severity Response Timeframes

| Severity | Examples | Remediation Target | Tracking |
|----------|----------|---------------------|----------|
| **CRITICAL** | Active exploitation, credential leak, auth bypass | Immediate -- fix within 24-48 hours | Dedicated issue, blocks release |
| **HIGH** | Exploitable vulnerability, significant security flaw | Within current sprint (1-2 weeks) | Dedicated issue with acceptance criteria |
| **MEDIUM** | Potential vulnerability, requires specific conditions | Next planned release | Track in backlog |
| **LOW** | Minor improvement, best practice violation | Opportunistic | Track in backlog |

#### Security Documentation Quality

When writing security reports or audit documentation:

- Use **CVSS scores** for vulnerability severity assessment
- Apply **STRIDE** threat modeling (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
- Map findings to **OWASP Top 10** categories where applicable
- Include **specific remediation steps** with code examples, not just descriptions of problems
- Provide **effort estimates** and **priority ordering** for remediation work
- Add **verification checklists** so fixes can be confirmed

### Testing

- Mark tests with `@pytest.mark.unit`, `@pytest.mark.integration`, or `@pytest.mark.security`
- Use shared fixtures from `tests/conftest.py` (30+ available)
- Test edge cases and error paths, not just happy paths
- See [docs/testing/TESTING.md](docs/testing/TESTING.md) for the full testing guide

## Documentation Standards

When writing or updating documentation:

- **Actionable content** -- include specific steps, commands, and effort estimates rather than vague guidance
- **Consistent formatting** -- markdown with clear hierarchy, tables for structured data, code blocks with syntax highlighting
- **Working internal links** -- use relative paths, validate cross-references
- **No stale information** -- update test counts, coverage numbers, and tool versions when they change
- **Executive summaries** -- lead with context for both technical and non-technical readers

## Documentation Structure

```
docs/
├── security/
│   ├── README.md                # Security docs index
│   ├── QUICK_REFERENCE.md       # One-page security tools reference
│   ├── SECURITY_SETUP.md        # Security tool setup guide
│   ├── SECURITY_PROCEDURES.md   # Incident response & procedures
│   ├── SECURITY_SUMMARY.md      # Security monitoring setup summary
│   └── audits/                  # Generated audit reports (gitignored)
├── testing/
│   ├── TESTING.md               # Complete testing guide
│   └── coverage-report.md       # Coverage analysis (gitignored)
└── plans/                       # Design docs and implementation plans
```

Root-level docs: `README.md`, `SECURITY.md` (policy), `SECURITY_QUICKSTART.md`, `CLAUDE.md` (AI agent context), this file.

## Workflows by Role

### Developers

1. Run `./scripts/run_security_audit.sh --report` to generate a current security report
2. Review generated reports in `docs/security/audits/`
3. Check `docs/testing/coverage-report.md` for coverage gaps before adding tests
4. Follow [docs/testing/TESTING.md](docs/testing/TESTING.md) for test patterns and fixtures

### Security Reviewers

Run `./scripts/run_security_audit.sh --report` to generate audit artifacts including STRIDE analysis, OWASP mapping, and remediation roadmap. Results are saved to a timestamped folder in `docs/security/audits/`.

### QA

- [docs/testing/TESTING.md](docs/testing/TESTING.md) -- complete testing guide with fixtures, markers, and best practices
- `pytest tests/ -v --cov=src` -- run full suite with coverage
- `pytest tests/ -m security -v` -- security tests only

## Issue & PR Conventions

- **Branch naming:** `fix/<issue>-<description>`, `feature/<description>`, `chore/<description>`
- **Commit messages:** `type: description` (e.g., `security: Fix JWT validation`, `test: Add path traversal tests`, `docs: Update README`)
- **Security issues** get their own tracking issues with acceptance criteria and test coverage -- not bundled into unrelated work
- **New security findings** are tracked against the relevant release/change set, not always the parent infrastructure issue

## For AI Agents

In addition to everything above:

- Read `CLAUDE.md` for project architecture and key commands
- Run tests after every code change -- do not claim tests pass without running them
- Do not include specific vulnerability details (CVE numbers, exploit steps, PoC code) in files that get committed
- When creating issues, include acceptance criteria, estimated effort, and `How to Verify` section
- Keep documentation current: if you change test counts, coverage, or tool versions, update all references

## Key References

| What | Where |
|------|-------|
| Testing guide | [docs/testing/TESTING.md](docs/testing/TESTING.md) |
| Security docs | [docs/security/README.md](docs/security/README.md) |
| Security quick ref | [docs/security/QUICK_REFERENCE.md](docs/security/QUICK_REFERENCE.md) |
| Run security audit | `./scripts/run_security_audit.sh --report` |
| Validate security setup | `bash scripts/validate_security_setup.sh` |
| AI agent context | [CLAUDE.md](CLAUDE.md) |
