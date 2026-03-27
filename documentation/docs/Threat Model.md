# Threat Model

This threat model defines key attack surfaces, assumptions, and mitigations for VulnParse-Pin deployments.

## Scope

In scope:

- Local and CI/CD CLI execution
- Parsing untrusted scanner exports
- Feed cache handling (including local SQLite index)
- Output artifact generation (JSON/CSV)

Out of scope:

- Host OS hardening baseline
- Network perimeter controls outside VPP runtime
- Third-party scanner correctness guarantees

## Trust boundaries

- **Untrusted:** Input files from scanners, possibly attacker-influenced
- **Semi-trusted:** External intelligence feeds (network path and source integrity matter)
- **Trusted runtime:** Local process + configured working directories
- **Potentially risky sink:** Spreadsheet tooling consuming CSV output

## Primary threat scenarios

1. **Path traversal / symlink abuse**
   - Goal: overwrite/read outside intended roots
   - Mitigation: PFH root enforcement and symlink controls

2. **CSV formula injection**
   - Goal: execute formulas when analysts open CSV in office tooling
   - Mitigation: default CSV sanitizer prefixes dangerous leading characters

3. **Cache tampering (SQLite NVD index)**
   - Goal: poison enrichment data to alter scoring decisions
   - Mitigation: optional HMAC signing, validation, quarantine/rebuild

4. **Parser resource exhaustion**
   - Goal: degrade service with huge or deeply nested input
   - Mitigation: size/depth limits and parser guardrails

5. **Malformed scanner output triggering unstable behavior**
   - Goal: crash or force undefined parse state
   - Mitigation: sentinel fallback values, edge-case tolerant parser logic, regression tests

## Security assumptions

- Python runtime and dependencies are trusted and patched
- Execution account has least privilege
- Feed source endpoints are authentic and monitored
- Output artifacts are handled with standard data governance controls

## Residual risks

- Compromised upstream feed content before ingest
- Operator misconfiguration of relaxed path/security flags
- Business logic misuse from unsupported parser formats

## Recommended controls by environment

### Developer workstation

- Keep defaults enabled
- Use virtual environments
- Avoid disabling CSV sanitization unless explicitly needed

### CI pipeline

- Pin dependencies and run tests on parser/security modules
- Set HMAC key for index integrity checks
- Restrict artifact directories

### Enterprise production

- Enforce least-privilege service account
- Centralize logs and monitor parse failures/anomalies
- Include VPP outputs in governance and change-management workflows

## Validation references

- `tests/test_adversarial_sqlite_feeds.py`
- `tests/test_csv_sanitization.py`
- `tests/test_pfh.py`
