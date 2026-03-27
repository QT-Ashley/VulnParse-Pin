# Security

VulnParse-Pin uses secure defaults across input handling, enrichment caching, and export paths.

## Security goals

- Prevent unsafe file path traversal and symlink abuse
- Protect downstream consumers from CSV formula injection
- Detect tampering in cached vulnerability intelligence stores
- Bound parsing complexity to reduce denial-of-service risk

## File I/O hardening (PFH)

`src/vulnparse_pin/io/pfhandler.py` enforces a policy-aware read/write model.

Key controls:

- Root-constrained read/write enforcement
- Symlink restrictions on write (and optional read restrictions)
- Controlled file/directory mode behavior (POSIX-focused)
- Structured path normalization and sanitization

Useful diagnostic mode:

```bash
vpp --debug-path-policy
```

## Input validation controls

`src/vulnparse_pin/utils/validations.py` validates:

- Allowed file extensions (`.json`, `.xml`, `.nessus`)
- Maximum input size guardrails
- Structural parse viability
- Maximum nesting depth (for JSON-like payload protection)

These controls reduce parser abuse risk for malformed or hostile inputs.

## CSV export sanitization

`src/vulnparse_pin/utils/csv_exporter.py` mitigates formula injection by sanitizing dangerous prefixes (`=`, `+`, `-`, `@`) and stripping unsafe control characters.

This is enabled by default and should remain enabled for general operations.

## NVD cache integrity protections

`src/vulnparse_pin/utils/nvdcacher.py` includes protections for the SQLite index path:

- CVE ID validation
- Optional HMAC signature verification (`VP_SQLITE_HMAC_KEY`)
- Permission enforcement (best effort, OS-dependent)
- Quarantine/rebuild behavior for integrity failures

## XML parser safety

XML processing relies on secure parsing primitives (`defusedxml`) to reduce exposure to XML parser attack classes.

## Security-by-default posture

Default behavior favors safety and explicit opt-out for potentially risky behavior.

Examples:

- CSV sanitization enabled by default
- Path confinement enabled in standard flow
- Parser/file-size guardrails active by default

## Security validation tests

Relevant tests include:

- `tests/test_csv_sanitization.py`
- `tests/test_adversarial_sqlite_feeds.py`
- `tests/test_pfh.py`

## Operational recommendations

- Set `VP_SQLITE_HMAC_KEY` in production for cache integrity validation
- Keep default path policy enabled in CI and server environments
- Restrict writable directories for service accounts
- Treat scan input as untrusted content
