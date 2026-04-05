# Troubleshooting

This guide helps diagnose common runtime and workflow issues quickly.

## Fast Triage Flow

1. Run with `--log-level INFO` (or `DEBUG` for deep diagnosis).
2. Confirm input format is supported and parser detection is expected.
3. Confirm enrichment mode (online/offline) and feed accessibility.
4. Validate output artifacts and RunManifest verification.

## Common Issues

### Input Not Detected or Unsupported

Symptoms:

- Parser detection chooses an unexpected parser.
- Run fails early with unsupported schema/format behavior.

Checks:

1. Ensure input is Nessus/OpenVAS XML or supported structured input.
2. Check for malformed XML or unexpected root tags.
3. Ensure the file is not truncated or partially exported.

Fixes:

- Re-export from scanner in supported format.
- Validate source file in an XML-aware editor.
- Review [Detection and Parsing](Detection%20and%20Parsing.md).

### Enrichment Coverage Lower Than Expected

Symptoms:

- Fewer findings contain KEV/EPSS/exploit context than expected.

Checks:

1. Confirm source flags (`--kev-source`, `--epss-source`, `--exploit-source`).
2. Confirm sources are not disabled (`--no-kev`, `--no-epss`, `--no-exploit`).
3. Confirm offline feed files are present and readable.

Fixes:

- Switch to online mode for source freshness where allowed.
- Use `--refresh-cache` if cache state is stale.
- Re-run with `--log-level INFO` to inspect phase behavior.

### Offline Mode Failures

Symptoms:

- Feed reads fail when using offline source mode.

Checks:

1. Confirm local feed paths exist and are readable.
2. Confirm feed files are valid JSON/CSV and not corrupted.
3. Confirm optional checksum regeneration policy if needed.

Fixes:

- Provide explicit feed paths (`--kev-feed`, `--epss-feed`, `--exploit-db`).
- Use `--allow-regen` where best-effort checksum regeneration is acceptable.

### Missing CSV or Markdown Output

Symptoms:

- JSON exists but CSV/Markdown files are missing.

Checks:

1. Confirm output flags were provided (`--output-csv`, `--output-md`, `--output-md-technical`).
2. Confirm write-path policies and permissions are valid.
3. Confirm symlink restrictions and enforced root settings are compatible with target paths.

Fixes:

- Use explicit writable output paths.
- Adjust path policy flags or write under allowed roots.

### RunManifest Verification Fails

Symptoms:

- `--verify-runmanifest` reports schema or integrity errors.

Checks:

1. Ensure the file is the original artifact and not manually edited.
2. Ensure file transfer/storage path did not alter content.
3. Verify with the same release family if possible.

Fixes:

- Re-generate artifact from the original run.
- Store and transfer runmanifest as immutable evidence.
- Use compact mode for routine runs, expanded mode for investigations.

### Performance Slow on Large Inputs

Symptoms:

- Large scan processing takes longer than expected.

Checks:

1. Confirm workload size and whether large-input flags are set.
2. Use lower log verbosity for high-volume workloads.
3. Confirm host system has sufficient CPU/RAM and no heavy contention.

Fixes:

- Use `--allow-large` for intentionally large workloads.
- Prefer `--log-level WARNING` or `ERROR` for very large runs.
- Run on dedicated compute where possible.

## Useful Diagnostic Commands

```bash
vpp --help
vpp --version
vpp -f input.xml -o out.json --log-level INFO
vpp -f input.xml -o out.json --output-runmanifest out.runmanifest.json
vpp --verify-runmanifest out.runmanifest.json
```

## When Filing an Issue

Include:

1. VulnParse-Pin version (`vpp --version`).
2. Command used (redact sensitive paths/data).
3. Log level and key error excerpts.
4. Input format type and approximate finding count.
5. Whether online/offline enrichment was used.

## Related Docs

- [Usage](Usage.md)
- [Getting Started In 5 Minutes](Getting%20Started%20In%205%20Minutes.md)
- [RunManifest Overview](RunManifest.md)
- [Upgrade and Migration](Upgrade%20and%20Migration.md)