# Upgrade and Migration

This guide covers practical upgrade steps and CLI behavior changes between recent releases.

## Supported Upgrade Path

- v1.0.x -> v1.1.x is supported.
- If you rely on automation, validate scripts in a staging run before production rollout.

## Breaking and Behavioral Changes (v1.0.x -> v1.1.x)

### Enrichment Flag Model Changed

Legacy positive-enable flags were removed:

- `--enrich-kev`
- `--enrich-epss`
- `--enrich-exploit`

Use the new disable/source model:

- `--no-kev`
- `--no-epss`
- `--no-exploit`
- `--kev-source <online|offline>`
- `--epss-source <online|offline>`
- `--exploit-source <online|offline>`

### RunManifest Workflows Added

New run artifact and verification workflows are available:

- `--output-runmanifest <path>`
- `--runmanifest-mode <compact|expanded>`
- `--verify-runmanifest <path>`

### GHSA Activation Is CLI-Only

GHSA enrichment no longer auto-activates from config defaults.

- GHSA is disabled unless `--ghsa` is provided at runtime.
- Use `--ghsa` or `--ghsa online` for online advisory lookups.
- Use `--ghsa <path>` for offline advisory database/repo loading.
- Optional online prefetch limit can be set per-run with `--ghsa-budget <count>`.

Notes:

- `enrichment.ghsa_source` in `config.yaml` is retained for compatibility documentation only and is not used to auto-enable GHSA.
- Token env var selection is controlled by `enrichment.ghsa_token_env` (default `VP_GHSA_TK`) with `GITHUB_TOKEN` fallback.

## Flag Migration Matrix

| Legacy pattern | Current pattern | Notes |
| --- | --- | --- |
| `--enrich-kev` | default-on (no flag) | Add `--no-kev` to disable |
| `--enrich-epss` | default-on (no flag) | Add `--no-epss` to disable |
| `--enrich-exploit` | default-on (no flag) | Add `--no-exploit` to disable |
| n/a | `--kev-source offline` | Use offline KEV source |
| n/a | `--epss-source offline` | Use offline EPSS source |
| n/a | `--exploit-source offline` | Use offline Exploit-DB source |

## Before and After Examples

### Legacy style (v1.0.x)

```bash
vpp -f input.xml -o out.json --enrich-kev --enrich-epss --enrich-exploit
```

### Current style (v1.1.x)

```bash
vpp -f input.xml -o out.json
```

### Current style with selective disable

```bash
vpp -f input.xml -o out.json --no-exploit
```

### Current style with mixed online/offline

```bash
vpp -f input.xml -o out.json --kev-source offline --epss-source online --exploit-source offline
```

## Automation Upgrade Checklist

1. Replace removed `--enrich-*` flags in scripts and pipeline jobs.
2. Add explicit source flags where deterministic mode is required.
3. Add RunManifest generation and verification for auditable workflows.
4. Compare sample output fields in JSON and CSV for any downstream assumptions.
5. Re-run parser/pass contract tests before release promotion.

## Recommended Post-Upgrade Verification

```bash
vpp -f input.xml -o out.json --output-runmanifest out.runmanifest.json
vpp --verify-runmanifest out.runmanifest.json
```

Review:

- Run success and expected output artifacts
- Expected enrichment coverage for your selected source modes
- `derived["Scoring@2.0"]`, `derived["TopN@1.0"]`, and `derived["Summary@1.0"]` presence

## Related Docs

- [Usage](Usage.md)
- [RunManifest Overview](RunManifest.md)
- [Troubleshooting](Troubleshooting.md)
- [Output Interpretation](Output%20Interpretation.md)