# Enrichment Deep Dive

This document explains VulnParse-Pin v2.0.0 (`Apache-2.0`) threat-intelligence enrichment sources, unified CVSS provenance, DuckDB snapshot hydration (`enrichment_snapshots`), and fail-closed security controls.

## Purpose

Enrichment augments normalized findings with external threat intelligence and authoritative severity/exploitability provenance without overwriting raw scanner observations. In v2.0.0, matched CVE and Package URL (`package_purl`) intelligence is hydrated per `run_id` into DuckDB's `enrichment_snapshots` table and `runs.intel_metadata_json`.

## Enrichment Sources (6 Source Families)

| Source | Cache / Storage | Lookup Keys | Key Signals Hydrated |
| --- | --- | --- | --- |
| **CISA KEV** | `kev_cache.json` + `kev_cache.sqlite3` | `CVE` | `in_kev`, `kev_date_added`, `kev_due_date`, `kev_ransomware`, `kev_required_action`, `catalog_version` |
| **EPSS v5** | `epss_cache.csv` + `epss_cache.sqlite3` | `CVE` | `epss_score`, `epss_percentile`, `epss_model_version` (`#model_version`), `epss_date` |
| **NVD** | `nvd/feeds/*.json.gz` + `nvd_cache.sqlite3` | `CVE` | CVSS v4.0/v3.1/v3.0/v2.0 vector & score, `cvss_provenance` (`NVD` vs `CNA`), `source_identifier` |
| **GHSA** | `ghsa_cache.sqlite3` (API or offline JSON/dir) | `CVE`, `GHSA`, `package_purl` | Advisory IDs, CVSS v4/v3, references (`ghsa_package_index` PURL matching) |
| **OSV** | `osv_cache.sqlite3` (offline JSON/dir/`.zip`) | `CVE`, `GHSA`, `package_purl` | Advisory IDs, CVSS v4/v3/v2, references (`osv_package_index` PURL matching) |
| **Exploit-DB** | `files_exploit.csv` (`FeedCacheManager`) + text heuristic | `CVE`, finding text | `verified_exploit`, `exploit_refs_json`, separated from `heuristic_exploit_mention` |

### CISA KEV (`KEVFeedCache`)

- Uses `FeedCacheManager` for remote/offline retrieval (`known_exploited_vulnerabilities.json`) and indexes records in `kev_cache.sqlite3` (signed `.sig.json`).
- Hydrates full KEV fields into `enrichment_snapshots`: `in_kev`, `kev_date_added`, `kev_due_date`, `kev_ransomware`, and `kev_required_action`.

### EPSS v5 (`EPSSFeedCache`)

- Parses FIRST EPSS v5 comment headers (`#model_version:...,score_date:...`) and extracts both raw probability (`epss_score`) and FIRST percentile (`epss_percentile`).
- Stores `epss_model_version` and `epss_date` in `epss_cache.sqlite3`, `enrichment_snapshots`, and `runs.intel_metadata_json` so `DiffEngine` can track model changes and threshold crossings (`0.04`/`0.10`, percentile `0.90`/`0.95`).

### NVD (`NVDFeedCache`)

- Indexes NVD CVE JSON 2.0 feeds into `nvd_cache.sqlite3`, extracting the highest-tier CVSS metric (`cvssMetricV40` -> `cvssMetricV31` -> `cvssMetricV30` -> `cvssMetricV2`).
- Uses `source_identifier` to distinguish authoritative NVD scoring (`nvd@nist.gov` -> `cvss_provenance = "NVD"`) from CNA-supplied scoring (`"CNA"`).

### GHSA (`GHSAEnrichmentSource`)

- Activated explicitly via `--ghsa [PATH|online]` (config does not auto-enable).
- Online mode queries `https://api.github.com/advisories/...` bounded by `--ghsa-budget` (default `25`). Token resolution checks `enrichment.ghsa_token_env` (default `VP_GHSA_TK`, validated against `^[A-Za-z_][A-Za-z0-9_]{0,127}$`), falls back to `GITHUB_TOKEN`, rejects `\r`/`\n` header-injection characters, and validates GitHub token prefixes (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`).
- Offline mode loads advisory JSON files/directories into `ghsa_cache.sqlite3` (`ghsa_cve_index` and `ghsa_package_index`), supporting PURL ecosystem/package matching via `parse_purl()`.

### OSV (`OSVEnrichmentSource`)

- Optional offline advisory source activated via `--osv <PATH>` (JSON file, ecosystem directory, or `.zip` bundle) or `vpp intel sync --feed osv --osv <PATH>`.
- Indexes advisories in `osv_cache.sqlite3` (`osv_advisories`, `osv_cve_index`, `osv_ghsa_index`, `osv_package_index`) with `<= 900`-parameter chunked queries and strict zip path-traversal / zip-bomb validation (`OSVSecurityError`).

### Exploit-DB & Negation-Aware Heuristics

- **Verified exploit references:** `files_exploit.csv` (from Exploit-DB or `--exploit-db <CSV>`) populates `verified_exploit = True` and `exploit_refs_json`.
- **Negation-aware heuristic separation:** `is_heuristic_exploit_mention()` (`src/vulnparse_pin/utils/exploit_enrichment_service.py`) scrubs explicit negations via `_NEGATED_EXPLOIT_RE` (e.g., `"not exploitable"`, `"no known exploit"`, `"unexploitable"`, `"without exploit"`, `"unlikely to be exploited"`, `"cannot be exploited"`) before matching `_POSITIVE_EXPLOIT_RE`.
- Heuristic mentions populate `heuristic_exploit_mention` (`0.0` default scoring points) separately from `verified_exploit`, preventing false inflation and preventing KEV + Exploit-DB double-counting (`verified_exploit_with_kev_points = 0.5`).

## Unified CVSS Provenance Precedence

`resolve_cvss_with_provenance()` (`src/vulnparse_pin/utils/enricher.py`) enforces strict provenance ordering across CVSS v4.0, v3.1, v3.0, and v2.0 vectors:

```text
NVD > CNA > GHSA > OSV > Scanner-Supplied > Missing
```

- Whenever a valid vector exists without a score (or with a vector-derivable score), base scores are computed via the clean-room Apache-2.0 calculator in `src/vulnparse_pin/utils/cvss_utils.py` (no LGPL `cvss` dependency).
- In `populate_enrichment_snapshots()`, CVE snapshots intentionally filter out `Scanner-Supplied` CVSS so finding-specific scanner vectors remain bound to the finding while `Scoring@3.0` (`resolve_effective_cvss_fields`) blends snapshot provenance with scanner fallback without `"Missing"` shadowing `"Scanner-Supplied"`.

## DuckDB Hydration (`populate_enrichment_snapshots`)

In `vpp scan`, `populate_enrichment_snapshots()` (`src/vulnparse_pin/app/enrichment.py`):

1. Queries `.vpp.db` for only the distinct CVEs (`finding_cves` / `findings.primary_cve`) and `package_purl`s present in the current `run_id`.
2. Hydrates KEV, EPSS v5, NVD, GHSA, OSV, and Exploit-DB records and computes source-attributed confidence (`enrichment.confidence`, `model_version: v2`).
3. Bulk-inserts snapshot rows via DuckDB `appender` into `_stg_enrich_snap` -> `INSERT OR REPLACE INTO enrichment_snapshots` and updates `runs.intel_metadata_json`.

## Integrity, Network & Inspection Controls

- **HMAC anti-downgrade:** When `VP_FEED_CACHE_HMAC_KEY` (`FeedCacheManager`) or `VP_SQLITE_HMAC_KEY` (all 5 SQLite caches) is set, plain `sha256` sidecars or unsigned pre-existing DBs fail verification closed with zero auto-resign; tampered SQLite caches are quarantined to `.tampered.<UTCSTAMP>`.
- **HTTPS streaming:** Remote fetches use `_open_https_stream` / `stream_https_get_bytes` (`allow_redirects=False` with per-hop HTTPS validation, `MAX_REMOTE_FEED_BYTES = 200 MiB`, `MAX_DECOMPRESSED_FEED_BYTES = 2 GiB`, `MAX_NVD_META_BYTES = 1 MiB`).
- **Read-only inspection:** `vpp intel status` verifies cache integrity and row counts read-only (`?mode=ro`) without mutating files or resigning caches.

## Related pages

- [Enrichment Seam Contract](Enrichment%20Seam%20Contract.md)
- [Caching Deep Dive](Caching%20Deep%20Dive.md)
- [Configs](Configs.md)
- [Security Features](Security%20Features.md)
