# Identity Contract

VulnParse-Pin v2.0.0 uses deterministic, versioned canonical identifiers (`aid_v2_` and `fid_v2_`) so assets and findings correlate reliably across multi-scanner runs, Nmap reconciliation, and scan-over-scan diffs (`vpp diff`).

Implementation resides in `src/vulnparse_pin/core/id.py`, `src/vulnparse_pin/core/assets_context.py`, and `src/vulnparse_pin/storage/repositories.py`.

## Canonical Target Keys & v2 Asset IDs (`aid_v2_`)

`canonicalize_target_key()` (`src/vulnparse_pin/core/id.py`) normalizes target attributes across IPv4/IPv6 addresses, FQDNs, URLs/URIs, container images/repositories, and explicit asset IDs:

- **IP normalization (`normalize_ip_value`):** Parses IPv4/IPv6 literals via `ipaddress.ip_address()`, strips zone IDs (`%...`), rejects placeholders (`-`, `n/a`, `none`, `unknown`, `unknown_host`), and formats compressed lowercase literals. If `hostname` is actually an IP literal, it is promoted to `ip` rather than kept as a hostname.
- **Hostname normalization (`normalize_hostname_value`):** Lowercases and strips trailing dots (`.`).
- **URI normalization (`normalize_target_uri`):** Lowercases scheme/host, strips default HTTP/WS (`80`) and HTTPS/WSS (`443`) ports, normalizes IPv6 brackets, and trims trailing slashes.
- **Image/Repo normalization (`normalize_image_or_repo`):** Normalizes registry prefixes (`index.docker.io/library/`, `registry-1.docker.io/library/`, `docker.io/library/` -> bare name; `index.docker.io/`, `registry-1.docker.io/` -> `docker.io/...`) and strips trailing `.git` / `/`.

Precedence used to construct `canonical_key`:

1. Explicit asset ID: `id=<explicit_asset_id>`
2. Container/Repo target: `image=<norm_image>[|host=<norm_host>][|ip=<norm_ip>]`
3. Host/IP target: `[host=<norm_host>][|ip=<norm_ip>]`
4. URI target: `uri=<norm_uri>`
5. Fallback: `unknown`

`make_asset_id_v2(canonical_key)` produces:

```text
aid_v2_<20-hex-sha256("vpp:asset:v2|" + canonical_key)>
```

## `AssetContextMatcher` 5-Tier Precedence (`assets.yaml`)

`AssetContextMatcher.resolve()` (`src/vulnparse_pin/core/assets_context.py`) enriches targets with inventory criticality, `internet_facing`, `owner`, `env`, `tags`, and canonical IDs using strict 5-tier precedence:

1. **Tier 1 (`alias`):** Explicit `asset_id`, rule `id`, or `aliases[]` match (normalized across IP, hostname, URI origin, and image/repo forms). If `rule.asset_id` is set, that ID is used; if `rule.aliases` is set without `asset_id`, `make_asset_id_v2(f"rule:{rule.rule_id}")` binds all aliases to one canonical asset ID.
2. **Tier 2 (`exact`):** Exact IP, exact FQDN/hostname (including URI host), exact image/repo, or exact URI match.
3. **Tier 3 (`cidr`):** Longest-prefix IPv4/IPv6 CIDR match (`-net.prefixlen`, then rule order).
4. **Tier 4 (`glob`):** Lowercased `fnmatchcase` glob match across hostnames, URIs, and images/repos, ordered by specificity (more literal characters, fewer wildcards, then rule order).
5. **Tier 5 (`unmatched`):** Unmatched targets receive `inventory_status = "unmatched_shadow"`, `match_tier = "unmatched"`, `matched_rule_id = None`, and `internet_facing = None` (allowing downstream Nmap/exposure inference while surfacing shadow assets).

## Dual-Track Finding Identity (`fid_v2_`)

`ingest_normalized_batches()` (`src/vulnparse_pin/storage/repositories.py`) assigns every finding to one of two scoring tracks and computes `make_finding_id_v2(asset_id, dedup_key)`:

```text
fid_v2_<20-hex-sha256("vpp:finding:v2|asset=" + asset_id + "|key=" + dedup_key)>
```

- **Track A (`cve_threat`):** When a valid primary CVE is present (`CVE-YYYY-NNNN+`, choosing `explicit_pcve` if valid or the sorted first normalized CVE):
  ```text
  dedup_key = "cve=" + primary_cve
  ```
- **Track B (`exposure_weakness`):** When no CVE is present (`primary_cve is None`):
  ```text
  dedup_key = "nocve|sig={sig}|svc={proto}:{port}|loc={loc}|line={line}|purl={purl}|title={norm_title}"
  ```
  where `sig` is lowercased `scanner_sig`, `loc` is `location_uri` or `target_uri`, and `norm_title` is whitespace-collapsed lowercase title (max 120 chars).

## Cross-Scanner Deduplication (`repositories.py`)

When multiple scanners (for example, Nessus XML, Trivy SARIF, and Nuclei JSONL) are ingested into the same `run_id` in `.vpp.db`:

1. Findings resolving to the same `(asset_id, dedup_key)` produce the exact same `fid_v2_` primary key.
2. `ingest_normalized_batches()` merges them into a single row in `findings`, incrementing `source_count`, setting `is_deduplicated = (source_count > 1)`, unioning `cves`, `cwes`, `ghsa_ids`, `references`, and `tags`, retaining the highest `scanner_severity` / `scanner_cvss_score`, and keeping the highest `signal_reliability`.
3. Every contributing scanner observation is preserved verbatim as a separate row in `finding_evidence` (`evidence_idx = 0, 1, ...`), and every contributing CVE across all scanners is recorded in `finding_cves`.

## Legacy v1 Compatibility IDs

`src/vulnparse_pin/core/id.py` retains `make_asset_id()` (`aid_v1_<16-hex>`) and `make_finding_id()` (`fid_v1_<16-hex>`) for legacy `ScanResult` unit tests and v1.x parser compatibility. New v2.0 `.vpp.db` pipelines always emit `aid_v2_` and `fid_v2_` identifiers.

## Contract guarantees

- Equivalent canonical inputs produce identical `aid_v2_` and `fid_v2_` IDs across runs and across supported scanners.
- Multi-scanner deduplication never discards raw scanner provenance (`finding_evidence`).
- `DiffEngine` (`vpp diff`) relies on `(asset_id, finding_id)` stability across runs in `.vpp.db`.
