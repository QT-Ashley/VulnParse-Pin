# Configs

VulnParse-Pin configuration is split into three primary policy files.

## Configuration files

- `src/vulnparse_pin/resources/config.yaml`
- `src/vulnparse_pin/resources/scoring.json`
- `src/vulnparse_pin/resources/tn_triage.json`

At runtime, defaults are copied into the active app config area if user versions are missing.

## `config.yaml`

Controls feed/cache and runtime data behavior.

Typical sections:

- `feed_cache.defaults.ttl_hours`
- Per-feed TTL overrides (`kev`, `epss`, `exploit_db`, `nvd_yearly`, `nvd_modified`)
- `feeds.nvd` options such as enablement, year range, SQLite protections

Operationally important fields:

- NVD start/end year (controls ingestion breadth)
- SQLite row cap and max age
- SQLite file permission policy where supported

## `scoring.json`

Defines scoring policy behavior, including:

- EPSS scaling factor
- Evidence points/weights (KEV, exploit, etc.)
- Risk band thresholds
- Operational weighting coefficients

Use this file to align risk output with your organization’s tolerance and remediation policy.

### Scoring semantics (important)

- `Finding Risk (Raw)` is a composite finding-level score used for ranking findings/CVEs.
- `Asset Risk Score` is an aggregate over findings (currently max-based in policy).
- These are not the same metric and should not be compared as if they are equivalent.

Current scoring model combines:

- CVSS contribution
- EPSS contribution (`epss * scale`, with `epss_high` / `epss_medium` multipliers)
- KEV evidence contribution (`kev` points * `w_kev`)
- Exploit evidence contribution (`exploit` points * `w_exploit`)

With default policy values, a finding can legitimately exceed 15 raw points.
Example worst-case shape:

- CVSS `7.5`
- EPSS high contribution `0.9417 * 10 * 0.96 = 9.04`
- KEV contribution `6 * 1.2 = 7.2`
- Exploit contribution `7 * 1.37 = 9.59`
- Raw total `≈ 33.33`

`max_raw_risk` is used as a normalization divisor for operational score scaling; it does not hard-cap raw score itself.
Operational score is then clamped to `max_operational_risk`.

### March 2026 tuned profile rationale

Validated final tuning (balanced exploit-first posture):

- `evidence_points.kev = 2.5`
- `bands.critical = 13.35`
- `weights.epss_high = 0.6`
- `weights.epss_medium = 0.4`

Observed behavior on representative large validation (100k OpenVAS regression sample):

- Reduced over-classification in upper bands (notably `High` inflation)
- Preserved exploit/KEV prioritization and top-CVE ordering
- Kept a narrow urgent set while moving borderline findings into lower operational tiers

This profile is intended for teams that want strong prioritization of known-exploited risk while avoiding broad “everything is urgent” output.

#### Current Scoring Profile (March 2026)

VulnParse-Pin now uses a **balanced, exploit-first** risk model (validated on 100k+ record samples):

- Strong prioritization of known-exploited vulnerabilities (CISA KEV, public exploits)
- Reduced over-classification in upper risk bands - focuses analyst effort on urgent, actionable items
- Preserves exploit-driven ordering for consistent triage workflow


## `tn_triage.json`

Controls TopN ranking and inference behavior:

- Rank basis (`raw` and policy-driven options)
- `k` and decay configuration for top findings contribution
- Max assets and findings per asset output limits
- Exposure inference rules and confidence thresholds

This file is where triage prioritization style is tuned.

## Path modes and config location behavior

Path and config directory behavior is resolved through `src/vulnparse_pin/core/apppaths.py`.

- System mode (default): platform-specific app-data location
- Portable mode: project-local data tree for self-contained execution

## Safe configuration workflow

1. Copy defaults and commit baseline policy files
2. Tune one parameter group at a time
3. Re-run representative datasets
4. Compare score coverage and TopN output changes
5. Lock validated policy in version control

## Configuration governance guidance

- Treat config changes as risk-policy changes
- Require review for scoring threshold adjustments
- Keep benchmark baselines when tuning performance-related options
- Document rationale for production policy deviations
