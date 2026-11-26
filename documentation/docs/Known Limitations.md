# Known Limitations

This document records current architectural boundaries, operational constraints, and planned Phase 2 capabilities for VulnParse-Pin v2.0.0 (`Apache-2.0`).

## Honest Network & Operational Reachability Boundary

VulnParse-Pin's reachability and exposure model is grounded in **network & deployment context** — specifically:

- Confirmed open TCP/UDP ports from supplementary Nmap XML (`NmapAdapterPass`),
- Operator-declared `internet_facing`, `criticality`, `cidrs`, `aliases`, and `tags` from `assets.yaml` (`AssetContextMatcher`), and
- Deterministic `ACI@2.0` signal inference (`aci_signals`) and `detection_mode` Signal Reliability weighting.

VulnParse-Pin does **not** perform static AST source-code call-graph reachability analysis (determining whether a vulnerable dependency function is invoked by application code) or eBPF/kernel runtime execution tracing. Accordingly, `static_sast` findings carry a `0.55` `signal_reliability` weight and an explicit `static_sast_p1_cap` guardrail unless corroborated by high-confidence exposure/severity context.

## Parser & Input Boundaries

- **Production vs. experimental parsers:** Production workflows should use `nessus-xml`, `openvas-xml`, `qualys-xml`, `nmap-xml`, `sarif-2.1.0`, `nuclei-jsonl`, `nessus-csv`, or `qualys-csv`. The legacy JSON fallbacks (`openvas-json`, `nessus-json`) remain `experimental` and `deprecated`.
- **Size guardrails:** `FileInputValidator` caps scanner inputs at **500 MiB** by default (**50 GiB** with `--allow-large`), JSONL lines at **8 MiB**, XML prologs at **1 MiB**, and CSV fields at **32 MiB**.
- **Vendor export nuances & Nmap port-only XML:** Qualys CSV exports with more than 25 non-empty metadata preamble lines before the real header row are rejected; port-only Nmap XML passed positionally (`vpp scan nmap.xml`) produces `Informational` port exposure findings rather than CVE risk (use `--nmap nmap.xml` alongside primary scanners for exposure context). See [Detection and Parsing — Vendor Export Nuances](Detection%20and%20Parsing.md#vendor-export-nuances) for Nessus Plugin `19506`, CVSS v4.0/v3.x/v2.0 precedence, and Qualys schema details.
- **Custom scanner exports:** Vendor-customized XML/CSV schemas outside standard scanner fields may drop malformed rows or fall back to sentinel markers (`SENTINEL:No_Description`, `SENTINEL:Vector_Unavailable`).

## Enrichment & Threat-Intel Boundaries

- **CVE vs. non-CVE enrichment depth:** Track A (`cve_threat`) receives full NVD/CNA/EPSS v5/KEV/Exploit-DB/GHSA/OSV hydration. Non-CVE findings (`exposure_weakness`, Track B) rely on scanner severity, CWEs, structured tags, PURL advisory matching (where applicable), and `ACI@2.0` signals.
- **Online vs. air-gapped sync:** Online feed refreshes (`vpp intel sync` or online `vpp scan`) require outbound HTTPS access to CISA, FIRST, NVD, GitLab/Exploit-DB, or GitHub (`VP_GHSA_TK` / `GITHUB_TOKEN`). Air-gapped enclaves must pre-seed signed caches and run with `--offline` (and `--osv` / `--ghsa <path>` / `--nvd <path>` as needed).
- **No Shodan live API:** Automated Shodan enrichment is not included in v2.0.0.

## Storage, Auditability, Concurrency, & Platform Semantics

- **Single-pass vs. post-export `dossier.html` RunManifest seal:** Single-pass `vpp scan` / `vpp demo` outputs write `dossier.html` before `RunManifest` computes `output_hashes`, so inline dossiers show `Pending post-export RunManifest seal (see runmanifest.json)` (preventing circular SHA-256 self-hashing). Run `vpp export --db .vpp.db --format dossier-html -o dossier.html` after the scan to embed the sealed `sha256:...` digest.
- **`--enforce-root-read` with `$PWD` scans:** Without `--portable` (`-P`), `PermFileHandler` sets `root_dir` to the OS user data directory (`~/.local/share/VulnParse-Pin/`), so `--enforce-root-read` rejects files under `$PWD`. Pair `--enforce-root-read` with `--portable` when scanning or verifying files under `$PWD`.
- **DuckDB single-writer locking:** `.vpp.db` is a local columnar workspace optimized for single-process writes (`vpp scan`, `vpp defer`, `vpp diff`); avoid running concurrent writers against the same `.vpp.db` file simultaneously.
- **OS permission parity:** POSIX `0o600`/`0o700` file and directory mode enforcement and `umask` hardening apply on Linux and macOS. Windows deployments rely on OS NTFS ACLs rather than `chmod` bits.

## Phase 2 Planned Capabilities (`v2.1+`)

Per [ROADMAP.md](https://github.com/QT-Ashley/VulnParse-Pin/blob/main/ROADMAP.md), the following capabilities are intentionally deferred to Phase 2 (`v2.1+`) and are not part of `v2.0.0`:

- **OpenVEX & CycloneDX VEX ingestion** (`not_affected`, `affected`, `fixed`, `under_investigation` fed into `Triage@2.0` and Dossiers)
- **CMDB & cloud inventory compilers** (AWS, GCP, Azure, NetBox, ServiceNow exports -> `assets.yaml`)
- **Extended threat-intel overlays** (VulnCheck KEV++ and ENISA EUVD regional advisories)
- **Cosign OCI signatures & pre-built air-gapped wheelhouse tarballs** (`release.yml` publishes attested multi-arch `ghcr.io/qt-ashley/vulnparse-pin` images; Cosign container signatures and bundled release wheelhouse archives remain planned for `v2.1+`)
- **`vpp bundle` signed offline evidence/intel archives**
- **Federal GRC export profiles** (native eMASS and FedRAMP POA&M templates)
- **Multi-run SLA burn-down analytics, ticketing (Jira/ServiceNow), and SIEM/chat adapters** (Splunk HEC, OpenSearch, Slack, Teams, PagerDuty)

## Related pages

- [Architecture](Architecture.md)
- [Threat Model](Threat%20Model.md)
- [Detection and Parsing](Detection%20and%20Parsing.md)
- [Enrichment Deep Dive](Enrichment%20Deep%20Dive.md)
