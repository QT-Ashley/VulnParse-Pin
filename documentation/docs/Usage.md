# Usage

Listed below are the detailed usage instructions for VulnParse-Pin. This guide will help you understand how to use the tool effectively to analyze vulnerabilities.

Here are example usage instructions for VulnParse-Pin. For detailed installation instructions, please refer to the [Installation Guide](Installation.md).

For version transitions and operations guidance, also see:

- [Upgrade and Migration](Upgrade%20and%20Migration.md)
- [Troubleshooting](Troubleshooting.md)
- [Output Interpretation](Output%20Interpretation.md)

## Basic Usage

To run VulnParse-Pin, use the following command in your terminal:

```bash
vpp -f <input_file> -o <output_file>
```

Where:

- `<input_file>` is the path to the input file containing vulnerability data. This file should be in a supported format (e.g., JSON, CSV) and contain the necessary information for analysis.

- `<output_file>` is the path where the output will be saved. The output will contain the parsed and analyzed vulnerability data.

## Additional Options

VulnParse-Pin also supports additional options to customize the analysis process. Here are some of the available options:

### General Options

#### --demo

- `--demo`: Runs the packaged full-pipeline demo profile using OpenVAS XML + Nmap context with GHSA online budget defaults. Use it like this:

```bash
vpp --demo
```

Demo profile defaults:

- Input file: packaged `openvas_updated_test.xml` (15 assets / 2,000 findings)
- Nmap context: packaged `base_test_nmap.xml`
- GHSA mode: forced online (`--ghsa online` semantics)
- GHSA budget: forced to `25`
- Enrichment: KEV/EPSS/Exploit enabled, NVD enabled
- Artifacts: JSON, CSV, executive markdown, technical markdown, runmanifest

#### --pretty-print

- `--pretty-print [-pp]`: This option formats the output in a more human-readable way. It can be used as follows:

```bash
vpp -f <input_file> -o <output_file> --pretty-print
```

#### --version

- `--version [-v]`: This option displays the current version of VulnParse-Pin. Use it like this:

```bash
vpp --version
```

#### --help

- `--help [-h]`: This option provides a help message with information about the available commands and options. You can access it with:

```bash
vpp --help
```

#### --log-file

- `--log-file [-Lf] <log_file>`: This option allows you to specify a log file where the tool will write its logs. Use it as follows:

```bash
vpp -f <input_file> -o <output_file> --log-file <log_file>
```

#### --log-level

- `--log-level [-Ll] <log_level>`: This option sets the logging level (e.g., DEBUG, INFO, WARNING, ERROR). Use it like this:

```bash
vpp -f <input_file> -o <output_file> --log-level DEBUG
```

### Enrichment Options

Enrichment defaults to enabled + online for KEV, EPSS, and Exploit-DB.

Use disable flags to turn a source off, and source flags to switch to offline cache/file mode.

#### --nmap-ctx

- `--nmap-ctx [-nmap] <path>`: Supply a Nmap XML file as supplementary attack-surface context. When provided, the Nmap adapter pass maps confirmed open ports to scan assets and makes port evidence available to downstream scoring and ranking passes. This flag is opt-in only; omitting it disables the adapter entirely.

```bash
vpp -f scan.nessus -o results.json --nmap-ctx nmap_results.xml
```

The file must have a `.xml` extension and be a valid Nmap `nmaprun` XML file. Policy controls for this feature are in `config.yaml` under `nmap_ctx`. See [Nmap Context Deep Dive](Nmap%20Context%20Deep%20Dive.md) for full details.

#### --no-kev

- `--no-kev`: Disable KEV enrichment.

```bash
vpp -f <input_file> -o <output_file> --no-kev
```

#### --no-epss

- `--no-epss`: Disable EPSS enrichment.

```bash
vpp -f <input_file> -o <output_file> --no-epss
```

#### --no-exploit

- `--no-exploit`: Disable Exploit-DB enrichment.

```bash
vpp -f <input_file> -o <output_file> --no-exploit
```

#### --kev-source

- `--kev-source <online|offline>`: Select KEV source mode. Default is `online`.

```bash
vpp -f <input_file> -o <output_file> --kev-source offline
```

#### --epss-source

- `--epss-source <online|offline>`: Select EPSS source mode. Default is `online`.

```bash
vpp -f <input_file> -o <output_file> --epss-source offline
```

#### --kev-feed

- `--kev-feed <PATH|URL>`: Optional KEV feed override.

```bash
vpp -f <input_file> -o <output_file> --kev-feed https://example.org/kev.json
```

#### --epss-feed

- `--epss-feed <PATH|URL>`: Optional EPSS feed override.

```bash
vpp -f <input_file> -o <output_file> --epss-feed https://example.org/epss.csv.gz
```

#### --exploit-source

- `--exploit-source [-es] <source>`: This option allows you to specify the feed source for exploit enrichment. The available sources are `online` and `offline`. (Default: online) Use it as follows:

```bash
vpp -f <input_file> -o <output_file> --exploit-source online
```

#### --exploit-db

- `--exploit-db [-edb] <path>`: This option allows you to specify the path to the local Exploit Database for offline enrichment. Use it like this:

```bash
vpp -f <input_file> -o <output_file> --exploit-db /path/to/exploit-db
```

#### --ghsa

- `--ghsa [PATH|online]`: Enable GitHub Security Advisory (GHSA) enrichment. Use bare `--ghsa` for online mode (queries the GitHub Advisories API) or `--ghsa <path>` for offline mode pointing to a local advisory database directory. GHSA enrichment is disabled by default — this flag is the only activation path at runtime.

```bash
# Online mode
vpp -f scan.nessus -o results.json --ghsa

# Offline mode
vpp -f scan.nessus -o results.json --ghsa /path/to/advisory-database
```

#### --ghsa-budget

- `--ghsa-budget <COUNT>`: Override the online GHSA prefetch CVE budget. Applies only when `--ghsa` is in online mode. Must be a positive integer. Config default is `25` (set via `enrichment.ghsa_online_prefetch_budget` in `config.yaml`).

```bash
vpp -f scan.nessus -o results.json --ghsa --ghsa-budget 50
```

#### --refresh-cache

- `--refresh-cache`: This option forces the tool to refresh its cache during enrichment. This will ensure that the latest data is used for enrichment. Use it like this:

```bash
vpp -f <input_file> -o <output_file> --refresh-cache
```

#### --allow-regen

- `--allow-regen`: This option allows the tool to regenerate checksum data during offline enrichment if necessary using best-effort. Use it as follows:

```bash
vpp -f <input_file> -o <output_file> --allow-regen
```

#### --no-nvd

- `--no-nvd`: This option disables the use of the National Vulnerability Database (NVD) for enrichment. Use it like this:

```bash
vpp -f <input_file> -o <output_file> --no-nvd
```

### Ingestion Quality Options

Use these flags to control how strictly VulnParse-Pin accepts degraded parser input (for example constrained CSV exports):

#### --allow-degraded-input / --no-allow-degraded-input

- `--allow-degraded-input` (default) allows degraded findings to pass normalization.
- `--no-allow-degraded-input` rejects runs that contain degraded findings.

```bash
vpp -f <input_file> -o <output_file> --no-allow-degraded-input
```

#### --strict-ingestion

- `--strict-ingestion`: strict gate that rejects any degraded findings. This flag overrides `--allow-degraded-input`.

```bash
vpp -f <input_file> -o <output_file> --strict-ingestion
```

#### --min-ingestion-confidence

- `--min-ingestion-confidence <0.0-1.0>`: reject the run if any finding's ingestion confidence is below the threshold.

```bash
vpp -f <input_file> -o <output_file> --min-ingestion-confidence 0.60
```

#### --show-ingestion-summary

- `--show-ingestion-summary`: print ingestion quality summary metrics (average confidence, degraded counts, fidelity distribution).

```bash
vpp -f <input_file> -o <output_file> --show-ingestion-summary
```

### Output Options

#### --output

- `--output [-o] <output_file>`: This option specifies the path where the output will be saved. The output will contain the parsed and analyzed vulnerability data. Use it as follows:

```bash
vpp -f <input_file> --output <output_file>
```

#### --output-csv

- `--output-csv [-oC] <csv_file>`: This option allows you to specify a CSV file where the output will be saved in CSV format. Use it like this:

```bash
vpp -f <input_file> --output-csv <csv_file>
```

#### --csv-profile

- `--csv-profile <full|analyst|audit>`: Selects the CSV presentation profile.
  - `full` (default): backward-compatible full schema for existing pipelines.
  - `analyst`: triage-focused view with high-value operational fields.
  - `audit`: traceability-focused view with contributor and aggregation context.

```bash
# Full legacy-compatible output
vpp -f <input_file> --output-csv out.csv --csv-profile full

# Analyst triage sheet
vpp -f <input_file> --output-csv out_analyst.csv --csv-profile analyst

# Audit traceability sheet
vpp -f <input_file> --output-csv out_audit.csv --csv-profile audit
```

Note: non-default profiles require `--output-csv`.

#### --webhook-endpoint

- `--webhook-endpoint <HTTPS_URL>`: Send a signed webhook event for the run to a specific HTTPS endpoint. This is a one-off runtime override and does not require editing config files.

```bash
set VP_WEBHOOK_HMAC_KEY=replace_with_strong_random_secret
vpp -f scan.nessus -o results.json --webhook-endpoint https://hooks.example.org/vpp
```

#### --webhook-oal-filter

- `--webhook-oal-filter <all|P1|P1b|P2>`: Restrict webhook `top_findings` payload content to one Operational Action Lane. Use with `--webhook-endpoint`.

```bash
vpp -f scan.nessus -o results.json --webhook-endpoint https://hooks.example.org/vpp --webhook-oal-filter P1
```

#### Persistent webhook config (config.yaml)

Use the `webhook` block in `src/vulnparse_pin/resources/config.yaml` for persistent endpoint delivery.

```yaml
webhook:
  enabled: true
  signing_key_env: VP_WEBHOOK_HMAC_KEY
  key_id: primary
  timeout_seconds: 5
  connect_timeout_seconds: 3
  read_timeout_seconds: 5
  max_retries: 2
  max_payload_bytes: 262144
  replay_window_seconds: 300
  allow_spool: true
  spool_subdir: webhook_spool
  endpoints:
    - url: https://hooks.example.org/vpp
      enabled: true
      oal_filter: all
      format: generic
```

#### --output-md

- `--output-md [-oM] <md_file>`: This option allows you to specify a Markdown file where the output will be saved in Markdown format. This type of output is useful for generating human-readable reports for executives or stakeholders. Use it as follows:

```bash
vpp -f <input_file> --output-md <md_file>
```

#### --output-md-technical

- `--output-md-technical [-oMT] <md_tech_file>`: This option allows you to specify a Markdown file where the output will be saved in a technical format. This type of output is useful for generating detailed reports for technical teams. Use it like this:

```bash
vpp -f <input_file> --output-md-technical <md_tech_file>
```

#### --output-runmanifest

- `--output-runmanifest [-oRM] <runmanifest_file>`: Emit a RunManifest JSON artifact that captures run metadata, pass metrics, and the embedded decision ledger.

```bash
vpp -f <input_file> --output-runmanifest runmanifest.json
```

#### --runmanifest-mode

- `--runmanifest-mode <compact|expanded>`: Controls decision detail volume in the RunManifest. `compact` is default and optimized for routine operations; `expanded` includes richer decision detail for investigations.

```bash
vpp -f <input_file> --output-runmanifest runmanifest.json --runmanifest-mode expanded
```

#### --verify-runmanifest

- `--verify-runmanifest <runmanifest_file>`: Validate an existing RunManifest file (schema + integrity chain + manifest digest) and exit without running the parsing/enrichment pipeline.

```bash
vpp --verify-runmanifest runmanifest.json
```

#### RunManifest auditability best practice

For auditable workflows, treat RunManifest as untrusted until verified.

- Verify immediately after the pipeline writes it.
- Verify again before trust actions (sharing, ticket evidence, compliance review, or archival as final evidence).

Example post-run verification pattern:

```bash
vpp -f <input_file> -o <output_file> --output-runmanifest runmanifest.json
vpp --verify-runmanifest runmanifest.json
```

#### --presentation

- `--presentation <mode>`: This option allows you to specify a presentation mode where the output is formatted for presentation purposes. This is useful for generating reports that are easy to read and understand and SIEM ingestion pipelines. Use it as follows:

```bash
vpp -f <input_file> -o <output_file> --presentation <mode>
```

#### --overlay-mode

- `--overlay-mode <mode>`: This option allows you to specify an overlay mode where the output is formatted for overlay purposes. This is useful for generating reports that can be easily overlaid on top of other data sources. The following options are available: `namespace`, `flatten`. (Default: flatten) Use it like this:

```bash
vpp -f <input_file> -o <output_file> --presentation --overlay-mode <mode>
```

### Operational and Security Options

#### --allow-large

- `--allow-large [-al]`: This option allows the tool to process large input files that may exceed typical size limits. Use it as follows:

```bash
vpp -f <input_file> -o <output_file> --allow-large
```

#### --no-csv-sanitize

- `--no-csv-sanitize [-ncC]`: This option disables the sanitization of CSV output, which may be necessary for certain use cases where special characters are present. This may present a security risk. Use it like this:

```bash
vpp -f <input_file> --output-csv <csv_file> --no-csv-sanitize
```

#### --forbid-symlinks-read

- `--forbid-symlinks-read [-Sr]`: This option prevents the tool from following symbolic links when reading input files, which can help mitigate certain security risks. Use it as follows:

```bash
vpp -f <input_file> -o <output_file> --forbid-symlinks-read
```

#### --forbid-symlinks-write

- `--forbid-symlinks-write [-Sw]`: This option prevents the tool from following symbolic links when writing output files, which can help mitigate certain security risks. Use it like this:

```bash
vpp -f <input_file> -o <output_file> --forbid-symlinks-write
```

#### --enforce-root-read

- `--enforce-root-read [-err]`: This option enforces read operations only on files within the list of acceptable root directories. This can help mitigate certain security risks by preventing unauthorized access to files outside of the specified directories. Use it as follows:

```bash
vpp -f <input_file> -o <output_file> --enforce-root-read
```

#### --enforce-root-write

- `--enforce-root-write [-erw]`: This option enforces write operations only on files within the list of acceptable root directories. This can help mitigate certain security risks by preventing unauthorized writing to files outside of the specified directories. (Default: True) Use it like this:

```bash
vpp -f <input_file> -o <output_file> --enforce-root-write
```

#### --file-mode

- `--file-mode [-fm] <mode>`: This option sets the file mode for output files, which can help mitigate certain security risks by controlling the permissions of the generated files. (POSIX-only) Use it as follows:

```bash
vpp -f <input_file> -o <output_file> --file-mode 0644
```

#### --dir-mode

- `--dir-mode [-dm] <mode>`: This option sets the directory mode for output directories, which can help mitigate certain security risks by controlling the permissions of the generated directories. (POSIX-only) Use it like this:

```bash
vpp -f <input_file> -o <output_file> --dir-mode 0755
```

#### --debug-path-policy

- `--debug-path-policy`: This option displays debug output for path policy enforcement, which can help you understand how the tool is enforcing path-related security policies. Use it as follows:

```bash
vpp --debug-path-policy
```

#### --portable

- `--portable [-P]`: This option enables portable mode, which ensures that the tool operates in a manner compatible with different environments and file systems. This will store application data next to the executable. Use it like this:

```bash
vpp -f <input_file> -o <output_file> --portable
```

## Examples

Here are some example commands to illustrate how to use VulnParse-Pin with various options:

```bash

# Basic usage with pretty print
vpp -f vulnerabilities.xml -o output.json --pretty-print

# Enrichment is enabled by default (KEV + EPSS + Exploit)
vpp -f vulnerabilities.xml -o enriched_output.json

# Disable specific enrichments
vpp -f vulnerabilities.xml -o enriched_output.json --no-kev --no-epss

# Output in CSV format with custom log file
vpp -f vulnerabilities.xml --output-csv output.csv --log-file vpp.log

# Enrichment with exploit database and refresh cache
vpp -f vulnerabilities.xml -o enriched_output.json --refresh-cache

# Enrichment with exploit database using offline source
vpp -f vulnerabilities.xml -o enriched_output.json --exploit-source offline --exploit-db /path/to/exploit-db

# KEV and EPSS using offline cache/files
vpp -f vulnerabilities.xml -o enriched_output.json --kev-source offline --epss-source offline

# Output in Markdown format for technical report
vpp -f vulnerabilities.xml --output-md-technical technical_report.md

# Emit RunManifest in default compact mode
vpp -f vulnerabilities.xml -o output.json --output-runmanifest runmanifest.json

# Emit RunManifest in expanded mode for deeper investigation
vpp -f vulnerabilities.xml -o output.json --output-runmanifest runmanifest.json --runmanifest-mode expanded

# Verify existing RunManifest without re-running scan
vpp --verify-runmanifest runmanifest.json

# Enrichment with KEV and EPSS, output in presentation mode with overlay
vpp -f vulnerabilities.xml -o presentation_output.json --presentation --overlay-mode namespace
```
