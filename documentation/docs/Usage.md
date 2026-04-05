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
- `--demo`: This option runs the tool in demo mode, which uses a predefined dataset to demonstrate the capabilities of VulnParse-Pin. Use it like this:

```bash
vpp --demo
```

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