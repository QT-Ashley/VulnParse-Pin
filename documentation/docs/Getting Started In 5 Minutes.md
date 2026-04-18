# Getting Started In 5 Minutes

This guide gets you from zero to a triaged output file quickly.

## 1) Install

From terminal

```bash
pip install vulnparse-pin
```

```bash
pipx install vulnparse-pin
```

From source:

```bash
git clone https://github.com/VulnParse-Pin/VulnParse-Pin.git
cd VulnParse-Pin
```

Then from your Python environment:

```bash
pip install -e .
```

Or install from wheel if downloading a release artifact:

```bash
pip install vulnparse_pin-1.0.0-py3-none-any.whl
```

## 2) Run your first scan parse

Use a supported input format (`.nessus` / `.xml` for Nessus or OpenVAS XML):

```bash
vpp -f test.xml -o test_output.json
```

Typical options:

```bash
vpp -f input.xml -o output.json
```

## 3) Export CSV or Markdown reports for operational use

```bash
vpp test.xml -o tests_output/out.json --csv tests_output/out.csv 
```

CSV output is sanitized by default to reduce spreadsheet formula-injection risk.

Markdown reports are also available when the `Summary@1.0` pass has run:

```bash
# Executive summary report
vpp test.xml -o tests_output/out.json --output-md tests_output/report.md

# Detailed technical report
vpp test.xml -o tests_output/out.json --output-md-technical tests_output/technical.md
```

## 4) Understand what just happened

The default execution flow is:

1. Validate input and enforce path policy
2. Detect schema and choose parser
3. Normalize to internal `ScanResult`
4. Enrich findings (KEV/EPSS/NVD/Exploit-DB depending on mode)
5. Run passes (`Scoring`, `TopN`, `Summary`)
6. Write JSON/CSV/Markdown output

## 5) Read the output quickly

In output JSON, check:

- `assets` → normalized hosts
- `assets[].findings` → normalized vulnerability records
- `derived["Scoring@2.0"]` → score coverage, scored findings, and whole-of-CVEs traces
- `derived["TopN@1.0"]` → ranked assets and global top findings
- `derived["Summary@1.0"]` → operator-ready aggregates, risk-band breakdown, and top-risk findings

## Practical next steps

- Tune scoring policy in `src/vulnparse_pin/resources/scoring.json`
- Tune TopN behavior in `src/vulnparse_pin/resources/tn_triage.json`
- Review parser behavior in [Detection and Parsing](Detection%20and%20Parsing.md)
- Review pass internals in [Pipeline System](Pipeline%20System.md)

## Common first-run issues

- **Unsupported file:** ensure the input is Nessus/OpenVAS XML supported by detector
- **Import warnings in editor:** confirm VS Code is using your project `.venv`
- **Network-restricted environment:** run in offline mode if external feed access is unavailable

For upgrade differences, deeper troubleshooting, and output-reading guidance, see:

- [Upgrade and Migration](Upgrade%20and%20Migration.md)
- [Troubleshooting](Troubleshooting.md)
- [Output Interpretation](Output%20Interpretation.md)

## 5-minute checklist

- [ ] Install environment dependencies
- [ ] Run one parse command to JSON
- [ ] Export CSV
- [ ] Confirm `Scoring@2.0`, `TopN@1.0`, and `Summary@1.0` exist in output
- [ ] Adjust one scoring or triage config value and rerun
