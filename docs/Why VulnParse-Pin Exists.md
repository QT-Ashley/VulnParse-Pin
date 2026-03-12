# Why VulnParse-Pin Exists

Vulnerability programs rarely fail from lack of data. They fail from lack of usable prioritization.

VulnParse-Pin exists to make vulnerability triage deterministic, explainable, and scalable.

## The core gap

Scanner output is valuable but fragmented:

- Different tools emit different schemas
- Severity labels are not enough for remediation order
- Teams manually correlate exploitability and threat context
- Large scans overwhelm analyst bandwidth

This creates expensive delay between detection and action.

## What VulnParse-Pin changes

VulnParse-Pin converts raw scanner artifacts into a normalized, enriched, and ranked decision stream.

It does this with:

- Schema detection and parser normalization
- Intelligence enrichment (KEV, EPSS, NVD, Exploit-DB)
- Configurable scoring policy
- Top-N triage pass for asset/finding prioritization

## Design principles

- **Transparent over opaque:** scoring is policy-driven and inspectable
- **Deterministic over ad hoc:** stable identity and repeatable pass outputs
- **Secure-by-default over convenience-only:** hardened file and export handling
- **Scale-aware over best-case-only:** parallelization paths for large workloads
- **Composable over monolithic:** pass system for extension without core rewrites

## Enterprise relevance

For organizations, this means:

- Reduced triage time per scan cycle
- Better alignment to governance and audit expectations
- Consistent risk interpretation across teams and clients
- Clearer ROI from vulnerability tooling investments

## Community relevance

For contributors and researchers, this means:

- Open implementation under AGPLv3+
- Auditable internals for scoring and parser behavior
- Practical code paths for experimentation in enrichment and ranking

## Bottom line

VulnParse-Pin exists because vulnerability management needs a bridge between raw findings and operational decisions.

That bridge must be open, testable, secure, and fast enough for real-world scale.
