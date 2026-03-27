# Known Limitations

This document tracks current boundaries and non-goals for VulnParse-Pin v1.0.0.

## Parser coverage limits

- Production-grade paths focus on Nessus/OpenVAS XML parser flows
- JSON parser implementations are present but marked experimental
- Non-standard or heavily vendor-customized exports may require parser extension work

## Data and model limits

- No built-in historical delta analysis across multiple scan generations
- Identity model is primarily host/service/plugin oriented
- Enrichment is strongest for CVE-referenced findings

## Performance/size guardrails

- Default size protections prioritize safety over unrestricted ingestion
- Extremely large inputs can shift bottlenecks to scoring and serialization
- Runtime characteristics depend on CVE cardinality, not only finding count

## Platform-specific behavior

- POSIX-style file mode enforcement is strongest on Linux/macOS
- Windows permission semantics rely on OS ACL model, not chmod parity

## Feature backlog indicators

Current codebase TODO markers include areas such as:

- **Shodan enrichment** (deferred to post-1.0) — placeholder at src/vulnparse_pin/utils/enricher.py; full implementation planned for v1.1+
- **Extended enrichment features** — additional threat intel integrations and vendor-specific enrichment modes
- **Additional strict schema/policy validation pathways** — full contract validation will be tightened in future releases
- **Further parser parity for non-XML formats** — JSON parsers are experimental; post-1.0 parity improvements planned

All deferred features are explicit non-blockers for v1.0.0 stability and API contract completion.

## Operational caveats

- Disabling safe defaults (path confinement, CSV sanitization) increases risk
- Using unsupported or malformed input can produce reduced enrichment fidelity
- Process-pool behavior requires pickle-safe worker payload discipline

## Documentation note

Limitations here are transparent by design so teams can plan controls, capacity, and integration strategy realistically.
