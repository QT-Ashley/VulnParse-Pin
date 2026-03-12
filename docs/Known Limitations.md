# Known Limitations

This document tracks current boundaries and non-goals for VulnParse-Pin v1.0.0rc.1.

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

- Extended enrichment features (for example, planned Shodan-related enrichments)
- Additional strict schema/policy validation pathways
- Further parser parity for non-XML formats

## Operational caveats

- Disabling safe defaults (path confinement, CSV sanitization) increases risk
- Using unsupported or malformed input can produce reduced enrichment fidelity
- Process-pool behavior requires pickle-safe worker payload discipline

## Documentation note

Limitations here are transparent by design so teams can plan controls, capacity, and integration strategy realistically.
