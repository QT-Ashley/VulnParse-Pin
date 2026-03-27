# Identity Contract

VulnParse-Pin uses deterministic identity construction to keep findings and assets stable across runs when canonical inputs are equivalent.

## Why identity contract matters

- Enables reliable deduplication and comparison workflows
- Supports reproducible scoring and ranking outputs
- Simplifies downstream joins to CMDB/ticketing/reporting systems

## Asset identity

Asset IDs are generated from canonicalized host attributes (not random UUIDs).

Conceptually:

`asset_id = hash(canonical(ip, hostname))`

Implementation resides in `src/vulnparse_pin/core/id.py`.

## Finding identity

Finding IDs are generated from canonicalized finding context, including:

- Asset identity
- Scanner signature/plugin identity
- Service tuple (protocol/port)
- Finding kind/title signal

Conceptually:

`finding_id = hash(canonical(asset_id, scanner_sig, proto, port, kind))`

## Canonicalization expectations

Normalization functions enforce stable semantics for:

- Text fields (case/spacing cleanup)
- Protocol values
- Port coercion
- Host string normalization

This minimizes accidental ID drift from formatting variation.

## Versioning

Identity generation includes versioned canonical prefixes, allowing controlled evolution while preserving compatibility boundaries.

## Contract guarantees

For equivalent canonical inputs, the resulting IDs should be identical across runs.

For materially different identity inputs, IDs should diverge.

## Non-goals

- Identity does not claim semantic equivalence across unrelated scanners without mapped signatures
- Identity does not replace historical diff logic by itself

## Integration guidance

- Persist IDs as authoritative keys in downstream systems
- Avoid recomputing IDs externally with different normalization rules
- Treat canonicalization changes as migration events requiring explicit version handling
