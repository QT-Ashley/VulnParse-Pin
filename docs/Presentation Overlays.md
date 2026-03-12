# Presentation Overlays

Presentation overlays let you shape derived pass output for reporting consumers without changing core normalized scan semantics.

## Purpose

- Make pass-derived intelligence easier to consume in dashboards/reports
- Preserve compatibility with tools expecting flattened fields
- Offer namespaced mode for cleaner machine-readability

Overlay generation logic is implemented in `src/vulnparse_pin/utils/reportgen.py`.

## Overlay modes

## `flatten`

Derived values are merged into finding-level output fields for easy consumption by existing report templates.

Best for:

- Legacy consumers
- Spreadsheet/report workflows with fixed field expectations

Tradeoff:

- Greater chance of field name collision if consumers add custom keys

## `namespace`

Derived values are grouped under a dedicated namespaced object (for example, `derived`) per finding.

Best for:

- API consumers
- Long-term schema governance
- Reduced key collision risk

Tradeoff:

- Consumers must traverse nested structures

## Typical usage

Use overlay mode when generating presentation-focused artifacts for stakeholders who do not need full internal context detail.

Keep raw + derived canonical exports for system integrations and auditability.

## Recommended pattern

- Store canonical JSON as source-of-truth
- Generate overlays as downstream views
- Keep overlay mode choice documented per integration endpoint
