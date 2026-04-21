# Attack Capability Inference (ACI) Feature Explanation

This page explains what ACI is, what problem it solves, what data it uses, and how to use it responsibly in vulnerability triage workflows.

## Why ACI exists

Many environments have thousands of findings with similar CVSS and similar enrichment signals. Analysts still need a practical way to answer:

- Which findings imply meaningful attacker capability?
- Which findings combine into realistic attack pathways?
- Which assets should be triaged first when score ties exist?

ACI adds a deterministic, explainable inference layer that helps answer those questions.

Methodology note:

- VulnParse-Pin triage methodology is real-world impact probability first: prioritize findings by the highest near-term likelihood of meaningful operational impact.
- This is a default decision model, not a universal mandate. Teams should tune ACI and TopN configuration and policy to their own environment, risk appetite, compliance duties, and business goals.

## What ACI is

ACI is a derived pass (`ACI@1.0`) that:

1. Extracts normalized signals from finding evidence
2. Maps signals to capability hypotheses
3. Optionally detects multi-capability chain candidates
4. Computes bounded confidence and bounded uplift
5. Emits finding and asset semantics for downstream ranking and reporting

ACI data is stored under:

- `derived["ACI@1.0"]`

## What ACI is not

ACI is not:

- proof of exploit success
- proof of compromise
- replacement for analyst validation
- replacement for environment-specific controls assessment

The feature is designed as evidence-based decision support.

## Inputs ACI uses

ACI derives signals from existing finding context, including:

- finding title and description
- plugin output
- references
- CVE analysis text fields (`description`, `summary`, `vector`)
- exploit flags and KEV flags
- selected service port hints

Signal extraction is substring-based and normalized to lower-case semantics.

## Outputs ACI produces

### Finding semantics

For each finding, ACI can emit:

- confidence score
- confidence factors
- inferred capabilities
- chain candidates
- CWE IDs
- evidence list
- exploit boost applied
- rank uplift

### Asset semantics

For each asset, ACI can emit:

- weighted confidence
- max confidence
- capability count
- chain candidate count
- ranked finding count
- aggregate rank uplift

### Metrics snapshot

Metrics include:

- total findings
- inferred findings
- coverage ratio
- capability counts
- chain counts
- confidence bucket counts
- uplifted finding count

## How ACI affects ranking

ACI uses bounded uplift and is integrated as a ranking signal. It does not rewrite source truth.

High-level behavior:

- confidence below `min_confidence` yields no uplift
- confidence above threshold yields uplift up to `max_uplift`
- TopN uses these signals to improve ordering in near-tie situations

This keeps ACI influence controlled and auditable.

## Token vocabulary model

ACI uses a hybrid vocabulary governance model:

- Maintainer-owned core token baseline
- User-extensible aliases (`signal_aliases`)
- Optional suppression (`disabled_core_tokens`)
- Optional full replacement (`token_mode: replace`)

Benefits:

- safe defaults for broad environments
- flexibility for organization-specific language
- stable behavior unless explicitly tuned

## Capability and chain rules

### Capability rules

Capability rules map one or more signals to a capability label with a weight.

Examples of capability labels in the default policy:

- `initial_access`
- `remote_execution`
- `privilege_escalation`
- `credential_access`
- `information_disclosure`
- `persistence`
- `local_file_inclusion`
- `sql_injection`
- `auth_bypass`
- `command_execution`
- `secrets_exposure`
- `lateral_movement`

### Chain rules

Chain rules identify pathway candidates using `requires_all` capability sets.

Examples:

- initial access and credential theft pathway
- file inclusion to information disclosure pathway
- command execution to privilege escalation pathway

## Reporting behavior

Markdown reporting includes ACI-specific sections that summarize:

- ACI availability and coverage
- top inferred capabilities
- top assets mapped to findings and inferred capabilities
- chain candidate context
- explicit disclaimer that capabilities are inferred and require due diligence

This is provided in both executive and technical views.

## Guardrails and validation

ACI config is guarded by:

1. schema constraints (field shape, type, ranges)
2. semantic checks (duplicates, normalization, required arrays)

Guardrails prevent:

- malformed rule IDs
- invalid token alias entries
- out-of-range weights and confidence parameters
- empty signal or chain definitions

## Recommended adoption pattern

1. Start with default ACI policy and `enabled: true`.
2. Observe one to two scan cycles with no custom aliases.
3. Add only environment-specific aliases.
4. Tune capability weights conservatively.
5. Add chain rules for workflows you actively triage.
6. Keep runmanifest artifacts for reviewability.

## Operational value summary

ACI improves triage operations by providing:

- better ordering within dense score clusters
- explicit capability hypotheses for analyst review
- repeatable pathway hints for remediation planning
- explainable, policy-driven behavior rather than opaque scoring jumps

## Related docs

- [ACI Rule Authoring Tutorial](ACI%20Rule%20Authoring%20Tutorial.md)
- [ACI Technical Deep Dive](ACI%20Technical%20Deep%20Dive.md)
- [Output Interpretation](Output%20Interpretation.md)
- [RunManifest Overview](RunManifest.md)
