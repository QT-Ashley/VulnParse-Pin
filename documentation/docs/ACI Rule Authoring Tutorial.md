# ACI Rule Authoring Tutorial

This tutorial shows how to design, implement, validate, and inspect Attack Capability Inference (ACI) rules in VulnParse-Pin.

Use this guide when you want to:

- Enable ACI for ranking support
- Add or tune capability and chain rules
- Extend token vocabulary safely
- Verify your changes in output artifacts

## What ACI does

ACI is a derived pass that infers likely attacker capabilities from finding evidence, then contributes bounded rank uplift used by TopN as a tie-break signal.

Important behavior:

- ACI never mutates raw scanner truth
- ACI emits versioned derived output at `derived["ACI@1.0"]`
- TopN consumes ACI signals during ordering
- Uplift is bounded by policy (`max_uplift`)

## Where to edit rules

Primary config file:

- `src/vulnparse_pin/resources/tn_triage.json`

ACI section path:

- `aci`

Runtime validation layers:

1. JSON schema validation (`topN.schema.json`)
2. Semantic validation (`TN_triage_semantics.py`)

If validation fails in strict mode, startup fails. In non-strict mode, a safe fallback is used.

## Step 1: Enable ACI

In `tn_triage.json`:

```json
"aci": {
  "enabled": true,
  "min_confidence": 0.6,
  "max_uplift": 2.0,
  "asset_uplift_weight": 0.5,
  "token_mode": "merge",
  "signal_aliases": [],
  "disabled_core_tokens": [],
  "exploit_boost": {
    "enabled": true,
    "weight": 0.25,
    "max_bonus": 0.2
  },
  "capability_rules": [],
  "chain_rules": []
}
```

Recommended starting values:

- `min_confidence`: `0.5-0.7`
- `max_uplift`: `1.0-2.0`
- `asset_uplift_weight`: `0.3-0.6`

## Step 2: Add a capability rule

Capability rules map observed signals to a capability label.

Example:

```json
{
  "id": "cap_remote_execution",
  "enabled": true,
  "capability": "remote_execution",
  "signals": ["exploit", "remote_service", "rce"],
  "weight": 0.85
}
```

Authoring checklist:

- Rule `id` is stable, lowercase, and unique
- `capability` is a normalized label you will reuse in chains
- `signals` are lower-case normalized terms
- `weight` is in `[0.0, 1.0]`

Design tip:

- Start with specific signals first, then broaden only after checking precision in outputs.

## Step 3: Add a chain rule

Chain rules infer multi-step pathways when required capabilities are all present.

Example:

```json
{
  "id": "chain_initial_to_privesc",
  "enabled": true,
  "requires_all": ["remote_execution", "privilege_escalation"],
  "label": "Initial access to privilege escalation pathway"
}
```

Authoring checklist:

- `requires_all` must reference existing capability labels
- Use concise labels that analysts can read quickly
- Keep chain labels decision-oriented (pathway language)

## Step 4: Extend vocabulary with aliases

ACI supports a hybrid token model:

- Maintainer-managed core tokens are always available in `merge` mode
- User aliases can be added in config
- Specific core tokens can be disabled if noisy
- Full replacement is available with `token_mode: "replace"`

### Add aliases (recommended)

```json
"token_mode": "merge",
"signal_aliases": [
  { "token": "acme edge rce", "signal": "rce" },
  { "token": "vault dump", "signal": "credential" },
  { "token": "service auto-start", "signal": "persistence" }
]
```

### Disable noisy core tokens

```json
"disabled_core_tokens": [
  "database",
  "query"
]
```

### Replace mode (advanced)

```json
"token_mode": "replace",
"signal_aliases": [
  { "token": "acme-rce-marker", "signal": "rce" },
  { "token": "acme-auth-bypass", "signal": "auth bypass" }
]
```

Use `replace` only when you fully control vocabulary quality and coverage.

## Step 5: Validate and run

Run an offline-friendly pass to inspect effects:

```bash
vpp -P -f tests_output/mock_openvas.json \
  --no-kev --no-epss --no-exploit --no-nvd \
  -oA tests_output/aci_tutorial \
  -oRM tests_output/aci_tutorial_runmanifest.json -pp
```

Generated artifacts:

- `tests_output/aci_tutorial.json`
- `tests_output/aci_tutorial_summary.md`
- `tests_output/aci_tutorial_technical.md`
- `tests_output/aci_tutorial_runmanifest.json`

## Step 6: Inspect output

### ACI pass output

Inspect:

- `derived["ACI@1.0"].metrics`
- `derived["ACI@1.0"].finding_semantics`
- `derived["ACI@1.0"].asset_semantics`

Look for:

- coverage ratio
- uplifted finding count
- capability distribution
- chain candidate distribution

### TopN output

Inspect:

- `derived["TopN@1.0"].findings_by_asset`
- `derived["TopN@1.0"].assets`

Look for tie-break reasons that mention ACI uplift.

### Markdown output

Executive and technical reports include:

- ACI metrics snapshot
- Top capability signals
- Top asset mapping from findings to inferred capabilities
- Explicit disclaimer that capabilities are inferred and require analyst due diligence

## Core token reference

The default core token vocabulary is maintained in code and used when `token_mode` is `merge`.

### Initial access and execution

- `initial access`
- `auth bypass`
- `authentication bypass`
- `bypass login`
- `default credential`
- `rce`
- `remote code execution`
- `command injection`
- `cmd injection`
- `os command`
- `command execution`
- `exploit`

### Privilege escalation

- `privesc`
- `privilege escalation`
- `sudo`
- `setuid`
- `kernel`

### Credential and secret access

- `credential`
- `password`
- `hash`
- `api key`
- `token`
- `secret`
- `private key`
- `hardcoded credential`

### Disclosure and inclusion

- `info disclosure`
- `information disclosure`
- `sensitive data`
- `leak`
- `exposure`
- `lfi`
- `local file inclusion`
- `path traversal`
- `file read`
- `etc/passwd`

### SQL and data-plane signals

- `sqli`
- `sql injection`
- `union select`
- `database`
- `query`

### Persistence and movement

- `persistence`
- `startup`
- `autorun`
- `scheduled task`
- `service install`
- `smb`
- `ssh`
- `rdp`
- `rpc`

## Tuning strategy that works

1. Enable ACI with conservative uplift.
2. Add one capability rule at a time.
3. Validate chain rules after capability quality is stable.
4. Add aliases for your environment-specific language.
5. Disable only proven noisy tokens.
6. Keep a before/after output pair for regression review.

## Common mistakes

1. Overweighting broad rules (`weight` too high) causes many low-signal findings to uplift.
2. Using `replace` mode too early removes useful defaults.
3. Adding chain rules before capability labels are stable creates noisy pathways.
4. Treating inferred capabilities as confirmed compromise.

## Safety and interpretation

ACI is decision support. It is not an incident verdict.

Always pair ACI outputs with:

- source evidence review
- exploitability context
- environment-specific validation

## Related docs

- [Configs](Configs.md)
- [Scoring and Prioritization Deep Dive](Scoring%20and%20Prioritization%20Deep%20Dive.md)
- [Output Interpretation](Output%20Interpretation.md)
- [RunManifest Technical Deep Dive](RunManifest_Technical.md)
