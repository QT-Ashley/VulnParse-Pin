# ACI Rule Authoring Tutorial

This tutorial shows how to design, configure, validate, and inspect Attack Capability Inference (`ACI@2.0`) rules in VulnParse-Pin v2.0.

Use this guide when you want to:

- Configure ACI capability and chain rules in `tn_triage.json`
- Tune triage/reliability interactions in `config.yaml`
- Extend the token vocabulary with `signal_aliases` or suppress noisy core tokens
- Run `vpp scan` and inspect `ACI@2.0` signals in JSON, CSV, `vpp ui`, and Decision Defense Dossiers

## Where Configuration Lives

1. **`tn_triage.json` (`aci` section):** Controls `enabled`, `min_confidence`, `max_uplift`, `asset_uplift_weight`, `token_mode`, `signal_aliases`, `disabled_core_tokens`, `exploit_boost`, `capability_rules`, and `chain_rules`.
2. **`config.yaml` (`triage` and `signal_reliability` sections):** Controls `triage.static_sast_p1_cap` (whether ACI/CWE corroboration is required to lift `static_sast` findings into `P1`) and per-`detection_mode` `signal_reliability` weights that govern how `Scoring@3.0` Track B (`exposure_weakness`) scales ACI capability bonuses.

Runtime validation layers:

1. JSON Schema Draft 2020-12 validation (`topN.schema.json`, `config.schema.json`)
2. Semantic validation (`TN_triage_semantics.py`, `config_validator.py`)

If validation fails under strict config checks, startup fails; in non-strict mode, safe packaged defaults are used.

## Step 1: Review `aci` Defaults in `tn_triage.json`

`ACI@2.0` is enabled by default in v2.0.0:

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

Recommended starting ranges:

- `min_confidence`: `0.5–0.7` (default `0.6`)
- `max_uplift`: `1.0–2.0` (default `2.0`)
- `asset_uplift_weight`: `0.3–0.6` (default `0.5`)

## Step 2: Add or Tune a Capability Rule

Capability rules map normalized signals (extracted from finding text, structured tags, CWEs, and `scanner_sig` rule IDs) to a capability label:

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

- Keep `id` stable, lowercase, and unique.
- Use normalized lowercase `signals`.
- Keep `weight` in `[0.0, 1.0]`.
- Note built-in precision guardrails in `aci_pass.py`:
  - `remote_service` alone (open port without other signals) will **not** trigger `remote_execution` or `initial_access`.
  - Protocol-only signals (`smb`, `ssh`, `rdp`, `rpc`) will **not** trigger `lateral_movement` without exploit, KEV, credential, or lateral context keywords.
- Keep `Scoring@3.0` Track B alignment in mind: capabilities in `{remote_execution, command_execution, auth_bypass, sql_injection, privilege_escalation, initial_access, deserialization, ssrf}` grant `+3.5` Track B `aci_high_impact_bonus` before `signal_reliability` scaling; other capabilities grant `+2.0`.

## Step 3: Add a Chain Rule

Chain rules detect multi-step attack pathways when all `requires_all` capabilities are inferred on a finding:

```json
{
  "id": "chain_initial_to_privesc",
  "enabled": true,
  "requires_all": ["remote_execution", "privilege_escalation"],
  "label": "Initial access to privilege escalation pathway"
}
```

In `Triage@2.0`, findings with matched `aci_chains` automatically qualify for at least `P2` (`Attend`, `60-day` in `bod-26-04`; `14-day` in `default`), and in Track B (`exposure_weakness`) they receive `+1.0` `aci_chain_bonus`.

## Step 4: Extend or Trim the Token Vocabulary

### Add Custom Aliases (`merge` mode, recommended)

```json
"token_mode": "merge",
"signal_aliases": [
  { "token": "acme edge rce", "signal": "rce" },
  { "token": "vault dump", "signal": "credential" },
  { "token": "service auto-start", "signal": "persistence" }
]
```

### Disable Noisy Core Tokens

```json
"disabled_core_tokens": [
  "database",
  "query"
]
```

### Full Replacement (`replace` mode, advanced)

```json
"token_mode": "replace",
"signal_aliases": [
  { "token": "acme-rce-marker", "signal": "rce" },
  { "token": "acme-auth-bypass", "signal": "auth bypass" }
]
```

> [!WARNING]
> Setting `token_mode: "replace"` suppresses core text tokens, extended text tokens, structured Nuclei/SARIF tag mappings, CWE mappings, and `_EXTRA_CAPABILITY_SIGNALS` (`deserialization`, `ssrf`, `panel`, `misconfig`, `exposure`, `xss`) so only your explicit `signal_aliases` and `capability_rules` apply.

## Step 5: Run a Scan and Inspect ACI Outputs

Run an offline v2.0 scan across any supported scanner input (Nessus, OpenVAS, Qualys, SARIF, Nuclei JSONL) into a `.vpp.db` workspace and export artifacts:

```bash
vpp scan scan.nessus \
  --offline --no-kev --no-epss --no-exploit --no-nvd \
  --db workspace.vpp.db \
  --output-all out/aci_tutorial \
  --pretty-print
```

Or run the built-in offline multi-scanner demo (`demo.nessus` + `demo_trivy.sarif` + `demo_nuclei.jsonl` + `demo_semgrep.sarif`):

```bash
vpp demo --no-ui --profile bod-26-04 --output-dir out/demo_aci
```

### Inspect Where ACI@2.0 Surfaces

1. **Interactive TUI (`vpp ui --db workspace.vpp.db`):** Select any finding to view `ACI Caps` and `ACI Chains` in the right-hand inspector pane.
2. **Decision Defense Dossier (`out/aci_tutorial_dossier.md` / `.html` or `vpp export --format dossier-md`):** Prioritized findings display `ACI Signals: capabilities=[...]; chains=[...]; confidence=...; uplift=...`.
3. **JSON (`out/aci_tutorial.json`):** Under `namespace` overlay mode (default), inspect `assets[].findings[].derived["ACI@2.0"]` (`capabilities`, `chains`, `matched_tokens`, `confidence`, `uplift_score`) and `score_trace.aci_capabilities` / `score_trace.aci_chains`.
4. **CSV (`out/aci_tutorial.csv`):** `full` and `audit` profiles export `aci_capabilities`, `aci_chains`, `aci_confidence`, and `aci_uplift_score`.
5. **DuckDB SQL:** Query `aci_signals` directly (`SELECT finding_id, capabilities_json, chains_json, confidence, uplift_score FROM aci_signals`).

## Core Token Reference

In `merge` mode, `aci_pass.py` evaluates:

- **Core text tokens (`_CORE_TEXT_TOKENS`):**
  - Initial access & execution: `initial access`, `auth bypass`, `authentication bypass`, `bypass login`, `default credential`, `rce`, `remote code execution`, `command injection`, `cmd injection`, `os command`, `command execution`, `exploit`
  - Privilege escalation: `privesc`, `privilege escalation`, `sudo`, `setuid`, `kernel`
  - Credential & secret access: `credential`, `password`, `hash`, `api key`, `token`, `secret`, `private key`, `hardcoded credential`
  - Disclosure & inclusion: `info disclosure`, `information disclosure`, `sensitive data`, `leak`, `lfi`, `local file inclusion`, `path traversal`, `file read`, `etc/passwd`
  - SQL & data plane: `sqli`, `sql injection`, `union select`, `database`, `query`
  - Persistence & lateral movement: `persistence`, `startup`, `autorun`, `scheduled task`, `service install`, `smb`, `ssh`, `rdp`, `rpc`
- **Extended text tokens (`_EXTENDED_TEXT_TOKENS`):** `deserialization`, `unsafe deserialization`, `ssrf`, `server-side request forgery`, `default-login`, `auth-bypass`, `misconfig`, `misconfiguration`, `admin panel`, `login panel`
- **Structured tags & `scanner_sig` rule hints (`_STRUCTURED_TAG_SIGNALS`, `_scan_sig`):** Nuclei tags (e.g. `default-login`, `panel`, `exposure`, `misconfig`, `ssrf`, `xss`, `hardcoded-secret`), Semgrep/CodeQL/Trivy rule IDs, and CWE mappings (`CWE-22`, `CWE-77`, `CWE-78`, `CWE-79`, `CWE-89`, `CWE-94`, `CWE-200`, `CWE-250`, `CWE-269`, `CWE-287`, `CWE-306`, `CWE-434`, `CWE-502`, `CWE-522`, `CWE-798`, `CWE-918`).

## Related Docs

- [ACI Feature Explanation](ACI%20Feature%20Explanation.md)
- [ACI Technical Deep Dive](ACI%20Technical%20Deep%20Dive.md)
- [Configs](Configs.md)
- [Scoring and Prioritization Deep Dive](Scoring%20and%20Prioritization%20Deep%20Dive.md)
- [Output Interpretation](Output%20Interpretation.md)
- [RunManifest Technical Deep Dive](RunManifest_Technical.md)
