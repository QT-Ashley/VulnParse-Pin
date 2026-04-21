# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, TYPE_CHECKING

from vulnparse_pin.core.classes.decision_reasons import DecisionReasonCodes
from vulnparse_pin.core.classes.pass_classes import DerivedPassResult, Pass, PassMeta
from vulnparse_pin.core.passes.types import (
    ACIAssetSemantic,
    ACIFindingSemantic,
    ACIPassMetrics,
    ACIPassOutput,
)

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import Finding, RunContext, ScanResult
    from vulnparse_pin.core.passes.TopN.TN_triage_semantics import ACIConfig

_REMOTE_PORT_SIGNALS = {
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 3389, 5900, 8080, 8443
}

_REMOTE_SERVICE_ONLY_GUARDRAIL_CAPS = {"remote_execution", "initial_access"}
_PROTOCOL_ONLY_LATERAL_SIGNALS = {"smb", "ssh", "rdp", "rpc"}

_CORE_TEXT_TOKENS = {
    "initial access": "initial_access",
    "auth bypass": "auth bypass",
    "authentication bypass": "authentication bypass",
    "bypass login": "bypass login",
    "default credential": "default credential",
    "rce": "rce",
    "remote code execution": "rce",
    "command injection": "command injection",
    "cmd injection": "cmd injection",
    "os command": "os command",
    "command execution": "command execution",
    "privesc": "privesc",
    "privilege escalation": "privilege escalation",
    "sudo": "sudo",
    "setuid": "setuid",
    "kernel": "kernel",
    "credential": "credential",
    "password": "password",
    "hash": "hash",
    "info disclosure": "info disclosure",
    "information disclosure": "information disclosure",
    "sensitive data": "sensitive data",
    "leak": "leak",
    "persistence": "persistence",
    "startup": "startup",
    "autorun": "autorun",
    "scheduled task": "scheduled task",
    "service install": "service install",
    "lfi": "lfi",
    "local file inclusion": "local file inclusion",
    "path traversal": "path traversal",
    "file read": "file read",
    "etc/passwd": "etc/passwd",
    "sqli": "sqli",
    "sql injection": "sql injection",
    "union select": "union select",
    "database": "database",
    "query": "query",
    "api key": "api key",
    "token": "token",
    "secret": "secret",
    "private key": "private key",
    "hardcoded credential": "hardcoded credential",
    "smb": "smb",
    "ssh": "ssh",
    "rdp": "rdp",
    "rpc": "rpc",
    "exploit": "exploit",
}


def _effective_text_tokens(cfg: "ACIConfig") -> Dict[str, str]:
    mode = str(getattr(cfg, "token_mode", "merge") or "merge").strip().lower()
    disabled = {
        str(token).strip().lower()
        for token in (getattr(cfg, "disabled_core_tokens", ()) or ())
        if str(token).strip()
    }

    if mode == "replace":
        tokens: Dict[str, str] = {}
    else:
        tokens = {
            token: signal
            for token, signal in _CORE_TEXT_TOKENS.items()
            if token not in disabled
        }

    aliases = getattr(cfg, "signal_aliases", ()) or ()
    for item in aliases:
        if not isinstance(item, tuple) or len(item) != 2:
            continue
        token = str(item[0]).strip().lower()
        signal = str(item[1]).strip().lower()
        if token and signal:
            tokens[token] = signal

    return tokens


def _bucket_confidence(value: float) -> str:
    if value >= 0.8:
        return "high"
    if value >= 0.5:
        return "medium"
    return "low"


def _normalize_cwe(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip().upper()
    if not text:
        return None
    if text.startswith("CWE-"):
        suffix = text[4:]
        if suffix.isdigit():
            return f"CWE-{int(suffix)}"
    if text.isdigit():
        return f"CWE-{int(text)}"
    return None


def _extract_cwe_ids(finding: "Finding") -> Tuple[str, ...]:
    cwes: Set[str] = set()
    cve_analysis = getattr(finding, "cve_analysis", [])
    if not isinstance(cve_analysis, list):
        return tuple()

    for entry in cve_analysis:
        if not isinstance(entry, dict):
            continue
        cwe_ids = entry.get("cwe_ids", [])
        if isinstance(cwe_ids, list):
            for item in cwe_ids:
                normalized = _normalize_cwe(item)
                if normalized:
                    cwes.add(normalized)

        normalized_single = _normalize_cwe(entry.get("cwe_id"))
        if normalized_single:
            cwes.add(normalized_single)

    return tuple(sorted(cwes))


def _extract_signals(finding: "Finding", text_tokens: Dict[str, str]) -> Set[str]:
    signals: Set[str] = set()

    if bool(getattr(finding, "exploit_available", False)):
        signals.add("exploit")

    if bool(getattr(finding, "cisa_kev", False)):
        signals.add("kev")

    port = getattr(finding, "affected_port", None)
    if isinstance(port, int) and port in _REMOTE_PORT_SIGNALS:
        signals.add("remote_service")

    cve_analysis = getattr(finding, "cve_analysis", [])
    if isinstance(cve_analysis, list):
        for entry in cve_analysis:
            if not isinstance(entry, dict):
                continue
            if bool(entry.get("exploit_available", False)):
                signals.add("exploit")
            for field in ("description", "summary", "vector"):
                value = entry.get(field)
                if isinstance(value, str):
                    lowered = value.lower()
                    for needle, signal in text_tokens.items():
                        if needle in lowered:
                            signals.add(signal)

    for text in (
        getattr(finding, "title", None),
        getattr(finding, "description", None),
        getattr(finding, "plugin_output", None),
    ):
        if isinstance(text, str):
            lowered = text.lower()
            for needle, signal in text_tokens.items():
                if needle in lowered:
                    signals.add(signal)

    references = getattr(finding, "references", [])
    if isinstance(references, list):
        for ref in references:
            if not isinstance(ref, str):
                continue
            lowered = ref.lower()
            for needle, signal in text_tokens.items():
                if needle in lowered:
                    signals.add(signal)

    return signals


def _has_exploit_for_confidence(finding: "Finding") -> bool:
    if bool(getattr(finding, "exploit_available", False)):
        return True
    cve_analysis = getattr(finding, "cve_analysis", [])
    if isinstance(cve_analysis, list):
        for entry in cve_analysis:
            if isinstance(entry, dict) and bool(entry.get("exploit_available", False)):
                return True
    return False


class AttackCapabilityInferencePass(Pass):
    name = "ACI"
    version = "1.0"
    requires_passes: tuple[str, ...] = ("Scoring@2.0",)

    def __init__(self, aci_config: "ACIConfig") -> None:
        self.cfg = aci_config

    def _iter_findings(self, scan: "ScanResult") -> Iterable[Tuple[str, "Finding"]]:
        for asset in scan.assets:
            asset_id = getattr(asset, "asset_id", None)
            for finding in asset.findings:
                fid = getattr(finding, "finding_id", None)
                if not fid:
                    continue
                resolved_asset_id = str(getattr(finding, "asset_id", None) or asset_id or "")
                if not resolved_asset_id:
                    continue
                yield resolved_asset_id, finding

    def run(self, ctx: "RunContext", scan: "ScanResult") -> DerivedPassResult:
        text_tokens = _effective_text_tokens(self.cfg)
        finding_semantics: Dict[str, ACIFindingSemantic] = {}
        asset_rollups: Dict[str, List[ACIFindingSemantic]] = {}

        capability_counts: Dict[str, int] = {}
        chain_counts: Dict[str, int] = {}
        confidence_buckets = {"low": 0, "medium": 0, "high": 0}

        total_findings = 0
        inferred_findings = 0
        uplifted_findings = 0

        for asset_id, finding in self._iter_findings(scan):
            total_findings += 1
            finding_id = str(getattr(finding, "finding_id", ""))
            signals = _extract_signals(finding, text_tokens)

            matched_caps: List[str] = []
            confidence_factors: List[str] = []
            capability_weight_max: Dict[str, float] = {}

            for rule in self.cfg.capability_rules:
                if not rule.enabled:
                    continue
                matched_rule_signals = {sig for sig in rule.signals if sig in signals}
                if matched_rule_signals:
                    if (
                        rule.capability in _REMOTE_SERVICE_ONLY_GUARDRAIL_CAPS
                        and matched_rule_signals == {"remote_service"}
                    ):
                        continue
                    if (
                        rule.capability == "lateral_movement"
                        and matched_rule_signals.issubset(_PROTOCOL_ONLY_LATERAL_SIGNALS)
                    ):
                        continue
                    matched_caps.append(rule.capability)
                    current = capability_weight_max.get(rule.capability, 0.0)
                    capability_weight_max[rule.capability] = max(current, float(rule.weight))
                    confidence_factors.append(f"capability_rule:{rule.rule_id}")

            confidence_base = sum(capability_weight_max.values())
            confidence_base = min(1.0, confidence_base)

            exploit_bonus = 0.0
            if self.cfg.exploit_boost.enabled and _has_exploit_for_confidence(finding):
                exploit_bonus = min(
                    float(self.cfg.exploit_boost.max_bonus),
                    float(self.cfg.exploit_boost.weight) * max(0.0, confidence_base),
                )
                if exploit_bonus > 0.0:
                    confidence_factors.append("exploit_boost")

            confidence = min(1.0, confidence_base + exploit_bonus)

            chains: List[str] = []
            matched_set = set(matched_caps)
            for rule in self.cfg.chain_rules:
                if not rule.enabled:
                    continue
                if set(rule.requires_all).issubset(matched_set):
                    chains.append(rule.label)
                    chain_counts[rule.rule_id] = chain_counts.get(rule.rule_id, 0) + 1

            cwe_ids = _extract_cwe_ids(finding)

            if confidence >= float(self.cfg.min_confidence):
                denom = max(0.000001, 1.0 - float(self.cfg.min_confidence))
                rank_uplift = float(self.cfg.max_uplift) * ((confidence - float(self.cfg.min_confidence)) / denom)
            else:
                rank_uplift = 0.0

            rank_uplift = max(0.0, min(float(self.cfg.max_uplift), rank_uplift))

            evidence: List[str] = []
            for cap in sorted(set(matched_caps)):
                capability_counts[cap] = capability_counts.get(cap, 0) + 1
                evidence.append(f"capability:{cap}")
            for chain in chains:
                evidence.append(f"chain:{chain}")
            for signal in sorted(signals):
                evidence.append(f"signal:{signal}")
            for cwe in cwe_ids:
                evidence.append(f"cwe:{cwe}")

            if matched_caps and confidence >= float(self.cfg.min_confidence):
                inferred_findings += 1
            if rank_uplift > 0:
                uplifted_findings += 1

            bucket = _bucket_confidence(confidence)
            confidence_buckets[bucket] = confidence_buckets.get(bucket, 0) + 1

            semantic = ACIFindingSemantic(
                finding_id=finding_id,
                asset_id=asset_id,
                confidence=round(confidence, 4),
                confidence_factors=tuple(sorted(set(confidence_factors))),
                capabilities=tuple(sorted(set(matched_caps))),
                chain_candidates=tuple(sorted(set(chains))),
                cwe_ids=cwe_ids,
                evidence=tuple(sorted(set(evidence))),
                exploit_boost_applied=round(exploit_bonus, 4),
                rank_uplift=round(rank_uplift, 4),
            )

            finding_semantics[finding_id] = semantic
            asset_rollups.setdefault(asset_id, []).append(semantic)

        asset_semantics: Dict[str, ACIAssetSemantic] = {}
        for asset_id, rows in asset_rollups.items():
            if not rows:
                continue
            total_confidence = sum(r.confidence for r in rows)
            max_conf = max(r.confidence for r in rows)
            avg_conf = total_confidence / len(rows)
            capability_union: Set[str] = set()
            chain_total = 0
            total_uplift = 0.0
            for row in rows:
                capability_union.update(row.capabilities)
                chain_total += len(row.chain_candidates)
                total_uplift += row.rank_uplift

            rank_uplift = min(
                float(self.cfg.max_uplift),
                total_uplift * float(self.cfg.asset_uplift_weight),
            )

            asset_semantics[asset_id] = ACIAssetSemantic(
                asset_id=asset_id,
                weighted_confidence=round(avg_conf, 4),
                max_confidence=round(max_conf, 4),
                capability_count=len(capability_union),
                chain_candidate_count=chain_total,
                ranked_finding_count=len(rows),
                rank_uplift=round(rank_uplift, 4),
            )

        coverage_ratio = (float(inferred_findings) / float(total_findings)) if total_findings else 0.0
        output = ACIPassOutput(
            finding_semantics=finding_semantics,
            asset_semantics=asset_semantics,
            metrics=ACIPassMetrics(
                total_findings=total_findings,
                inferred_findings=inferred_findings,
                coverage_ratio=round(coverage_ratio, 4),
                capabilities_detected=dict(sorted(capability_counts.items())),
                chain_candidates_detected=dict(sorted(chain_counts.items())),
                confidence_buckets=confidence_buckets,
                uplifted_findings=uplifted_findings,
            ),
        )

        ledger = getattr(getattr(ctx, "services", None), "ledger", None)
        if ledger is not None:
            ledger.append_event(
                component="ACI",
                event_type="decision",
                subject_ref="aci:summary",
                reason_code=DecisionReasonCodes.ACI_INFERENCE_SUMMARY,
                reason_text="Attack capability inference summary computed.",
                factor_refs=["aci.enabled", "aci.min_confidence", "aci.max_uplift"],
                evidence={
                    "enabled": bool(self.cfg.enabled),
                    "total_findings": total_findings,
                    "inferred_findings": inferred_findings,
                    "uplifted_findings": uplifted_findings,
                },
            )

            preview_limit = min(10, len(finding_semantics))
            for semantic in list(finding_semantics.values())[:preview_limit]:
                if not semantic.capabilities:
                    continue
                ledger.append_event(
                    component="ACI",
                    event_type="decision",
                    subject_ref=f"finding:{semantic.finding_id}",
                    reason_code=DecisionReasonCodes.ACI_FINDING_INFERRED,
                    reason_text="Attack capability inferred for finding.",
                    factor_refs=["aci.capability_rules", "aci.chain_rules", "aci.exploit_boost"],
                    confidence=_bucket_confidence(semantic.confidence),
                    evidence={
                        "asset_id": semantic.asset_id,
                        "confidence": semantic.confidence,
                        "capabilities": list(semantic.capabilities),
                        "chain_candidates": list(semantic.chain_candidates),
                        "rank_uplift": semantic.rank_uplift,
                    },
                )

        meta = PassMeta(
            name=self.name,
            version=self.version,
            created_at_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            notes="Derived Attack Capability Inference output.",
        )
        return DerivedPassResult(meta=meta, data=asdict(output))
