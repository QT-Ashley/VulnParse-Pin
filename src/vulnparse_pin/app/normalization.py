# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Any

from vulnparse_pin.core.classes.decision_reasons import DecisionReasonCodes
from vulnparse_pin.core.classes.dataclass import ScanResult
from vulnparse_pin.utils.schema_validate import validate_scan_result_schema
from vulnparse_pin.utils.validations import FileInputValidator


@dataclass(frozen=True)
class NormalizationState:
    input_file: Path
    scan_result: ScanResult


def _collect_ingestion_stats(scan_result: ScanResult) -> dict[str, Any]:
    total = 0
    degraded = 0
    low_conf = 0
    conf_sum = 0.0
    fidelity_counts: dict[str, int] = {}

    for asset in scan_result.assets:
        for finding in asset.findings:
            total += 1
            tier = str(getattr(finding, "fidelity_tier", "unknown") or "unknown").lower()
            fidelity_counts[tier] = fidelity_counts.get(tier, 0) + 1

            is_degraded = bool(getattr(finding, "degraded_input", False))
            if is_degraded:
                degraded += 1

            raw_conf = getattr(finding, "ingestion_confidence", None)
            try:
                conf = float(raw_conf)
            except (TypeError, ValueError):
                conf = 0.0 if is_degraded else 1.0
            conf_sum += conf

    avg_conf = (conf_sum / total) if total > 0 else 0.0
    return {
        "total": total,
        "degraded": degraded,
        "avg_conf": round(avg_conf, 4),
        "fidelity": fidelity_counts,
        "low_conf": low_conf,
    }


def normalize_input(
    ctx,
    detector,
    scanner_input: Path,
    allow_large: bool,
    *,
    allow_degraded_input: bool = True,
    strict_ingestion: bool = False,
    min_ingestion_confidence: float = 0.0,
    show_ingestion_summary: bool = False,
) -> NormalizationState:
    logger = ctx.logger

    logger.print_info(f"Loading file: {scanner_input.name}", label="Target File")

    input_file = scanner_input

    validator = FileInputValidator(ctx, input_file, allow_large=allow_large)
    try:
        input_file = validator.validate()
    except (ValueError, TypeError, OSError, RuntimeError):
        sys.exit(1)

    logger.phase("Normalization")
    logger.print_info("Scanning structure to determine the type of parser to use...", label="Normalization")

    scan_result = None
    try:
        det = detector.select(ctx, input_file)
        parser = det.parser_cls(ctx, input_file)
        scan_result = parser.parse()
        try:
            assert isinstance(scan_result, ScanResult)
        except (ValueError, TypeError) as exc:
            raise TypeError(f"Scan Object does is not of valid type(ScanResult), Trace: {exc}") from exc
        validate_scan_result_schema(scan_result)
    except (ValueError, TypeError, OSError, RuntimeError) as e:
        logger.print_error(f"Error occured while trying to determine parser to use. Msg: {e}", label="Normalization")
        return sys.exit(1)

    logger.print_success(
        f"Parsed {len(scan_result.assets)} assets, {sum(len(a.findings) for a in scan_result.assets)} findings",
        label="Normalization",
    )

    stats = _collect_ingestion_stats(scan_result)
    if stats["total"] > 0:
        if show_ingestion_summary:
            logger.print_info(
                f"Ingestion quality: avg_conf={stats['avg_conf']:.2f} | degraded={stats['degraded']}/{stats['total']} | fidelity={stats['fidelity']}",
                label="Ingestion",
            )

        effective_allow_degraded = bool(allow_degraded_input) and (not strict_ingestion)
        if not effective_allow_degraded and stats["degraded"] > 0:
            services = getattr(ctx, "services", None)
            ledger = getattr(services, "ledger", None)
            if ledger is not None:
                ledger.append_event(
                    component="Ingestion",
                    event_type="decision",
                    subject_ref="ingestion:strict",
                    reason_code=DecisionReasonCodes.INGESTION_STRICT_REJECTED,
                    reason_text="Strict ingestion mode rejected degraded findings.",
                    factor_refs=["strict_ingestion", "degraded_findings"],
                    confidence="high",
                    evidence={
                        "strict_ingestion": True,
                        "degraded_findings": int(stats["degraded"]),
                        "total_findings": int(stats["total"]),
                    },
                )
            logger.print_error(
                f"Strict ingestion rejected degraded findings: {stats['degraded']} of {stats['total']}.",
                label="Ingestion",
            )
            return sys.exit(1)

        if min_ingestion_confidence > 0.0:
            below = 0
            for asset in scan_result.assets:
                for finding in asset.findings:
                    conf = getattr(finding, "ingestion_confidence", None)
                    if conf is None:
                        conf_val = 0.0 if bool(getattr(finding, "degraded_input", False)) else 1.0
                    else:
                        try:
                            conf_val = float(conf)
                        except (TypeError, ValueError):
                            conf_val = 0.0
                    if conf_val < min_ingestion_confidence:
                        below += 1
            if below > 0:
                services = getattr(ctx, "services", None)
                ledger = getattr(services, "ledger", None)
                if ledger is not None:
                    ledger.append_event(
                        component="Ingestion",
                        event_type="decision",
                        subject_ref="ingestion:min_confidence",
                        reason_code=DecisionReasonCodes.INGESTION_CONFIDENCE_THRESHOLD_FAILED,
                        reason_text="Ingestion confidence threshold check failed.",
                        factor_refs=["min_ingestion_confidence", "findings_below_threshold"],
                        confidence="high",
                        evidence={
                            "min_ingestion_confidence": float(min_ingestion_confidence),
                            "below_threshold": int(below),
                            "total_findings": int(stats["total"]),
                        },
                    )
                logger.print_error(
                    f"Ingestion confidence threshold failed: {below} findings below {min_ingestion_confidence:.2f}.",
                    label="Ingestion",
                )
                return sys.exit(1)

    return NormalizationState(input_file=input_file, scan_result=scan_result)
