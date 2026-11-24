# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, Sequence

from vulnparse_pin.cli.errors import VppError
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


def _record_ledger_rejection(
    ctx: Any,
    *,
    subject_ref: str,
    reason_code: str,
    reason_text: str,
    factor_refs: list[str],
    evidence: dict[str, Any],
) -> None:
    services = getattr(ctx, "services", None)
    ledger = getattr(services, "ledger", None)
    if ledger is not None:
        ledger.append_event(
            component="Ingestion",
            event_type="decision",
            subject_ref=subject_ref,
            reason_code=reason_code,
            reason_text=reason_text,
            factor_refs=factor_refs,
            confidence="high",
            evidence=evidence,
        )


def validate_scanner_input(ctx: Any, scanner_input: Path, *, allow_large: bool = False) -> Path:
    """Validate scanner input file via FileInputValidator, translating SystemExit into VppError."""
    validator = FileInputValidator(ctx, scanner_input, allow_large=allow_large)
    try:
        return validator.validate()
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) and exc.code != 0 else 1
        raise VppError(f"Input validation failed for {scanner_input.name}.", exit_code=code) from exc
    except (ValueError, TypeError, OSError, RuntimeError) as exc:
        raise VppError(f"Input validation failed for {scanner_input.name}: {exc}", exit_code=1) from exc


def enforce_batch_ingestion_gates(
    ctx: Any,
    batches: Iterable[Sequence[Dict[str, Any]]],
    *,
    allow_degraded_input: bool = True,
    strict_ingestion: bool = False,
    min_ingestion_confidence: float = 0.0,
    show_ingestion_summary: bool = False,
) -> Iterator[Sequence[Dict[str, Any]]]:
    """Stream normalized batches while enforcing strict-ingestion and min-confidence gates."""
    total = 0
    degraded = 0
    below_conf = 0
    conf_sum = 0.0
    fidelity_counts: dict[str, int] = {}
    effective_allow_degraded = bool(allow_degraded_input) and (not strict_ingestion)

    for batch in batches:
        for rec in batch:
            total += 1
            tier = str(rec.get("fidelity_tier") or "unknown").lower()
            fidelity_counts[tier] = fidelity_counts.get(tier, 0) + 1

            is_degraded = bool(rec.get("degraded_input", False))
            if is_degraded:
                degraded += 1

            raw_conf = rec.get("ingestion_confidence")
            if raw_conf is None:
                conf_val = 0.0 if is_degraded else 1.0
            else:
                try:
                    conf_val = float(raw_conf)
                except (TypeError, ValueError):
                    conf_val = 0.0
            conf_sum += conf_val
            if min_ingestion_confidence > 0.0 and conf_val < min_ingestion_confidence:
                below_conf += 1

        if not effective_allow_degraded and degraded > 0:
            _record_ledger_rejection(
                ctx,
                subject_ref="ingestion:strict",
                reason_code=DecisionReasonCodes.INGESTION_STRICT_REJECTED,
                reason_text="Strict ingestion mode rejected degraded findings.",
                factor_refs=["strict_ingestion", "degraded_findings"],
                evidence={
                    "strict_ingestion": True,
                    "degraded_findings": int(degraded),
                    "total_findings": int(total),
                },
            )
            msg = f"Strict ingestion rejected degraded findings: {degraded} of {total}."
            ctx.logger.print_error(msg, label="Ingestion")
            raise VppError(msg, exit_code=1)

        if min_ingestion_confidence > 0.0 and below_conf > 0:
            _record_ledger_rejection(
                ctx,
                subject_ref="ingestion:min_confidence",
                reason_code=DecisionReasonCodes.INGESTION_CONFIDENCE_THRESHOLD_FAILED,
                reason_text="Ingestion confidence threshold check failed.",
                factor_refs=["min_ingestion_confidence", "findings_below_threshold"],
                evidence={
                    "min_ingestion_confidence": float(min_ingestion_confidence),
                    "below_threshold": int(below_conf),
                    "total_findings": int(total),
                },
            )
            msg = (
                f"Ingestion confidence threshold failed: {below_conf} findings below "
                f"{min_ingestion_confidence:.2f}."
            )
            ctx.logger.print_error(msg, label="Ingestion")
            raise VppError(msg, exit_code=1)

        yield batch

    if total > 0 and show_ingestion_summary:
        avg_conf = round(conf_sum / total, 4)
        ctx.logger.print_info(
            f"Ingestion quality: avg_conf={avg_conf:.2f} | degraded={degraded}/{total} | fidelity={fidelity_counts}",
            label="Ingestion",
        )


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

    input_file = validate_scanner_input(ctx, scanner_input, allow_large=allow_large)

    logger.phase("Normalization")
    logger.print_info("Scanning structure to determine the type of parser to use...", label="Normalization")

    scan_result = None
    try:
        det = detector.select(ctx, input_file)
        parser = det.parser_cls(ctx, input_file)
        scan_result = parser.parse()
        if not isinstance(scan_result, ScanResult):
            raise TypeError(f"Scan Object is not of valid type (ScanResult): {type(scan_result).__name__}")
        validate_scan_result_schema(scan_result)
    except (ValueError, TypeError, OSError, RuntimeError) as e:
        logger.print_error(f"Error occured while trying to determine parser to use. Msg: {e}", label="Normalization")
        raise VppError(f"Normalization failed for {input_file.name}: {e}", exit_code=1) from e

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
            _record_ledger_rejection(
                ctx,
                subject_ref="ingestion:strict",
                reason_code=DecisionReasonCodes.INGESTION_STRICT_REJECTED,
                reason_text="Strict ingestion mode rejected degraded findings.",
                factor_refs=["strict_ingestion", "degraded_findings"],
                evidence={
                    "strict_ingestion": True,
                    "degraded_findings": int(stats["degraded"]),
                    "total_findings": int(stats["total"]),
                },
            )
            msg = f"Strict ingestion rejected degraded findings: {stats['degraded']} of {stats['total']}."
            logger.print_error(msg, label="Ingestion")
            raise VppError(msg, exit_code=1)

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
                _record_ledger_rejection(
                    ctx,
                    subject_ref="ingestion:min_confidence",
                    reason_code=DecisionReasonCodes.INGESTION_CONFIDENCE_THRESHOLD_FAILED,
                    reason_text="Ingestion confidence threshold check failed.",
                    factor_refs=["min_ingestion_confidence", "findings_below_threshold"],
                    evidence={
                        "min_ingestion_confidence": float(min_ingestion_confidence),
                        "below_threshold": int(below),
                        "total_findings": int(stats["total"]),
                    },
                )
                msg = (
                    f"Ingestion confidence threshold failed: {below} findings below "
                    f"{min_ingestion_confidence:.2f}."
                )
                logger.print_error(msg, label="Ingestion")
                raise VppError(msg, exit_code=1)

    return NormalizationState(input_file=input_file, scan_result=scan_result)
