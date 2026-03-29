# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.
from __future__ import annotations
from typing import TYPE_CHECKING, Sequence, Tuple, Any, Type, Optional, Callable
from pathlib import Path
from dataclasses import dataclass


if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext

# Parser Spec
@dataclass(frozen=True)
class ParserSpec:
    name: str
    parser_cls: Type[Any]
    formats: Tuple[str]
    scanner: str                        # "openvas" | "nessus" | "unknown"
    priority: int = 100                 # lower = preferred tie-breaker
    detect_file: Optional[Callable[[Any, Path], DetectionResult]] = None

@dataclass(frozen=True)
class DetectionResult:
    parser_name: str
    parser_cls: Type[Any]
    matched: bool
    confidence: float
    format: str
    scanner: str
    evidence: tuple[DetectionEvidence, ...] = ()
    error: Optional[str] = None

@dataclass(frozen=True)
class DetectionEvidence:
    key: str
    value: str

# Schema Detector
class SchemaDetector:
    def __init__(self, specs: Sequence[ParserSpec]):
        self._specs = list(specs)

        # Priority mapping
        self._priority: dict[str, int] = {
            spec.name: spec.priority for spec in self._specs
        }

        # Helper for name -> spec
        self._spec_by_name: dict[str, ParserSpec] = {
            spec.name: spec for spec in self._specs
        }

    def select(self, ctx, path: Path) -> DetectionResult:
        path = Path(path)
        path = ctx.pfh.ensure_readable_file(path, label="Input file", log = False)

        # Cheap sniff first (format)
        sniff = self._sniff_format(ctx, path) # Lightweight sniffer

        candidates = [s for s in self._specs if sniff in s.formats or sniff == "unknown"]
        results: list[DetectionResult] = []

        for spec in candidates:
            try:
                if spec.detect_file is None:
                    # Fallback: Call parser classmethod detect_file if present
                    det = self._call_parser_detect_file(ctx, spec, path, sniff)
                else:
                    det = spec.detect_file(ctx, path)

                results.append(det)

            except Exception as e:
                ctx.logger.debug("Detector error for %s", spec.name, exc_info=True)
                results.append(DetectionResult(
                    parser_name=spec.name,
                    parser_cls=spec.parser_cls,
                    matched=False,
                    confidence=0.0,
                    format=sniff,
                    scanner=spec.scanner,
                    evidence=(),
                    error=str(e)
                ))

        winner = self._pick_winner(results)

        # Log decision trail
        self._log_decision(ctx, path, sniff, results, winner)

        if not winner.matched:
            raise ValueError(f"No parser matched input: {path.name}")

        return winner

    def _sniff_format(self, ctx, path: Path) -> str:
        # Small data read only here.
        with ctx.pfh.open_for_read(path, mode="rb", label="Input File", log = False) as f:
            head = f.read(4096)
        # Strip UTF-8 BOM then leading whitespace before inspecting first byte
        head = head.lstrip(b"\xef\xbb\xbf").lstrip()

        if head.startswith(b"{") or head.startswith(b"["):
            return "json"
        if head.startswith(b"<"):
            return "xml"
        return "unknown"

    def _call_parser_detect_file(self, ctx, spec: ParserSpec, path: Path, sniff: str) -> DetectionResult:
        p = spec.parser_cls
        # If parser implements classmethod detect_file, call it
        if hasattr(p, "detect_file"):
            result = p.detect_file(path)
            # Parsers may return (confidence, evidence_pairs) tuple or legacy bool
            if isinstance(result, tuple) and len(result) == 2:
                confidence = float(result[0])
                evidence = tuple(
                    DetectionEvidence(str(k), str(v)) for k, v in result[1]
                )
            else:
                # Legacy bool return — treat True as 0.9
                confidence = 0.9 if result else 0.0
                evidence = (DetectionEvidence("detect_file", "true" if result else "false"),)
            return DetectionResult(
                parser_name=spec.name,
                parser_cls=p,
                matched=confidence >= 0.50,
                confidence=confidence,
                format=sniff,
                scanner=spec.scanner,
                evidence=evidence,
            )
        return DetectionResult(
            parser_name=spec.name,
            parser_cls=p,
            matched=False,
            confidence=0.0,
            format=sniff,
            scanner=spec.scanner,
            evidence=(DetectionEvidence("detect_file", "missing"),),
        )

    def _pick_winner(self, results: list[DetectionResult]) -> DetectionResult:
        """
        Winner: Highest confidence;
        Ties: Parser Priority;
        Then Stable Name

        :param self: Description
        :param results: Description
        :type results: list[DetectionResult]
        :return: Description
        :rtype: DetectionResult
        """
        matched = [r for r in results if r.matched]
        if not matched:
            # Return "best stats failure" for logging, but not matched
            return max(results, key=lambda r: r.confidence, default=DetectionResult(
                parser_name="none",
                parser_cls=object,
                matched=False,
                confidence=0.0,
                format="unknown",
                scanner="unknown",
            ))
        def sort_key(r: DetectionResult):
            return (
                r.confidence,
                -self._priority.get(r.parser_name, 1000),
                r.parser_name,
            )
        # If multiple matched, pick highest conf, then priority
        return max(matched, key=sort_key)

    def _log_decision(self, ctx, path: Path, sniff: str, all_results: list[DetectionResult], winner: DetectionResult) -> None:
        ctx.logger.debug("SchemaDetector: sniff=%s file=%s", sniff, path.name)
        for r in all_results:
            ctx.logger.debug(
                "candidate=%s, matched=%s, confidence=%.2f, error=%s evidence=%s",
                r.parser_name, r.matched, r.confidence, r.error, [(e.key, e.value) for e in r.evidence],
            )

        if winner.matched:
            ctx.logger.print_success(
                f"Detected parser: {winner.parser_name} (format={winner.format}, confidence={winner.confidence:.2f})", label = "Normalization",
            )
