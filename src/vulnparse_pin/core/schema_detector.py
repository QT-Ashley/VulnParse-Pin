# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from dataclasses import dataclass
import inspect
import json
from pathlib import Path
from typing import Any, Callable, Optional, Sequence, Tuple, Type

if False:  # TYPE_CHECKING
    from vulnparse_pin.core.classes.dataclass import RunContext


_SNIFF_READ_BYTES = 65_536


@dataclass(frozen=True)
class ParserSpec:
    name: str
    parser_cls: Type[Any]
    formats: Tuple[str, ...]
    scanner: str                        # "openvas" | "nessus" | "qualys" | "nmap" | "sarif" | "nuclei" | "unknown"
    priority: int = 100                 # lower = preferred tie-breaker
    stability: str = "stable"           # stable | experimental
    deprecated: bool = False
    deprecation_notice: Optional[str] = None
    detect_file: Optional[Callable[[Any, Path], DetectionResult]] = None


@dataclass(frozen=True)
class DetectionResult:
    parser_name: str
    parser_cls: Type[Any]
    matched: bool
    confidence: float
    format: str
    scanner: str
    stability: str = "stable"
    deprecated: bool = False
    evidence: tuple[DetectionEvidence, ...] = ()
    error: Optional[str] = None


@dataclass(frozen=True)
class DetectionEvidence:
    key: str
    value: str


class SchemaDetector:
    def __init__(self, specs: Sequence[ParserSpec]):
        self._specs = list(specs)
        self._priority: dict[str, int] = {spec.name: spec.priority for spec in self._specs}
        self._spec_by_name: dict[str, ParserSpec] = {spec.name: spec for spec in self._specs}

    def select(self, ctx, path: Path, allow_large: Optional[bool] = None) -> DetectionResult:
        path = Path(path)
        path = ctx.pfh.ensure_readable_file(path, label="Input file", log=False)

        # Single bounded 64 KB read via ctx.pfh.open_for_read(...)
        if type(self)._sniff_format is SchemaDetector._sniff_format and "_sniff_format" not in self.__dict__:
            head_bytes = self._read_head_bytes(ctx, path)
            sniff = self._classify_head_bytes(head_bytes, path)
        else:
            head_bytes = None
            sniff = self._sniff_format(ctx, path)

        candidates = [s for s in self._specs if sniff in s.formats or sniff == "unknown"]
        results: list[DetectionResult] = []

        for spec in candidates:
            try:
                if spec.detect_file is None:
                    det = self._call_parser_detect_file(
                        ctx,
                        spec,
                        path,
                        sniff,
                        allow_large=allow_large,
                        head_bytes=head_bytes,
                    )
                else:
                    det = spec.detect_file(ctx, path)
                results.append(det)
            except Exception as e:
                ctx.logger.debug("Detector error for %s", spec.name, exc_info=True)
                results.append(
                    DetectionResult(
                        parser_name=spec.name,
                        parser_cls=spec.parser_cls,
                        matched=False,
                        confidence=0.0,
                        format=sniff,
                        scanner=spec.scanner,
                        stability=spec.stability,
                        deprecated=spec.deprecated,
                        evidence=(),
                        error=str(e),
                    )
                )

        winner = self._pick_winner(results)
        self._log_decision(ctx, path, sniff, results, winner)

        if not winner.matched:
            raise ValueError(f"No parser matched input: {path.name}")

        winner_spec = self._spec_by_name.get(winner.parser_name)
        if winner_spec is not None and (winner_spec.deprecated or winner_spec.stability == "experimental"):
            msg = (
                f"Parser '{winner.parser_name}' is marked {winner_spec.stability}"
                f"{' and deprecated' if winner_spec.deprecated else ''}."
            )
            if winner_spec.deprecation_notice:
                msg += f" {winner_spec.deprecation_notice}"
            if hasattr(ctx.logger, "print_warning"):
                ctx.logger.print_warning(msg, label="Normalization")
            else:
                ctx.logger.warning(msg)

        return winner

    def _read_head_bytes(self, ctx, path: Path) -> bytes:
        with ctx.pfh.open_for_read(path, mode="rb", label="Input File", log=False) as f:
            return f.read(_SNIFF_READ_BYTES)

    def _sniff_format(self, ctx, path: Path) -> str:
        head = self._read_head_bytes(ctx, path)
        return self._classify_head_bytes(head, path)

    @staticmethod
    def _classify_head_bytes(raw_head: bytes, path: Path) -> str:
        if not raw_head:
            return "unknown"

        # Handle UTF-16 BOM XML before UTF-8 BOM check
        if raw_head.startswith((b"\xff\xfe", b"\xfe\xff")):
            try:
                decoded = raw_head.decode("utf-16", errors="ignore").lstrip()
                if decoded.startswith("<"):
                    return "xml"
            except Exception:
                pass

        # Strip UTF-8 BOM cleanly (exact prefix, never lstrip character class) then leading whitespace
        if raw_head.startswith(b"\xef\xbb\xbf"):
            head = raw_head[3:].lstrip()
        else:
            head = raw_head.lstrip()

        if not head:
            return "unknown"

        if head.startswith(b"<"):
            return "xml"

        suffix = Path(path).suffix.lower()

        if head.startswith(b"{"):
            # Distinguish JSONL vs SARIF vs JSON within the 64 KB head
            non_empty_lines = [ln.strip() for ln in head.splitlines() if ln.strip()]
            if suffix in {".jsonl", ".ndjson"}:
                return "jsonl"

            if non_empty_lines:
                first_line = non_empty_lines[0]
                if len(non_empty_lines) >= 2 and non_empty_lines[1].startswith(b"{"):
                    try:
                        first_obj = json.loads(first_line.decode("utf-8"))
                        if isinstance(first_obj, dict):
                            return "jsonl"
                    except Exception:
                        pass
                elif len(non_empty_lines) == 1:
                    try:
                        first_obj = json.loads(first_line.decode("utf-8"))
                        if (
                            isinstance(first_obj, dict)
                            and "template-id" in first_obj
                            and isinstance(first_obj.get("info"), dict)
                        ):
                            return "jsonl"
                    except Exception:
                        pass

            lowered = head.lower()
            if suffix == ".sarif":
                return "sarif"
            if b'"runs"' in head and (
                b'"2.1.0"' in head
                or b"sarif" in lowered
                or (b'"tool"' in head and b'"driver"' in head)
            ):
                return "sarif"
            return "json"

        if head.startswith(b"["):
            return "json"

        has_row_break = b"\n" in head or b"\r" in head
        has_csv_delim = any(d in head for d in (b",", b";", b"\t", b"|"))
        if b"\x00" not in head and has_csv_delim and (has_row_break or suffix == ".csv"):
            return "csv"

        return "unknown"

    def _call_parser_detect_file(
        self,
        ctx,
        spec: ParserSpec,
        path: Path,
        sniff: str,
        *,
        allow_large: Optional[bool] = None,
        head_bytes: Optional[bytes] = None,
    ) -> DetectionResult:
        p = spec.parser_cls
        if hasattr(p, "detect_file"):
            fn = p.detect_file
            kwargs: dict[str, Any] = {}
            try:
                sig = inspect.signature(fn)
                params = sig.parameters
                accepts_var_kw = any(
                    param.kind == inspect.Parameter.VAR_KEYWORD for param in params.values()
                )
                if accepts_var_kw or "ctx" in params:
                    kwargs["ctx"] = ctx
                if accepts_var_kw or "allow_large" in params:
                    kwargs["allow_large"] = allow_large
                if head_bytes is not None and (accepts_var_kw or "head_bytes" in params):
                    kwargs["head_bytes"] = head_bytes
            except (TypeError, ValueError):
                kwargs = {}

            result = fn(path, **kwargs) if kwargs else fn(path)
            if isinstance(result, tuple) and len(result) == 2:
                confidence = float(result[0])
                evidence = tuple(DetectionEvidence(str(k), str(v)) for k, v in result[1])
            else:
                confidence = 0.9 if result else 0.0
                evidence = (DetectionEvidence("detect_file", "true" if result else "false"),)
            return DetectionResult(
                parser_name=spec.name,
                parser_cls=p,
                matched=confidence >= 0.50,
                confidence=confidence,
                format=sniff,
                scanner=spec.scanner,
                stability=spec.stability,
                deprecated=spec.deprecated,
                evidence=evidence,
            )
        return DetectionResult(
            parser_name=spec.name,
            parser_cls=p,
            matched=False,
            confidence=0.0,
            format=sniff,
            scanner=spec.scanner,
            stability=spec.stability,
            deprecated=spec.deprecated,
            evidence=(DetectionEvidence("detect_file", "missing"),),
        )

    def _pick_winner(self, results: list[DetectionResult]) -> DetectionResult:
        """
        Winner: Highest confidence;
        Ties: Parser Priority;
        Then Stable Name
        """
        matched = [r for r in results if r.matched]
        if not matched:
            return max(
                results,
                key=lambda r: r.confidence,
                default=DetectionResult(
                    parser_name="none",
                    parser_cls=object,
                    matched=False,
                    confidence=0.0,
                    format="unknown",
                    scanner="unknown",
                    stability="stable",
                    deprecated=False,
                ),
            )

        def sort_key(r: DetectionResult):
            return (
                r.confidence,
                -self._priority.get(r.parser_name, 1000),
                r.parser_name,
            )

        return max(matched, key=sort_key)

    def _log_decision(
        self,
        ctx,
        path: Path,
        sniff: str,
        all_results: list[DetectionResult],
        winner: DetectionResult,
    ) -> None:
        ctx.logger.debug("SchemaDetector: sniff=%s file=%s", sniff, path.name)
        for r in all_results:
            ctx.logger.debug(
                "candidate=%s, matched=%s, confidence=%.2f, error=%s evidence=%s",
                r.parser_name,
                r.matched,
                r.confidence,
                r.error,
                [(e.key, e.value) for e in r.evidence],
            )

        if winner.matched:
            ctx.logger.print_success(
                f"Detected parser: {winner.parser_name} (format={winner.format}, confidence={winner.confidence:.2f})",
                label="Normalization",
            )
