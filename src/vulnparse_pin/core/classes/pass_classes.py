# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Optional, Protocol, TYPE_CHECKING

from vulnparse_pin.core.classes.decision_reasons import DecisionReasonCodes

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import ScanResult
    from vulnparse_pin.core.classes.dataclass import RunContext

# Derived Context Classes
@dataclass(frozen=True)
class PassMeta:
    """
    Stores metadata about a particular Pass.
    """
    name: str
    version: str
    created_at_utc: str
    notes: Optional[str] = None

@dataclass(frozen=True)
class DerivedPassResult:
    """
    Stores result data from a Pass.
    """
    meta: PassMeta
    data: Any

@dataclass(frozen=True)
class DerivedContext:
    """
    Append-only derived outputs. Separate from the Truth.
    """
    passes: Dict[str, DerivedPassResult] = field(default_factory=dict)

    def put(self, result: DerivedPassResult) -> "DerivedContext":
        key = f"{result.meta.name}@{result.meta.version}"

        if key in self.passes:
            raise ValueError(f"Derived pass '{key}' already exists (append-only).")

        new_map = dict(self.passes)
        new_map[key] = result

        return replace(self, passes = new_map)

    def get(self, key: str) -> Optional[DerivedPassResult]:
        return self.passes.get(key)

    def get_latest(self, name: str) -> Optional[DerivedPassResult]:
        for _, v in reversed(list(self.passes.items())):
            if v.meta.name == name:
                return v
        return None

# Passes Interface
class Pass(Protocol):
    """
    Pass Protocol that store the name of Passrun to determine which pass should be ran on data.
    """
    name: str
    version: str
    requires_passes: tuple[str, ...]

    def run(self, ctx: "RunContext", scan: "ScanResult") -> DerivedPassResult:
        pass

@dataclass
class PassRunner:
    """
    Orchestrator for Passruns
    """
    passes: List[Pass]

    def _validate_dependencies(self) -> None:
        pipeline_keys = [f"{p.name}@{p.version}" for p in self.passes]

        duplicates = {k for k in pipeline_keys if pipeline_keys.count(k) > 1}
        if duplicates:
            dupes = ", ".join(sorted(duplicates))
            raise ValueError(f"Duplicate passes in pipeline: {dupes}")

        key_to_index = {k: i for i, k in enumerate(pipeline_keys)}
        for i, p in enumerate(self.passes):
            current_key = pipeline_keys[i]
            required = tuple(getattr(p, "requires_passes", ()) or ())
            for dep in required:
                dep_idx = key_to_index.get(dep)
                if dep_idx is None:
                    raise ValueError(f"Pass {current_key} requires missing dependency {dep}")
                if dep_idx >= i:
                    raise ValueError(f"Pass {current_key} must run after dependency {dep}")

    def run_all(self, ctx: "RunContext", scan: "ScanResult") -> "ScanResult":
        self._validate_dependencies()
        for p in self.passes:
            ctx.logger.debug("Running pass: %s@%s", p.name, p.version, extra = {"vp_label": "PassRunner"})
            ledger = getattr(getattr(ctx, "services", None), "ledger", None)
            if ledger is not None:
                ledger.append_event(
                    component="PassRunner",
                    event_type="pass_start",
                    subject_ref=f"pass:{p.name}@{p.version}",
                    reason_code=DecisionReasonCodes.PASS_EXECUTION_STARTED,
                    reason_text=f"Starting pass {p.name}@{p.version}.",
                    factor_refs=["pass.name", "pass.version"],
                )

            try:
                res = p.run(ctx, scan)
            except Exception as exc:
                if ledger is not None:
                    ledger.append_event(
                        component="PassRunner",
                        event_type="pass_error",
                        subject_ref=f"pass:{p.name}@{p.version}",
                        reason_code=DecisionReasonCodes.PASS_EXECUTION_FAILED,
                        reason_text=f"Pass {p.name}@{p.version} raised an exception.",
                        factor_refs=["pass.name", "pass.version"],
                        evidence={"error": str(exc)},
                    )
                raise

            if ledger is not None:
                ledger.append_event(
                    component="PassRunner",
                    event_type="pass_end",
                    subject_ref=f"pass:{p.name}@{p.version}",
                    reason_code=DecisionReasonCodes.PASS_EXECUTION_COMPLETED,
                    reason_text=f"Completed pass {p.name}@{p.version}.",
                    factor_refs=["pass.name", "pass.version"],
                )

            new_derived = scan.derived.put(res)
            scan = replace(scan, derived=new_derived)
        return scan
