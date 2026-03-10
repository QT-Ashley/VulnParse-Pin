# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 QTShade
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Optional, Protocol, TYPE_CHECKING

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
        for k, v in reversed(list(self.passes.items())):
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

    def run(self, ctx: "RunContext", scan: "ScanResult") -> DerivedPassResult:
        pass

@dataclass
class PassRunner:
    """
    Orchestrator for Passruns
    """
    passes: List[Pass]

    def run_all(self, ctx: "RunContext", scan: "ScanResult") -> "ScanResult":
        for p in self.passes:
            ctx.logger.debug("Running pass: %s@%s", p.name, p.version, extra = {"vp_label": "PassRunner"})
            res = p.run(ctx, scan)

            new_derived = scan.derived.put(res)
            scan = replace(scan, derived=new_derived)
        return scan
