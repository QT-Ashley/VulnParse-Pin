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
from pathlib import Path
import re
from typing import Dict, Optional, Set, Tuple, TYPE_CHECKING

from defusedxml.ElementTree import fromstring

from vulnparse_pin.core.classes.decision_reasons import DecisionReasonCodes
from vulnparse_pin.core.classes.pass_classes import DerivedPassResult, Pass, PassMeta
from vulnparse_pin.core.passes.types import NmapAdapterPassOutput

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext, ScanResult

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class NmapAdapterPass(Pass):
    """
    Adapter pass that ingests Nmap XML and emits a derived snapshot for downstream passes.
    This pass does not mutate truth-layer findings/assets.
    """

    name: str = "nmap_adapter"
    version: str = "1.0"
    requires_passes: Tuple[str, ...] = ()

    def __init__(self, nmap_source: Optional[Path] = None):
        self.nmap_source = Path(nmap_source) if nmap_source else None

    def run(self, ctx: "RunContext", scan: "ScanResult") -> DerivedPassResult:
        created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        if self.nmap_source is None:
            output = NmapAdapterPassOutput(
                status="disabled",
                source_file=None,
                host_count=0,
                matched_asset_count=0,
                unmatched_asset_ids=(),
                asset_open_ports={},
                nse_cves_by_asset={},
            )
            services = getattr(ctx, "services", None)
            ledger = getattr(services, "ledger", None)
            if ledger is not None:
                ledger.append_event(
                    component="nmap_adapter",
                    event_type="decision",
                    subject_ref="nmap_ctx:summary",
                    reason_code=DecisionReasonCodes.NMAP_CTX_DISABLED,
                    reason_text="Nmap context adapter disabled (no source provided).",
                    factor_refs=["--nmap-ctx"],
                    evidence={"status": "disabled"},
                )
            return DerivedPassResult(
                meta=PassMeta(
                    name=self.name,
                    version=self.version,
                    created_at_utc=created_at,
                    notes="Nmap adapter disabled (no source provided).",
                ),
                data=asdict(output),
            )

        try:
            source_file = ctx.pfh.ensure_readable_file(self.nmap_source, label="Nmap Adapter Source")
            raw = Path(source_file).read_bytes()
            root = fromstring(raw)
        except (OSError, ValueError) as e:
            ctx.logger.warning("Nmap adapter source read failed: %s", e)
            output = NmapAdapterPassOutput(
                status="error",
                source_file=str(self.nmap_source),
                host_count=0,
                matched_asset_count=0,
                unmatched_asset_ids=(),
                asset_open_ports={},
                nse_cves_by_asset={},
            )
            services = getattr(ctx, "services", None)
            ledger = getattr(services, "ledger", None)
            if ledger is not None:
                ledger.append_event(
                    component="nmap_adapter",
                    event_type="decision",
                    subject_ref="nmap_ctx:summary",
                    reason_code=DecisionReasonCodes.NMAP_CTX_FAILED,
                    reason_text="Nmap context adapter source could not be read or parsed.",
                    factor_refs=["--nmap-ctx"],
                    evidence={"status": "error", "error": str(e), "source_file": str(self.nmap_source)},
                )
            return DerivedPassResult(
                meta=PassMeta(
                    name=self.name,
                    version=self.version,
                    created_at_utc=created_at,
                    notes="Nmap adapter parse failed.",
                ),
                data=asdict(output),
            )

        if str(root.tag).lower() != "nmaprun":
            output = NmapAdapterPassOutput(
                status="invalid_format",
                source_file=str(source_file),
                host_count=0,
                matched_asset_count=0,
                unmatched_asset_ids=(),
                asset_open_ports={},
                nse_cves_by_asset={},
            )
            services = getattr(ctx, "services", None)
            ledger = getattr(services, "ledger", None)
            if ledger is not None:
                ledger.append_event(
                    component="nmap_adapter",
                    event_type="decision",
                    subject_ref="nmap_ctx:summary",
                    reason_code=DecisionReasonCodes.NMAP_CTX_INVALID_FORMAT,
                    reason_text="Nmap context adapter source is not valid nmaprun XML.",
                    factor_refs=["--nmap-ctx"],
                    evidence={"status": "invalid_format", "root_tag": str(root.tag), "source_file": str(source_file)},
                )
            return DerivedPassResult(
                meta=PassMeta(
                    name=self.name,
                    version=self.version,
                    created_at_utc=created_at,
                    notes="Nmap adapter source is not nmaprun XML.",
                ),
                data=asdict(output),
            )

        host_count, host_port_map, host_cves = self._extract_host_maps(root)
        asset_keys = self._build_asset_lookup(scan)

        asset_open_ports: Dict[str, Tuple[int, ...]] = {}
        nse_cves_by_asset: Dict[str, Tuple[str, ...]] = {}

        for asset_id, keys in asset_keys.items():
            matched_ports: Set[int] = set()
            matched_cves: Set[str] = set()
            for key in keys:
                matched_ports.update(host_port_map.get(key, ()))
                matched_cves.update(host_cves.get(key, ()))

            if matched_ports:
                asset_open_ports[asset_id] = tuple(sorted(matched_ports))
            if matched_cves:
                nse_cves_by_asset[asset_id] = tuple(sorted(matched_cves))

        unmatched_asset_ids = tuple(sorted(aid for aid in asset_keys.keys() if aid not in asset_open_ports))

        output = NmapAdapterPassOutput(
            status="enabled",
            source_file=str(source_file),
            host_count=host_count,
            matched_asset_count=len(asset_open_ports),
            unmatched_asset_ids=unmatched_asset_ids,
            asset_open_ports=asset_open_ports,
            nse_cves_by_asset=nse_cves_by_asset,
        )

        ctx.logger.info(
            "[pass:nmap_adapter] enabled | hosts=%d | matched_assets=%d",
            output.host_count,
            output.matched_asset_count,
            extra={"vp_label": "NmapAdapterPass"},
        )

        services = getattr(ctx, "services", None)
        ledger = getattr(services, "ledger", None)
        if ledger is not None:
            total_assets = len(asset_keys)
            join_rate = round(output.matched_asset_count / total_assets, 4) if total_assets > 0 else 0.0
            ledger.append_event(
                component="nmap_adapter",
                event_type="decision",
                subject_ref="nmap_ctx:summary",
                reason_code=DecisionReasonCodes.NMAP_CTX_ENABLED,
                reason_text="Nmap context adapter parsed and matched against scan assets.",
                factor_refs=["--nmap-ctx", "nmap_ctx.port_tiebreak_enabled"],
                evidence={
                    "status": "enabled",
                    "source_file": str(source_file),
                    "host_count": output.host_count,
                    "matched_asset_count": output.matched_asset_count,
                    "unmatched_asset_count": len(output.unmatched_asset_ids),
                    "join_rate": join_rate,
                },
            )

        return DerivedPassResult(
            meta=PassMeta(
                name=self.name,
                version=self.version,
                created_at_utc=created_at,
                notes="Derived Nmap adapter snapshot.",
            ),
            data=asdict(output),
        )

    def _extract_host_maps(self, root) -> Tuple[int, Dict[str, Set[int]], Dict[str, Set[str]]]:
        host_port_map: Dict[str, Set[int]] = {}
        host_cves: Dict[str, Set[str]] = {}
        host_count = 0

        for host in root.findall(".//host"):
            keys = self._host_keys(host)
            if not keys:
                continue
            host_count += 1

            open_ports: Set[int] = set()
            for port in host.findall("./ports/port"):
                state_el = port.find("./state")
                state = (state_el.attrib.get("state", "") if state_el is not None else "").lower()
                if "open" not in state:
                    continue
                raw_port = port.attrib.get("portid")
                try:
                    port_num = int(raw_port)
                except (TypeError, ValueError):
                    continue
                open_ports.add(port_num)

            cves: Set[str] = set()
            for script in host.findall(".//script"):
                script_name = str(script.attrib.get("id", "")).strip().lower()
                if script_name not in {"vulners", "vulns", "nmap-vulners"}:
                    continue
                output = str(script.attrib.get("output", "") or "")
                cves.update(m.group(0).upper() for m in _CVE_RE.finditer(output))

            for key in keys:
                host_port_map.setdefault(key, set()).update(open_ports)
                if cves:
                    host_cves.setdefault(key, set()).update(cves)

        return host_count, host_port_map, host_cves

    def _host_keys(self, host) -> Set[str]:
        keys: Set[str] = set()

        for addr in host.findall("./address"):
            value = str(addr.attrib.get("addr", "")).strip().lower()
            if value:
                keys.add(value)

        for node in host.findall("./hostnames/hostname"):
            value = str(node.attrib.get("name", "")).strip().lower()
            if value:
                keys.add(value)

        return keys

    def _build_asset_lookup(self, scan: "ScanResult") -> Dict[str, Set[str]]:
        lookup: Dict[str, Set[str]] = {}

        for asset in scan.assets:
            asset_id = getattr(asset, "asset_id", None)
            if not asset_id:
                first_finding_asset_id = next((getattr(f, "asset_id", None) for f in asset.findings if getattr(f, "asset_id", None)), None)
                asset_id = first_finding_asset_id or str(getattr(asset, "ip_address", "") or getattr(asset, "hostname", "") or "")
            asset_id = str(asset_id).strip()
            if not asset_id:
                continue

            keys: Set[str] = set()
            if getattr(asset, "ip_address", None):
                keys.add(str(asset.ip_address).strip().lower())
            if getattr(asset, "hostname", None):
                keys.add(str(asset.hostname).strip().lower())

            if keys:
                lookup[asset_id] = keys

        return lookup
