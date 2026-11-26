# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, TYPE_CHECKING

from lxml import etree

from vulnparse_pin.core.classes.decision_reasons import DecisionReasonCodes
from vulnparse_pin.core.classes.pass_classes import DerivedPassResult, Pass, PassMeta
from vulnparse_pin.core.id import (
    canonicalize_target_key,
    make_asset_id_v2,
    normalize_hostname_value,
    normalize_ip_value,
)
from vulnparse_pin.core.passes.types import NmapAdapterPassOutput
from vulnparse_pin.parsers._xml_security import prune_element, safe_iterparse

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext, ScanResult

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_PUBLIC_INTERNET_PORTS = frozenset({21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 3389, 5900, 8080, 8443})
_TEST_NET_V4 = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)


def _classify_ip_exposure(ip_str: Optional[str]) -> Optional[bool]:
    """Return True for public/test-net IPs, False for RFC1918/local/reserved, None if invalid."""
    if not ip_str:
        return None
    try:
        addr = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return None
    if addr.version == 4 and any(addr in net for net in _TEST_NET_V4):
        return True
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        return False
    if addr.is_private:
        return False
    return bool(addr.is_global)


def _infer_unmatched_internet_facing(
    ips: Sequence[str] | Tuple[str, ...],
    open_ports: Set[int],
) -> Optional[bool]:
    ip_flags = [_classify_ip_exposure(ip) for ip in ips]
    if any(flag is True for flag in ip_flags):
        return True
    if any(flag is False for flag in ip_flags):
        return False
    if any(p in _PUBLIC_INTERNET_PORTS for p in open_ports):
        return True
    return None


def _get_duckdb_conn(db: Any) -> Any:
    conn = getattr(db, "conn", None)
    if conn is not None:
        return conn
    if hasattr(db, "execute") and hasattr(db, "appender"):
        return db
    return None


class _InvalidNmapRootError(ValueError):
    """Raised internally when XML root element is not <nmaprun>."""

    def __init__(self, root_tag: str) -> None:
        self.root_tag = root_tag
        super().__init__(f"Invalid Nmap root tag: {root_tag}")


class NmapAdapterPass(Pass):
    """
    Streaming lxml adapter pass that ingests Nmap XML and emits a derived snapshot
    for downstream passes while optionally reconciling hosts/ports into DuckDB.
    """

    name: str = "nmap_adapter"
    version: str = "1.0"
    requires_passes: Tuple[str, ...] = ()

    def __init__(self, nmap_source: Optional[Path] = None):
        self.nmap_source = Path(nmap_source) if nmap_source else None

    def run(self, ctx: "RunContext", scan: Optional["ScanResult"] = None) -> DerivedPassResult:
        created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        services = getattr(ctx, "services", None)
        ledger = getattr(services, "ledger", None)

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
            parsed_hosts = self._stream_nmap_hosts(ctx, Path(source_file))
        except _InvalidNmapRootError as inv:
            output = NmapAdapterPassOutput(
                status="invalid_format",
                source_file=str(self.nmap_source),
                host_count=0,
                matched_asset_count=0,
                unmatched_asset_ids=(),
                asset_open_ports={},
                nse_cves_by_asset={},
            )
            if ledger is not None:
                ledger.append_event(
                    component="nmap_adapter",
                    event_type="decision",
                    subject_ref="nmap_ctx:summary",
                    reason_code=DecisionReasonCodes.NMAP_CTX_INVALID_FORMAT,
                    reason_text="Nmap context adapter source is not valid nmaprun XML.",
                    factor_refs=["--nmap-ctx"],
                    evidence={
                        "status": "invalid_format",
                        "root_tag": inv.root_tag,
                        "source_file": str(self.nmap_source),
                    },
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
        except (OSError, ValueError, etree.XMLSyntaxError) as e:
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

        host_count = len(parsed_hosts)
        host_port_map: Dict[str, Set[int]] = {}
        host_cves: Dict[str, Set[str]] = {}
        for host_rec in parsed_hosts:
            for key in host_rec["all_keys"]:
                host_port_map.setdefault(key, set()).update(host_rec["open_ports"])
                if host_rec["nse_cves"]:
                    host_cves.setdefault(key, set()).update(host_rec["nse_cves"])

        asset_open_ports: Dict[str, Tuple[int, ...]] = {}
        nse_cves_by_asset: Dict[str, Tuple[str, ...]] = {}
        all_known_asset_ids: Set[str] = set()

        db = getattr(ctx, "db", None) or getattr(services, "db", None)
        run_id = getattr(ctx, "run_id", None) or getattr(services, "run_id", None)
        asset_matcher = getattr(ctx, "asset_matcher", None) or getattr(services, "asset_matcher", None)
        conn = _get_duckdb_conn(db) if (db is not None and run_id is not None) else None

        db_shadow_aids: Set[str] = set()
        if conn is not None and run_id is not None:
            db_ports, db_cves, db_all_aids, db_shadow_aids = self._reconcile_duckdb_hosts(
                conn=conn,
                run_id=str(run_id),
                parsed_hosts=parsed_hosts,
                asset_matcher=asset_matcher,
            )
            asset_open_ports.update(db_ports)
            nse_cves_by_asset.update(db_cves)
            all_known_asset_ids.update(db_all_aids)

        if scan is not None:
            asset_keys = self._build_asset_lookup(scan)
            all_known_asset_ids.update(asset_keys.keys())
            for asset_id, keys in asset_keys.items():
                matched_ports: Set[int] = set(asset_open_ports.get(asset_id, ()))
                matched_cves: Set[str] = set(nse_cves_by_asset.get(asset_id, ()))
                for key in keys:
                    matched_ports.update(host_port_map.get(key, ()))
                    matched_cves.update(host_cves.get(key, ()))
                if matched_ports:
                    asset_open_ports[asset_id] = tuple(sorted(matched_ports))
                if matched_cves:
                    nse_cves_by_asset[asset_id] = tuple(sorted(matched_cves))

        unmatched_asset_ids = tuple(sorted(aid for aid in all_known_asset_ids if aid not in asset_open_ports))
        matched_asset_count = len([aid for aid in asset_open_ports if aid not in db_shadow_aids])

        output = NmapAdapterPassOutput(
            status="enabled",
            source_file=str(source_file),
            host_count=host_count,
            matched_asset_count=matched_asset_count,
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

        if ledger is not None:
            total_assets = len(all_known_asset_ids)
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

    def _stream_nmap_hosts(self, ctx: "RunContext", source_file: Path) -> List[Dict[str, Any]]:
        """Stream Nmap XML via hardened lxml.etree.iterparse in O(1) memory per host."""
        hosts: List[Dict[str, Any]] = []
        root_seen = False

        with ctx.pfh.open_for_read(source_file, mode="rb", label="Nmap Adapter Source") as fh:
            for event, elem in safe_iterparse(fh, events=("start", "end")):
                tag = elem.tag if isinstance(elem.tag, str) else ""
                local_tag = tag.rsplit("}", 1)[-1].lower() if tag else ""

                if event == "start":
                    if not root_seen:
                        root_seen = True
                        if local_tag != "nmaprun":
                            raise _InvalidNmapRootError(tag)
                    continue

                if local_tag in {"hosthint", "scaninfo", "verbose", "debugging"}:
                    prune_element(elem)
                    continue

                if local_tag == "host":
                    rec = self._extract_host_record(elem)
                    prune_element(elem)
                    if rec is not None:
                        hosts.append(rec)

        if not root_seen:
            raise ValueError("Empty XML document; missing <nmaprun> root element.")
        return hosts

    @staticmethod
    def _extract_host_record(host: etree._Element) -> Optional[Dict[str, Any]]:
        ips: List[str] = []
        hostnames: List[str] = []
        all_keys: Set[str] = set()

        for addr in host.findall("./address"):
            raw_val = str(addr.attrib.get("addr", "")).strip()
            if not raw_val:
                continue
            all_keys.add(raw_val.lower())
            addrtype = str(addr.attrib.get("addrtype", "")).strip().lower()
            if addrtype in ("", "ipv4", "ipv6"):
                norm_ip = normalize_ip_value(raw_val)
                if norm_ip and norm_ip not in ips:
                    ips.append(norm_ip)

        for node in host.findall("./hostnames/hostname"):
            raw_name = str(node.attrib.get("name", "")).strip()
            if not raw_name:
                continue
            all_keys.add(raw_name.lower())
            norm_host = normalize_hostname_value(raw_name)
            if norm_host and norm_host not in hostnames:
                hostnames.append(norm_host)

        if not all_keys:
            return None

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
            if 0 < port_num <= 65535:
                open_ports.add(port_num)

        os_name: Optional[str] = None
        best_acc = -1
        for osmatch in host.findall("./os/osmatch"):
            name = (osmatch.attrib.get("name") or "").strip()
            try:
                acc = int(osmatch.attrib.get("accuracy") or 0)
            except (TypeError, ValueError):
                acc = 0
            if name and acc > best_acc:
                best_acc = acc
                os_name = name
        if not os_name:
            osclass = host.find("./os/osclass")
            if osclass is not None:
                fam = (osclass.attrib.get("osfamily") or "").strip()
                gen = (osclass.attrib.get("osgen") or "").strip()
                os_name = f"{fam} {gen}".strip() or None

        cves: Set[str] = set()
        for script in host.findall(".//script"):
            script_name = str(script.attrib.get("id", "")).strip().lower()
            if script_name not in {"vulners", "vulns", "nmap-vulners"}:
                continue
            output = str(script.attrib.get("output", "") or "")
            cves.update(m.group(0).upper() for m in _CVE_RE.finditer(output))

        return {
            "ips": tuple(ips),
            "hostnames": tuple(hostnames),
            "all_keys": all_keys,
            "open_ports": open_ports,
            "os_name": os_name,
            "nse_cves": cves,
        }

    def _reconcile_duckdb_hosts(
        self,
        *,
        conn: Any,
        run_id: str,
        parsed_hosts: List[Dict[str, Any]],
        asset_matcher: Optional[Any],
    ) -> Tuple[Dict[str, Tuple[int, ...]], Dict[str, Tuple[str, ...]], Set[str], Set[str]]:
        """Resolve Nmap hosts against DuckDB assets/aliases and persist open ports + shadow assets."""
        from vulnparse_pin.storage.repositories import ensure_run

        ensure_run(conn, run_id)

        existing_assets: Dict[str, Dict[str, Any]] = {}
        key_to_aid: Dict[str, str] = {}
        existing_aliases: Set[Tuple[str, str, str]] = set()

        for row in conn.execute(
            """
            SELECT asset_id, canonical_key, hostname, ip_address, target_uri, image_or_repo,
                   os, declared_criticality, derived_criticality, internet_facing,
                   owner, env_tags_json, inventory_status, matched_rule_id, open_ports_json
            FROM assets
            WHERE run_id = ?
            ORDER BY asset_id ASC
            """,
            [run_id],
        ).fetchall():
            aid = row[0]
            try:
                ports = {int(p) for p in json.loads(row[14] or "[]") if int(p) > 0}
            except Exception:
                ports = set()
            existing_assets[aid] = {
                "asset_id": aid,
                "canonical_key": row[1],
                "hostname": row[2],
                "ip_address": row[3],
                "target_uri": row[4],
                "image_or_repo": row[5],
                "os": row[6],
                "declared_criticality": row[7],
                "derived_criticality": row[8],
                "internet_facing": row[9],
                "owner": row[10],
                "env_tags_json": row[11],
                "inventory_status": row[12],
                "matched_rule_id": row[13],
                "open_ports": ports,
            }
            if row[2]:
                nh = normalize_hostname_value(row[2])
                if nh:
                    key_to_aid.setdefault(nh, aid)
                key_to_aid.setdefault(str(row[2]).strip().lower(), aid)
            if row[3]:
                nip = normalize_ip_value(row[3])
                if nip:
                    key_to_aid.setdefault(nip, aid)
                key_to_aid.setdefault(str(row[3]).strip().lower(), aid)

        for aid, atype, aval in conn.execute(
            "SELECT asset_id, alias_type, alias_value FROM asset_aliases WHERE run_id = ? ORDER BY asset_id ASC, alias_type ASC, alias_value ASC",
            [run_id],
        ).fetchall():
            existing_aliases.add((aid, atype, aval))
            if aval:
                key_to_aid.setdefault(str(aval).strip().lower(), aid)
                nip = normalize_ip_value(aval)
                if nip:
                    key_to_aid.setdefault(nip, aid)
                nh = normalize_hostname_value(aval)
                if nh:
                    key_to_aid.setdefault(nh, aid)

        updated_aids: Set[str] = set()
        new_assets: Dict[str, Dict[str, Any]] = {}
        new_aliases: Set[Tuple[str, str, str]] = set()
        nmap_ports_by_aid: Dict[str, Set[int]] = {}
        nmap_cves_by_aid: Dict[str, Set[str]] = {}

        for host in parsed_hosts:
            ips = host["ips"]
            hostnames = host["hostnames"]
            open_ports = host["open_ports"]
            nse_cves = host["nse_cves"]
            os_name = host["os_name"]
            primary_ip = ips[0] if ips else None
            primary_host = hostnames[0] if hostnames else None

            matched_aid: Optional[str] = None
            for cand in (*hostnames, *ips, *sorted(host["all_keys"])):
                if cand in key_to_aid:
                    matched_aid = key_to_aid[cand]
                    break

            matched_ctx = None
            if asset_matcher is not None:
                matched_ctx = asset_matcher.resolve(ip=primary_ip, hostname=primary_host)
                if matched_aid is None and matched_ctx.asset_id in existing_assets:
                    matched_aid = matched_ctx.asset_id

            if matched_aid is not None and matched_aid in existing_assets:
                arec = existing_assets[matched_aid]
                prev_ports = set(arec["open_ports"])
                arec["open_ports"].update(open_ports)
                if arec["open_ports"] != prev_ports:
                    updated_aids.add(matched_aid)
                if not arec["os"] and os_name:
                    arec["os"] = os_name
                    updated_aids.add(matched_aid)
                if arec["inventory_status"] == "unmatched_shadow" and arec["internet_facing"] is None:
                    inferred = _infer_unmatched_internet_facing(ips, arec["open_ports"])
                    if inferred is not None:
                        arec["internet_facing"] = inferred
                        updated_aids.add(matched_aid)
                if not arec["hostname"] and primary_host:
                    arec["hostname"] = primary_host
                    updated_aids.add(matched_aid)
                if not arec["ip_address"] and primary_ip:
                    arec["ip_address"] = primary_ip
                    updated_aids.add(matched_aid)
                aid = matched_aid
            else:
                if matched_ctx is not None:
                    aid = matched_ctx.asset_id
                    ckey = matched_ctx.canonical_key
                    inv_status = matched_ctx.inventory_status
                    decl_crit = matched_ctx.declared_criticality
                    rule_id = matched_ctx.matched_rule_id
                    owner = matched_ctx.owner
                    env_payload = {"env": list(matched_ctx.env_tags), "tags": dict(matched_ctx.tags)}
                    inet = matched_ctx.internet_facing
                    if inet is None and inv_status == "unmatched_shadow":
                        inet = _infer_unmatched_internet_facing(ips, set(open_ports))
                else:
                    ckey = canonicalize_target_key(ip=primary_ip, hostname=primary_host)
                    aid = make_asset_id_v2(ckey)
                    inv_status = "unmatched_shadow"
                    decl_crit = None
                    rule_id = None
                    owner = None
                    env_payload = {"env": [], "tags": {}}
                    inet = _infer_unmatched_internet_facing(ips, set(open_ports))

                if aid in new_assets:
                    arec = new_assets[aid]
                    arec["open_ports"].update(open_ports)
                    if not arec["os"] and os_name:
                        arec["os"] = os_name
                    if arec["inventory_status"] == "unmatched_shadow" and arec["internet_facing"] is None:
                        arec["internet_facing"] = _infer_unmatched_internet_facing(ips, arec["open_ports"])
                else:
                    new_assets[aid] = {
                        "asset_id": aid,
                        "canonical_key": ckey,
                        "hostname": primary_host,
                        "ip_address": primary_ip,
                        "target_uri": None,
                        "image_or_repo": None,
                        "os": os_name,
                        "declared_criticality": decl_crit,
                        "derived_criticality": None,
                        "internet_facing": inet,
                        "owner": owner,
                        "env_tags_json": json.dumps(env_payload, sort_keys=True, ensure_ascii=True),
                        "inventory_status": inv_status,
                        "matched_rule_id": rule_id,
                        "open_ports": set(open_ports),
                    }
                    for ip_val in ips:
                        key_to_aid.setdefault(ip_val, aid)
                    for h_val in hostnames:
                        key_to_aid.setdefault(h_val, aid)

            for ip_val in ips:
                pair = (aid, "ip", ip_val)
                if pair not in existing_aliases:
                    new_aliases.add(pair)
            for h_val in hostnames:
                pair = (aid, "hostname", h_val)
                if pair not in existing_aliases:
                    new_aliases.add(pair)

            if open_ports:
                nmap_ports_by_aid.setdefault(aid, set()).update(open_ports)
            if nse_cves:
                nmap_cves_by_aid.setdefault(aid, set()).update(nse_cves)

        if updated_aids or new_assets or new_aliases:
            conn.execute("BEGIN TRANSACTION")
            try:
                if updated_aids:
                    upd_rows = [
                        (
                            run_id,
                            aid,
                            existing_assets[aid]["hostname"],
                            existing_assets[aid]["ip_address"],
                            existing_assets[aid]["os"],
                            existing_assets[aid]["internet_facing"],
                            json.dumps(sorted(existing_assets[aid]["open_ports"]), ensure_ascii=True),
                        )
                        for aid in sorted(updated_aids)
                    ]
                    conn.execute(
                        """
                        CREATE TEMP TABLE _stg_nmap_upd (
                            run_id VARCHAR, asset_id VARCHAR, hostname VARCHAR, ip_address VARCHAR,
                            os VARCHAR, internet_facing BOOLEAN, open_ports_json VARCHAR
                        )
                        """
                    )
                    with conn.appender("_stg_nmap_upd") as app:
                        app.append_rows(upd_rows)
                    conn.execute(
                        """
                        UPDATE assets AS a
                        SET hostname = COALESCE(a.hostname, s.hostname),
                            ip_address = COALESCE(a.ip_address, s.ip_address),
                            os = COALESCE(a.os, s.os),
                            internet_facing = COALESCE(a.internet_facing, s.internet_facing),
                            open_ports_json = s.open_ports_json
                        FROM _stg_nmap_upd AS s
                        WHERE a.run_id = s.run_id AND a.asset_id = s.asset_id
                        """
                    )
                    conn.execute("DROP TABLE _stg_nmap_upd")

                if new_assets:
                    ins_rows = [
                        (
                            run_id,
                            a["asset_id"],
                            a["canonical_key"],
                            a["hostname"],
                            a["ip_address"],
                            a["target_uri"],
                            a["image_or_repo"],
                            a["os"],
                            a["declared_criticality"],
                            a["derived_criticality"],
                            a["internet_facing"],
                            a["owner"],
                            a["env_tags_json"],
                            a["inventory_status"],
                            a["matched_rule_id"],
                            json.dumps(sorted(a["open_ports"]), ensure_ascii=True),
                        )
                        for a in new_assets.values()
                    ]
                    with conn.appender("assets") as app:
                        app.append_rows(ins_rows)

                if new_aliases:
                    alias_rows = [(run_id, aid, atype, aval) for (aid, atype, aval) in sorted(new_aliases)]
                    with conn.appender("asset_aliases") as app:
                        app.append_rows(alias_rows)

                conn.execute("COMMIT")
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise

        all_aids = set(existing_assets.keys()) | set(new_assets.keys())
        shadow_aids = {
            aid for aid, rec in existing_assets.items() if rec.get("inventory_status") == "unmatched_shadow"
        } | {
            aid for aid, rec in new_assets.items() if rec.get("inventory_status") == "unmatched_shadow"
        }
        return (
            {aid: tuple(sorted(ports)) for aid, ports in nmap_ports_by_aid.items()},
            {aid: tuple(sorted(cves)) for aid, cves in nmap_cves_by_aid.items()},
            all_aids,
            shadow_aids,
        )

    def _build_asset_lookup(self, scan: "ScanResult") -> Dict[str, Set[str]]:
        lookup: Dict[str, Set[str]] = {}

        for asset in scan.assets:
            asset_id = getattr(asset, "asset_id", None)
            if not asset_id:
                first_finding_asset_id = next(
                    (getattr(f, "asset_id", None) for f in asset.findings if getattr(f, "asset_id", None)),
                    None,
                )
                asset_id = first_finding_asset_id or str(
                    getattr(asset, "ip_address", "") or getattr(asset, "hostname", "") or ""
                )
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
