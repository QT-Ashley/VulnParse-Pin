# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

import duckdb

from vulnparse_pin.core.id import (
    canonicalize_target_key,
    make_asset_id_v2,
    make_finding_id_v2,
    normalize_hostname_value,
    normalize_image_or_repo,
    normalize_ip_value,
    normalize_target_uri,
)
from vulnparse_pin.utils.cvss_utils import resolve_effective_cvss_fields

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

_DETECTION_MODE_RELIABILITY: Dict[str, float] = {
    "credentialed_host": 1.0,
    "active_dast": 1.0,
    "sca_container": 0.90,
    "uncredentialed_banner": 0.85,
    "static_sast": 0.55,
    "network_probe": 0.80,
}

_SEVERITY_RANK: Dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "info": 1,
    "none": 0,
    "unknown": 0,
}

_PRIORITY_ORDER_SQL = """
CASE UPPER(COALESCE(td.priority_tier, 'ZZZZ'))
    WHEN 'P1' THEN 1
    WHEN 'OAL-1' THEN 1
    WHEN 'ACT' THEN 1
    WHEN 'P1B' THEN 2
    WHEN 'OAL-2' THEN 2
    WHEN 'P2' THEN 3
    WHEN 'ATTEND' THEN 3
    WHEN 'OAL-3' THEN 4
    WHEN 'P3' THEN 5
    WHEN 'TRACK*' THEN 5
    WHEN 'P4' THEN 6
    WHEN 'TRACK' THEN 6
    WHEN 'ZZZZ' THEN 999
    ELSE 100
END ASC,
COALESCE(td.priority_tier, 'ZZZZ') ASC,
s.operational_score DESC NULLS LAST,
e.epss_score DESC NULLS LAST,
f.finding_id ASC
""".strip()

_FAST_EFFECTIVE_PRIMARY_CVE_SQL = (
    "CASE "
    "WHEN s.score_trace_json IS NULL OR NOT CONTAINS(s.score_trace_json, 'primary_cve') THEN UPPER(f.primary_cve) "
    "WHEN f.primary_cve IS NOT NULL AND ("
    "CONTAINS(s.score_trace_json, '\"primary_cve\":\"' || f.primary_cve || '\"') "
    "OR CONTAINS(s.score_trace_json, '\"primary_cve\": \"' || f.primary_cve || '\"')"
    ") THEN UPPER(f.primary_cve) "
    "WHEN CONTAINS(s.score_trace_json, '\"primary_cve\":null') "
    "OR CONTAINS(s.score_trace_json, '\"primary_cve\": null') THEN UPPER(f.primary_cve) "
    "ELSE COALESCE(UPPER(NULLIF(json_extract_string(s.score_trace_json, '$.primary_cve'), '')), UPPER(f.primary_cve)) "
    "END"
)

_FAST_SCORE_TRACE_IN_KEV_SQL = (
    "CASE "
    "WHEN s.score_trace_json IS NULL OR NOT CONTAINS(s.score_trace_json, 'in_kev') THEN FALSE "
    "WHEN (CONTAINS(s.score_trace_json, '\"in_kev\":false') OR CONTAINS(s.score_trace_json, '\"in_kev\": false')) "
    "AND NOT CONTAINS(s.score_trace_json, '\"in_kev\":true') "
    "AND NOT CONTAINS(s.score_trace_json, '\"in_kev\": true') THEN FALSE "
    "ELSE COALESCE(TRY_CAST(json_extract(s.score_trace_json, '$.in_kev') AS BOOLEAN), FALSE) "
    "END"
)

_KEV_CTES_SQL = (
    "WITH e_kev AS ("
    "SELECT DISTINCT UPPER(cve_id) AS cve_u "
    "FROM enrichment_snapshots WHERE run_id = ? AND COALESCE(in_kev, FALSE)"
    "), "
    "fc_kev AS ("
    "SELECT DISTINCT fc.finding_id "
    "FROM finding_cves fc "
    "JOIN enrichment_snapshots es ON es.run_id = fc.run_id AND UPPER(es.cve_id) = UPPER(fc.cve_id) "
    "WHERE fc.run_id = ? AND COALESCE(es.in_kev, FALSE)"
    "), "
    "s_kev AS ("
    "SELECT DISTINCT s.finding_id "
    "FROM scores s "
    "LEFT JOIN findings f2 ON f2.run_id = s.run_id AND f2.finding_id = s.finding_id "
    "LEFT JOIN e_kev e2 ON e2.cve_u = ("
    "CASE "
    "WHEN s.score_trace_json IS NULL OR NOT CONTAINS(s.score_trace_json, 'primary_cve') THEN NULL "
    "WHEN f2.primary_cve IS NOT NULL AND ("
    "CONTAINS(s.score_trace_json, '\"primary_cve\":\"' || f2.primary_cve || '\"') "
    "OR CONTAINS(s.score_trace_json, '\"primary_cve\": \"' || f2.primary_cve || '\"')"
    ") THEN NULL "
    "WHEN CONTAINS(s.score_trace_json, '\"primary_cve\":null') "
    "OR CONTAINS(s.score_trace_json, '\"primary_cve\": null') THEN NULL "
    "ELSE UPPER(NULLIF(json_extract_string(s.score_trace_json, '$.primary_cve'), '')) "
    "END"
    ") "
    f"WHERE s.run_id = ? AND s.score_trace_json IS NOT NULL AND (e2.cve_u IS NOT NULL OR ({_FAST_SCORE_TRACE_IN_KEV_SQL}))"
    ") "
)


def _get_conn(db: Any) -> duckdb.DuckDBPyConnection:
    if isinstance(db, duckdb.DuckDBPyConnection):
        return db
    conn = getattr(db, "conn", None)
    if conn is not None:
        return conn
    raise TypeError(f"Expected VppDatabase or DuckDBPyConnection, got {type(db).__name__}")


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_loads_safe(raw: Optional[str], default: Any) -> Any:
    if not raw:
        return default
    try:
        return json.loads(raw)
    except Exception:
        return default


def _json_dumps_list(items: Optional[Sequence[Any]], cache: Optional[Dict[Tuple[Any, ...], str]] = None) -> str:
    if not items:
        return "[]"
    if cache is not None and len(items) <= 8:
        key = tuple(items)
        cached = cache.get(key)
        if cached is not None:
            return cached
        encoded = json.dumps(list(items), ensure_ascii=True)
        if len(cache) < 50_000:
            cache[key] = encoded
        return encoded
    return json.dumps(list(items), ensure_ascii=True)


class _PendingFinding:
    __slots__ = (
        "finding_id",
        "asset_id",
        "scoring_track",
        "primary_cve",
        "cves",
        "cwes",
        "ghsa_ids",
        "title",
        "description",
        "solution",
        "plugin_output",
        "affected_port",
        "protocol",
        "service_name",
        "location_uri",
        "line_number",
        "package_purl",
        "scanner_severity",
        "scanner_cvss_score",
        "scanner_cvss_vector",
        "detection_mode",
        "signal_reliability",
        "ingestion_confidence",
        "fidelity_tier",
        "source_format",
        "references",
        "tags",
        "exploit_evidence",
        "source_count",
        "initial_source_sig",
        "seen_sigs",
    )

    def __init__(
        self,
        finding_id: str,
        asset_id: str,
        scoring_track: str,
        primary_cve: Optional[str],
        cves: List[str],
        cwes: List[str],
        ghsa_ids: List[str],
        title: str,
        description: str,
        solution: str,
        plugin_output: str,
        affected_port: Optional[int],
        protocol: Optional[str],
        service_name: Optional[str],
        location_uri: Optional[str],
        line_number: Optional[int],
        package_purl: Optional[str],
        scanner_severity: Optional[str],
        scanner_cvss_score: Optional[float],
        scanner_cvss_vector: Optional[str],
        detection_mode: Optional[str],
        signal_reliability: float,
        ingestion_confidence: float,
        fidelity_tier: Optional[str],
        source_format: Optional[str],
        references: List[str],
        tags: List[str],
        exploit_evidence: Optional[bool],
        source_count: int,
        initial_source_sig: Tuple[Any, ...],
    ) -> None:
        self.finding_id = finding_id
        self.asset_id = asset_id
        self.scoring_track = scoring_track
        self.primary_cve = primary_cve
        self.cves = cves
        self.cwes = cwes
        self.ghsa_ids = ghsa_ids
        self.title = title
        self.description = description
        self.solution = solution
        self.plugin_output = plugin_output
        self.affected_port = affected_port
        self.protocol = protocol
        self.service_name = service_name
        self.location_uri = location_uri
        self.line_number = line_number
        self.package_purl = package_purl
        self.scanner_severity = scanner_severity
        self.scanner_cvss_score = scanner_cvss_score
        self.scanner_cvss_vector = scanner_cvss_vector
        self.detection_mode = detection_mode
        self.signal_reliability = signal_reliability
        self.ingestion_confidence = ingestion_confidence
        self.fidelity_tier = fidelity_tier
        self.source_format = source_format
        self.references = references
        self.tags = tags
        self.exploit_evidence = exploit_evidence
        self.source_count = source_count
        self.initial_source_sig = initial_source_sig
        self.seen_sigs: Optional[Set[Tuple[Any, ...]]] = None


def _merge_unique_strs(existing: List[str], incoming: Sequence[Any]) -> List[str]:
    if not incoming:
        return existing
    if not existing:
        if len(incoming) == 1:
            item = incoming[0]
            if item is not None:
                s = item.strip() if type(item) is str else str(item).strip()
                if s and not s.startswith("SENTINEL:"):
                    return [s]
            return []
        seen: Set[str] = set()
        out: List[str] = []
        for item in incoming:
            if item is None:
                continue
            s = item.strip() if type(item) is str else str(item).strip()
            if s and not s.startswith("SENTINEL:") and s not in seen:
                seen.add(s)
                out.append(s)
        return out
    if len(incoming) == 1 and len(existing) <= 4:
        item = incoming[0]
        if item is not None:
            s = item.strip() if type(item) is str else str(item).strip()
            if s and not s.startswith("SENTINEL:") and s not in existing:
                existing.append(s)
        return existing
    seen_existing = set(existing)
    for item in incoming:
        if item is None:
            continue
        s = item.strip() if type(item) is str else str(item).strip()
        if s and not s.startswith("SENTINEL:") and s not in seen_existing:
            seen_existing.add(s)
            existing.append(s)
    return existing


def _extract_clean_cves(raw_cves: Any, cve_cache: Dict[str, Optional[str]]) -> List[str]:
    if not raw_cves:
        return []
    if isinstance(raw_cves, str):
        raw_list: Sequence[Any] = [raw_cves]
    else:
        raw_list = raw_cves
    out: List[str] = []
    seen: Set[str] = set()
    for item in raw_list:
        if not item:
            continue
        key = str(item).strip()
        cached = cve_cache.get(key, "__MISS__")
        if cached == "__MISS__":
            norm = key.upper() if _CVE_RE.match(key) else None
            cve_cache[key] = norm
        else:
            norm = cached  # type: ignore[assignment]
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out


def _safe_int(val: Any) -> Optional[int]:
    if val is None or val == "":
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _safe_float(val: Any) -> Optional[float]:
    if val is None or val == "":
        return None
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def _safe_bool(val: Any) -> Optional[bool]:
    if val is None:
        return None
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        low = val.strip().lower()
        if low in ("true", "1", "yes"):
            return True
        if low in ("false", "0", "no"):
            return False
        return None
    return bool(val)


def _iter_normalized_batches(
    batches: Iterable[Sequence[Dict[str, Any]]] | Sequence[Dict[str, Any]],
) -> Iterable[Sequence[Dict[str, Any]]]:
    if isinstance(batches, (list, tuple)):
        if not batches:
            return
        if isinstance(batches[0], dict):
            yield batches  # type: ignore[misc]
            return
    for batch in batches:
        if batch:
            yield batch  # type: ignore[misc]


def _default_signal_reliability(detection_mode: Optional[str], ingestion_confidence: Optional[float]) -> float:
    if detection_mode:
        val = _DETECTION_MODE_RELIABILITY.get(str(detection_mode).strip().lower())
        if val is not None:
            return val
    if ingestion_confidence is not None:
        return max(0.0, min(1.0, float(ingestion_confidence)))
    return 0.7


_RUN_SCOPED_CHILD_TABLES: Tuple[str, ...] = (
    "ledger_events",
    "triage_decisions",
    "scores",
    "aci_signals",
    "enrichment_snapshots",
    "finding_cves",
    "finding_evidence",
    "findings",
    "asset_aliases",
    "assets",
)


def _clear_run_children(conn: duckdb.DuckDBPyConnection, run_id: str) -> None:
    """Remove all run-scoped child rows for ``run_id`` prior to overwriting or deleting a run."""
    for table in _RUN_SCOPED_CHILD_TABLES:
        conn.execute(f"DELETE FROM {table} WHERE run_id = ?", [run_id])
    conn.execute("DELETE FROM diff_events WHERE base_run_id = ? OR target_run_id = ?", [run_id, run_id])


def delete_run(db: Any, run_id: str) -> None:
    """Atomically delete a run row and all associated child records from DuckDB."""
    conn = _get_conn(db)
    conn.execute("BEGIN TRANSACTION")
    try:
        _clear_run_children(conn, run_id)
        conn.execute("DELETE FROM runs WHERE run_id = ?", [run_id])
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise


def ensure_run(
    db: Any,
    run_id: str,
    *,
    created_at_utc: Optional[str] = None,
    vpp_version: Optional[str] = None,
    profile: Optional[str] = None,
    config_sha256: Optional[str] = None,
    assets_sha256: Optional[str] = None,
    decisions_sha256: Optional[str] = None,
    intel_metadata: Optional[Dict[str, Any]] = None,
    manifest_digest: Optional[str] = None,
    input_files: Optional[Sequence[str]] = None,
    baseline_run_id: Optional[str] = None,
    overwrite: bool = False,
) -> None:
    """Create or update a row in `runs`."""
    conn = _get_conn(db)
    ts = created_at_utc or _utc_now_z()
    intel_json = json.dumps(intel_metadata, sort_keys=True, ensure_ascii=True) if intel_metadata is not None else None
    files_json = json.dumps(list(input_files), ensure_ascii=True) if input_files is not None else None

    if overwrite:
        conn.execute("BEGIN TRANSACTION")
        try:
            _clear_run_children(conn, run_id)
            conn.execute(
                """
                INSERT INTO runs (
                    run_id, created_at_utc, vpp_version, profile,
                    config_sha256, assets_sha256, decisions_sha256,
                    intel_metadata_json, manifest_digest, input_files_json, baseline_run_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (run_id) DO UPDATE SET
                    created_at_utc = EXCLUDED.created_at_utc,
                    vpp_version = COALESCE(EXCLUDED.vpp_version, runs.vpp_version),
                    profile = COALESCE(EXCLUDED.profile, runs.profile),
                    config_sha256 = COALESCE(EXCLUDED.config_sha256, runs.config_sha256),
                    assets_sha256 = COALESCE(EXCLUDED.assets_sha256, runs.assets_sha256),
                    decisions_sha256 = COALESCE(EXCLUDED.decisions_sha256, runs.decisions_sha256),
                    intel_metadata_json = COALESCE(EXCLUDED.intel_metadata_json, runs.intel_metadata_json),
                    manifest_digest = COALESCE(EXCLUDED.manifest_digest, runs.manifest_digest),
                    input_files_json = COALESCE(EXCLUDED.input_files_json, runs.input_files_json),
                    baseline_run_id = COALESCE(EXCLUDED.baseline_run_id, runs.baseline_run_id)
                """,
                [
                    run_id,
                    ts,
                    vpp_version,
                    profile,
                    config_sha256,
                    assets_sha256,
                    decisions_sha256,
                    intel_json,
                    manifest_digest,
                    files_json,
                    baseline_run_id,
                ],
            )
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise
    else:
        conn.execute(
            """
            INSERT INTO runs (
                run_id, created_at_utc, vpp_version, profile,
                config_sha256, assets_sha256, decisions_sha256,
                intel_metadata_json, manifest_digest, input_files_json, baseline_run_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (run_id) DO NOTHING
            """,
            [
                run_id,
                ts,
                vpp_version,
                profile,
                config_sha256,
                assets_sha256,
                decisions_sha256,
                intel_json,
                manifest_digest,
                files_json,
                baseline_run_id,
            ],
        )


def ingest_normalized_batches(
    db: Any,
    run_id: str,
    batches: Iterable[Sequence[Dict[str, Any]]] | Sequence[Dict[str, Any]],
    asset_matcher: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    High-speed columnar ingestion of normalized finding batches into DuckDB.

    Deduplicates findings deterministically per run on:
      - (canonical_asset_id, primary_cve) when CVEs are present (`scoring_track = "cve_threat"`)
      - (canonical_asset_id, nocve_key) when CVEs are absent (`scoring_track = "exposure_weakness"`)

    Preserves all contributing scanner detections in `finding_evidence` and distinct CVEs
    in `finding_cves`. Uses DuckDB Appender (`append_rows`) for high throughput.
    """
    conn = _get_conn(db)
    ensure_run(conn, run_id)

    existing_count = conn.execute("SELECT COUNT(*) FROM findings WHERE run_id = ?", [run_id]).fetchone()[0]
    incremental = existing_count > 0

    cve_cache: Dict[str, Optional[str]] = {}
    asset_resolve_cache: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    fid_cache: Dict[Tuple[str, str], str] = {}
    sig_rel_cache: Dict[Tuple[Any, Any], float] = {}
    json_list_cache: Dict[Tuple[Any, ...], str] = {}
    seen_target_tuples: Set[Tuple[Any, ...]] = set()

    # Track assets & aliases
    assets_map: Dict[str, Dict[str, Any]] = {}
    existing_asset_ids: Set[str] = set()
    existing_shadow_asset_ids: Set[str] = set()
    existing_asset_ports: Dict[str, Set[int]] = {}
    alias_set: Set[Tuple[str, str, str]] = set()
    existing_alias_set: Set[Tuple[str, str, str]] = set()

    # Track deduplicated findings (keyed by finding_id)
    findings_map: Dict[str, _PendingFinding] = {}
    existing_finding_ids: Set[str] = set()
    existing_finding_cves: Set[Tuple[str, str]] = set()
    ev_next_idx: Dict[str, int] = {}

    if incremental:
        for row in conn.execute("SELECT asset_id, open_ports_json, inventory_status FROM assets WHERE run_id = ?", [run_id]).fetchall():
            existing_asset_ids.add(row[0])
            if row[2] == "unmatched_shadow":
                existing_shadow_asset_ids.add(row[0])
            existing_asset_ports[row[0]] = {
                int(p) for p in _json_loads_safe(row[1], []) if _safe_int(p) is not None
            }
        for row in conn.execute(
            "SELECT asset_id, alias_type, alias_value FROM asset_aliases WHERE run_id = ?",
            [run_id],
        ).fetchall():
            existing_alias_set.add((row[0], row[1], row[2]))
        for row in conn.execute(
            "SELECT finding_id, COALESCE(MAX(evidence_idx), -1) + 1 FROM finding_evidence WHERE run_id = ? GROUP BY finding_id",
            [run_id],
        ).fetchall():
            ev_next_idx[row[0]] = int(row[1])
        for row in conn.execute(
            "SELECT finding_id, cve_id FROM finding_cves WHERE run_id = ?",
            [run_id],
        ).fetchall():
            existing_finding_cves.add((row[0], row[1]))
        for row in conn.execute(
            """
            SELECT finding_id, asset_id, scoring_track, primary_cve, cves_json, cwes_json, ghsa_ids_json,
                   title, description, solution, plugin_output, affected_port, protocol, service_name,
                   location_uri, line_number, package_purl, scanner_severity, scanner_cvss_score,
                   scanner_cvss_vector, detection_mode, signal_reliability, ingestion_confidence,
                   fidelity_tier, source_format, references_json, tags_json, exploit_evidence,
                   is_deduplicated, source_count
            FROM findings WHERE run_id = ?
            """,
            [run_id],
        ).fetchall():
            fid = row[0]
            existing_finding_ids.add(fid)
            pf = _PendingFinding(
                finding_id=fid,
                asset_id=row[1],
                scoring_track=row[2],
                primary_cve=row[3],
                cves=_json_loads_safe(row[4], []),
                cwes=_json_loads_safe(row[5], []),
                ghsa_ids=_json_loads_safe(row[6], []),
                title=row[7],
                description=row[8] or "",
                solution=row[9] or "",
                plugin_output=row[10] or "",
                affected_port=row[11],
                protocol=row[12],
                service_name=row[13],
                location_uri=row[14],
                line_number=row[15],
                package_purl=row[16],
                scanner_severity=row[17],
                scanner_cvss_score=row[18],
                scanner_cvss_vector=row[19],
                detection_mode=row[20],
                signal_reliability=row[21] if row[21] is not None else 0.7,
                ingestion_confidence=row[22] if row[22] is not None else 0.0,
                fidelity_tier=row[23],
                source_format=row[24],
                references=_json_loads_safe(row[25], []),
                tags=_json_loads_safe(row[26], []),
                exploit_evidence=row[27],
                source_count=int(row[29] or 1),
                initial_source_sig=(row[24], None),
            )
            pf.seen_sigs = set()
            findings_map[fid] = pf

    raw_count = 0
    evidence_buffer: List[Tuple[Any, ...]] = []
    evidence_flush_threshold = 25_000

    json_dumps = json.dumps
    severity_rank = _SEVERITY_RANK

    def _resolve_asset(rec: Dict[str, Any]) -> Dict[str, Any]:
        raw_ip = rec.get("ip_address")
        raw_host = rec.get("hostname")
        raw_uri = rec.get("target_uri")
        raw_img = rec.get("image_or_repo")
        explicit_aid = rec.get("asset_id")
        cache_key = (raw_ip, raw_host, raw_uri, raw_img, explicit_aid)
        cached = asset_resolve_cache.get(cache_key)
        if cached is not None:
            return cached

        if asset_matcher is not None:
            matched = asset_matcher.resolve(
                ip=raw_ip,
                hostname=raw_host,
                target_uri=raw_uri,
                image_or_repo=raw_img,
                asset_id=explicit_aid,
            )
            info = {
                "asset_id": matched.asset_id,
                "canonical_key": matched.canonical_key,
                "hostname": normalize_hostname_value(raw_host),
                "ip_address": normalize_ip_value(raw_ip),
                "target_uri": normalize_target_uri(raw_uri),
                "image_or_repo": normalize_image_or_repo(raw_img),
                "declared_criticality": matched.declared_criticality,
                "internet_facing": matched.internet_facing,
                "owner": matched.owner,
                "env_tags": list(matched.env_tags) if getattr(matched, "env_tags", None) else [],
                "tags": dict(matched.tags) if getattr(matched, "tags", None) else {},
                "inventory_status": matched.inventory_status,
                "matched_rule_id": matched.matched_rule_id,
                "rule_aliases": list(getattr(matched, "aliases", ()) or ()),
            }
        else:
            ckey = canonicalize_target_key(
                ip=raw_ip,
                hostname=raw_host,
                target_uri=raw_uri,
                image_or_repo=raw_img,
                explicit_asset_id=explicit_aid,
            )
            aid = explicit_aid or make_asset_id_v2(ckey)
            info = {
                "asset_id": aid,
                "canonical_key": ckey,
                "hostname": normalize_hostname_value(raw_host),
                "ip_address": normalize_ip_value(raw_ip),
                "target_uri": normalize_target_uri(raw_uri),
                "image_or_repo": normalize_image_or_repo(raw_img),
                "declared_criticality": None,
                "internet_facing": None,
                "owner": None,
                "env_tags": [],
                "tags": {},
                "inventory_status": "unmatched_shadow",
                "matched_rule_id": None,
                "rule_aliases": [],
            }

        asset_resolve_cache[cache_key] = info
        return info

    conn.execute("BEGIN TRANSACTION")
    try:
        with conn.appender("finding_evidence") as ev_appender:
            for batch in _iter_normalized_batches(batches):
                for rec in batch:
                    raw_count += 1
                    rec_get = rec.get
                    raw_ip = rec_get("ip_address")
                    raw_host = rec_get("hostname")
                    raw_uri = rec_get("target_uri")
                    raw_img = rec_get("image_or_repo")
                    explicit_aid = rec_get("asset_id")
                    t_key = (raw_ip, raw_host, raw_uri, raw_img, explicit_aid)

                    ainfo = asset_resolve_cache.get(t_key)
                    if ainfo is None:
                        ainfo = _resolve_asset(rec)
                    aid = ainfo["asset_id"]

                    raw_aff_port = rec_get("affected_port")
                    aff_port = raw_aff_port if type(raw_aff_port) is int else _safe_int(raw_aff_port)

                    asset_rec = assets_map.get(aid)
                    if asset_rec is None or t_key not in seen_target_tuples:
                        seen_target_tuples.add(t_key)
                        asset_meta = rec_get("asset_metadata") or {}
                        rec_ports = asset_meta.get("open_ports") or ()

                        if asset_rec is None:
                            ports_set: Set[int] = set(existing_asset_ports.get(aid, ()))
                            for p in rec_ports:
                                pi = p if type(p) is int else _safe_int(p)
                                if pi is not None and 0 < pi <= 65535:
                                    ports_set.add(pi)
                            if aff_port is not None and 0 < aff_port <= 65535:
                                ports_set.add(aff_port)

                            env_payload: Dict[str, Any] = {
                                "env": ainfo["env_tags"],
                                "tags": ainfo["tags"],
                            }

                            asset_rec = {
                                "asset_id": aid,
                                "canonical_key": ainfo["canonical_key"],
                                "hostname": ainfo["hostname"] or raw_host,
                                "ip_address": ainfo["ip_address"] or raw_ip,
                                "target_uri": ainfo["target_uri"] or raw_uri,
                                "image_or_repo": ainfo["image_or_repo"] or raw_img,
                                "os": rec_get("os"),
                                "declared_criticality": ainfo["declared_criticality"],
                                "derived_criticality": None,
                                "internet_facing": ainfo["internet_facing"],
                                "owner": ainfo["owner"],
                                "env_tags_payload": env_payload,
                                "inventory_status": ainfo["inventory_status"],
                                "matched_rule_id": ainfo["matched_rule_id"],
                                "open_ports": ports_set,
                            }
                            assets_map[aid] = asset_rec

                            for rule_alias in ainfo["rule_aliases"]:
                                pair = (aid, "rule_alias", str(rule_alias))
                                if pair not in existing_alias_set:
                                    alias_set.add(pair)
                        else:
                            if not asset_rec["hostname"] and (ainfo["hostname"] or raw_host):
                                asset_rec["hostname"] = ainfo["hostname"] or raw_host
                            if not asset_rec["ip_address"] and (ainfo["ip_address"] or raw_ip):
                                asset_rec["ip_address"] = ainfo["ip_address"] or raw_ip
                            if not asset_rec["target_uri"] and (ainfo["target_uri"] or raw_uri):
                                asset_rec["target_uri"] = ainfo["target_uri"] or raw_uri
                            if not asset_rec["image_or_repo"] and (ainfo["image_or_repo"] or raw_img):
                                asset_rec["image_or_repo"] = ainfo["image_or_repo"] or raw_img
                            if not asset_rec["os"] and rec_get("os"):
                                asset_rec["os"] = rec_get("os")
                            ports_set = asset_rec["open_ports"]
                            for p in rec_ports:
                                pi = p if type(p) is int else _safe_int(p)
                                if pi is not None and 0 < pi <= 65535:
                                    ports_set.add(pi)
                            if aff_port is not None and 0 < aff_port <= 65535:
                                ports_set.add(aff_port)

                        if ainfo["ip_address"]:
                            ip_alias = (aid, "ip", ainfo["ip_address"])
                            if ip_alias not in existing_alias_set:
                                alias_set.add(ip_alias)
                        if ainfo["hostname"]:
                            host_alias = (aid, "hostname", ainfo["hostname"])
                            if host_alias not in existing_alias_set:
                                alias_set.add(host_alias)
                        if ainfo["target_uri"]:
                            uri_alias = (aid, "target_uri", ainfo["target_uri"])
                            if uri_alias not in existing_alias_set:
                                alias_set.add(uri_alias)
                        if ainfo["image_or_repo"]:
                            img_alias = (aid, "image_or_repo", ainfo["image_or_repo"])
                            if img_alias not in existing_alias_set:
                                alias_set.add(img_alias)
                    elif aff_port is not None and 0 < aff_port <= 65535:
                        asset_rec["open_ports"].add(aff_port)

                    raw_cves = rec_get("cves")
                    explicit_pcve = rec_get("primary_cve")
                    if (
                        not explicit_pcve
                        and type(raw_cves) is list
                        and len(raw_cves) == 1
                        and type(raw_cves[0]) is str
                    ):
                        c0 = raw_cves[0]
                        norm_c0 = cve_cache.get(c0, "__MISS__")
                        if norm_c0 == "__MISS__":
                            c0_s = c0.strip()
                            norm_c0 = c0_s.upper() if _CVE_RE.match(c0_s) else None
                            cve_cache[c0] = norm_c0
                        if norm_c0 is not None:
                            clean_cves = [norm_c0]
                            primary_cve: Optional[str] = norm_c0
                        else:
                            clean_cves = []
                            primary_cve = None
                    elif not raw_cves and not explicit_pcve:
                        clean_cves = []
                        primary_cve = None
                    else:
                        clean_cves = _extract_clean_cves(raw_cves, cve_cache)
                        primary_cve = None
                        if explicit_pcve:
                            ep_list = _extract_clean_cves([explicit_pcve], cve_cache)
                            if ep_list:
                                primary_cve = ep_list[0]
                                if primary_cve not in clean_cves:
                                    clean_cves.insert(0, primary_cve)
                        if primary_cve is None and clean_cves:
                            primary_cve = clean_cves[0] if len(clean_cves) == 1 else sorted(clean_cves)[0]

                    scanner_sig = rec_get("scanner_sig") or ""
                    if type(scanner_sig) is not str:
                        scanner_sig = str(scanner_sig)
                    scanner_sig = scanner_sig.strip()

                    raw_title = rec_get("title")
                    title = raw_title.strip() if type(raw_title) is str and raw_title.strip() else (str(raw_title or scanner_sig or "Untitled Finding").strip())

                    raw_proto = rec_get("protocol")
                    proto = raw_proto.strip().lower() if type(raw_proto) is str and raw_proto.strip() else None
                    loc_uri = rec_get("location_uri")
                    raw_line = rec_get("line_number")
                    line_num = raw_line if type(raw_line) is int else _safe_int(raw_line)
                    purl = rec_get("package_purl")

                    if primary_cve is not None:
                        scoring_track = "cve_threat"
                        fid_key = (aid, primary_cve)
                        fid = fid_cache.get(fid_key)
                        if fid is None:
                            fid = make_finding_id_v2(aid, f"cve={primary_cve}")
                            if len(fid_cache) < 250_000:
                                fid_cache[fid_key] = fid
                    else:
                        scoring_track = "exposure_weakness"
                        loc_part = str(loc_uri or raw_uri or "").strip()
                        sig_part = scanner_sig.lower()
                        norm_title = " ".join(title.lower().split())[:120]
                        dedup_key = (
                            f"nocve|sig={sig_part}|svc={proto or '-'}:{aff_port if aff_port is not None else '-'}|"
                            f"loc={loc_part}|line={line_num if line_num is not None else '-'}|"
                            f"purl={purl or '-'}|title={norm_title}"
                        )
                        fid = make_finding_id_v2(aid, dedup_key)

                    ev_idx = ev_next_idx.get(fid, 0)
                    ev_next_idx[fid] = ev_idx + 1

                    source_fmt = rec_get("source_format")
                    raw_sev = rec_get("severity")
                    raw_cvss_in = rec_get("scanner_cvss_score")
                    raw_cvss = raw_cvss_in if type(raw_cvss_in) is float else _safe_float(raw_cvss_in)
                    raw_loc = (
                        rec_get("raw_location")
                        or loc_uri
                        or raw_uri
                        or (f"{proto or 'tcp'}:{aff_port}" if aff_port is not None else None)
                    )
                    ev_excerpt = rec_get("raw_evidence_excerpt")
                    if ev_excerpt is None:
                        ev_excerpt = (rec_get("plugin_output") or "")[:512]
                    elif type(ev_excerpt) is not str:
                        ev_excerpt = str(ev_excerpt)

                    evidence_buffer.append(
                        (
                            run_id,
                            fid,
                            ev_idx,
                            source_fmt,
                            scanner_sig,
                            raw_sev,
                            raw_cvss,
                            raw_loc,
                            ev_excerpt,
                        )
                    )
                    if len(evidence_buffer) >= evidence_flush_threshold:
                        ev_appender.append_rows(evidence_buffer)
                        evidence_buffer.clear()

                    raw_ing = rec_get("ingestion_confidence")
                    ing_conf = raw_ing if type(raw_ing) is float else _safe_float(raw_ing)
                    det_mode = rec_get("detection_mode")
                    raw_sig_rel = rec_get("signal_reliability")
                    if raw_sig_rel is not None:
                        sig_rel = raw_sig_rel if type(raw_sig_rel) is float else _safe_float(raw_sig_rel)
                    else:
                        sr_key = (det_mode, ing_conf)
                        sig_rel = sig_rel_cache.get(sr_key)
                        if sig_rel is None:
                            sig_rel = _default_signal_reliability(det_mode, ing_conf)
                            sig_rel_cache[sr_key] = sig_rel

                    raw_exp = rec_get("exploit_evidence")
                    exp_ev = raw_exp if (raw_exp is None or type(raw_exp) is bool) else _safe_bool(raw_exp)

                    existing_f = findings_map.get(fid)
                    if existing_f is None:
                        raw_cwes = rec_get("cwes")
                        raw_ghsa = rec_get("ghsa_ids")
                        raw_refs = rec_get("references")
                        raw_tags = rec_get("tags")
                        findings_map[fid] = _PendingFinding(
                            finding_id=fid,
                            asset_id=aid,
                            scoring_track=scoring_track,
                            primary_cve=primary_cve,
                            cves=clean_cves,
                            cwes=_merge_unique_strs([], raw_cwes) if raw_cwes else [],
                            ghsa_ids=_merge_unique_strs([], raw_ghsa) if raw_ghsa else [],
                            title=title,
                            description=rec_get("description") or "",
                            solution=rec_get("solution") or "",
                            plugin_output=rec_get("plugin_output") or "",
                            affected_port=aff_port,
                            protocol=proto,
                            service_name=rec_get("service_name"),
                            location_uri=loc_uri,
                            line_number=line_num,
                            package_purl=purl,
                            scanner_severity=raw_sev,
                            scanner_cvss_score=raw_cvss,
                            scanner_cvss_vector=rec_get("scanner_cvss_vector"),
                            detection_mode=det_mode,
                            signal_reliability=sig_rel,
                            ingestion_confidence=ing_conf if ing_conf is not None else 0.0,
                            fidelity_tier=rec_get("fidelity_tier"),
                            source_format=source_fmt,
                            references=_merge_unique_strs([], raw_refs) if raw_refs else [],
                            tags=_merge_unique_strs([], raw_tags) if raw_tags else [],
                            exploit_evidence=exp_ev,
                            source_count=1,
                            initial_source_sig=(source_fmt, scanner_sig),
                        )
                    else:
                        existing_f.source_count += 1
                        if len(clean_cves) > 1 or (clean_cves and clean_cves[0] not in existing_f.cves):
                            _merge_unique_strs(existing_f.cves, clean_cves)

                        sig_pair = (source_fmt, scanner_sig)
                        seen_sigs = existing_f.seen_sigs
                        if seen_sigs is None:
                            if sig_pair != existing_f.initial_source_sig or incremental:
                                seen_sigs = {existing_f.initial_source_sig, sig_pair}
                                existing_f.seen_sigs = seen_sigs
                                need_merge = True
                            else:
                                need_merge = False
                        elif sig_pair not in seen_sigs or incremental:
                            seen_sigs.add(sig_pair)
                            need_merge = True
                        else:
                            need_merge = False

                        if need_merge:
                            raw_cwes = rec_get("cwes")
                            if raw_cwes:
                                _merge_unique_strs(existing_f.cwes, raw_cwes)
                            raw_ghsa = rec_get("ghsa_ids")
                            if raw_ghsa:
                                _merge_unique_strs(existing_f.ghsa_ids, raw_ghsa)
                            raw_refs = rec_get("references")
                            if raw_refs:
                                _merge_unique_strs(existing_f.references, raw_refs)
                            raw_tags = rec_get("tags")
                            if raw_tags:
                                _merge_unique_strs(existing_f.tags, raw_tags)

                        if exp_ev is True:
                            existing_f.exploit_evidence = True
                        elif exp_ev is False and existing_f.exploit_evidence is None:
                            existing_f.exploit_evidence = False

                        # Prefer richer signal detection for primary display metadata
                        cur_score = (
                            float(existing_f.signal_reliability or 0.0),
                            float(existing_f.ingestion_confidence or 0.0),
                            severity_rank.get(str(existing_f.scanner_severity or "").lower(), 0),
                        )
                        new_score = (
                            float(sig_rel or 0.0),
                            float(ing_conf or 0.0),
                            severity_rank.get(str(raw_sev or "").lower(), 0),
                        )
                        if new_score > cur_score:
                            existing_f.title = title or existing_f.title
                            existing_f.scanner_severity = raw_sev or existing_f.scanner_severity
                            existing_f.detection_mode = det_mode or existing_f.detection_mode
                            existing_f.signal_reliability = sig_rel
                            existing_f.ingestion_confidence = ing_conf if ing_conf is not None else existing_f.ingestion_confidence
                            existing_f.fidelity_tier = rec_get("fidelity_tier") or existing_f.fidelity_tier
                            existing_f.source_format = source_fmt or existing_f.source_format
                            if rec_get("description"):
                                existing_f.description = str(rec_get("description"))
                            if rec_get("solution"):
                                existing_f.solution = str(rec_get("solution"))
                            if rec_get("plugin_output"):
                                existing_f.plugin_output = str(rec_get("plugin_output"))
                            if raw_cvss is not None:
                                existing_f.scanner_cvss_score = raw_cvss
                            if rec_get("scanner_cvss_vector"):
                                existing_f.scanner_cvss_vector = rec_get("scanner_cvss_vector")

                        if not existing_f.description and rec_get("description"):
                            existing_f.description = str(rec_get("description"))
                        if not existing_f.solution and rec_get("solution"):
                            existing_f.solution = str(rec_get("solution"))
                        if not existing_f.plugin_output and rec_get("plugin_output"):
                            existing_f.plugin_output = str(rec_get("plugin_output"))
                        if existing_f.affected_port is None and aff_port is not None:
                            existing_f.affected_port = aff_port
                        if not existing_f.protocol and proto:
                            existing_f.protocol = proto
                        if not existing_f.service_name and rec_get("service_name"):
                            existing_f.service_name = rec_get("service_name")
                        if not existing_f.location_uri and loc_uri:
                            existing_f.location_uri = loc_uri
                        if existing_f.line_number is None and line_num is not None:
                            existing_f.line_number = line_num
                        if not existing_f.package_purl and purl:
                            existing_f.package_purl = purl
                        if existing_f.scanner_cvss_score is None and raw_cvss is not None:
                            existing_f.scanner_cvss_score = raw_cvss
                        if not existing_f.scanner_cvss_vector and rec_get("scanner_cvss_vector"):
                            existing_f.scanner_cvss_vector = rec_get("scanner_cvss_vector")

            if evidence_buffer:
                ev_appender.append_rows(evidence_buffer)
                evidence_buffer.clear()

        ev_next_idx.clear()

        # Prepare bulk tuples for assets, asset_aliases, findings, finding_cves
        new_asset_rows: List[Tuple[Any, ...]] = []
        update_asset_rows: List[Tuple[Any, ...]] = []
        for aid, a in assets_map.items():
            ports_json = json_dumps(sorted(a["open_ports"])) if a["open_ports"] else "[]"
            env_tags_json = json_dumps(a["env_tags_payload"], sort_keys=True, ensure_ascii=True)
            row_tuple = (
                run_id,
                aid,
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
                env_tags_json,
                a["inventory_status"],
                a["matched_rule_id"],
                ports_json,
            )
            if aid in existing_asset_ids:
                update_asset_rows.append(row_tuple)
            else:
                new_asset_rows.append(row_tuple)

        if new_asset_rows:
            with conn.appender("assets") as asset_app:
                asset_app.append_rows(new_asset_rows)

        if update_asset_rows:
            conn.execute(
                """
                CREATE TEMP TABLE _stg_assets (
                    run_id VARCHAR, asset_id VARCHAR, canonical_key VARCHAR, hostname VARCHAR,
                    ip_address VARCHAR, target_uri VARCHAR, image_or_repo VARCHAR, os VARCHAR,
                    declared_criticality VARCHAR, derived_criticality VARCHAR, internet_facing BOOLEAN,
                    owner VARCHAR, env_tags_json VARCHAR, inventory_status VARCHAR,
                    matched_rule_id VARCHAR, open_ports_json VARCHAR
                )
                """
            )
            with conn.appender("_stg_assets") as stg_a_app:
                stg_a_app.append_rows(update_asset_rows)
            conn.execute(
                """
                INSERT INTO assets
                SELECT * FROM _stg_assets
                ON CONFLICT (run_id, asset_id) DO UPDATE SET
                    hostname = COALESCE(assets.hostname, EXCLUDED.hostname),
                    ip_address = COALESCE(assets.ip_address, EXCLUDED.ip_address),
                    target_uri = COALESCE(assets.target_uri, EXCLUDED.target_uri),
                    image_or_repo = COALESCE(assets.image_or_repo, EXCLUDED.image_or_repo),
                    os = COALESCE(assets.os, EXCLUDED.os),
                    open_ports_json = EXCLUDED.open_ports_json
                """
            )
            conn.execute("DROP TABLE _stg_assets")

        if alias_set:
            alias_rows = [(run_id, aid, atype, aval) for (aid, atype, aval) in sorted(alias_set)]
            with conn.appender("asset_aliases") as alias_app:
                alias_app.append_rows(alias_rows)

        update_finding_rows: List[Tuple[Any, ...]] = []
        dedup_count = 0
        cve_links_count = 0
        all_asset_ids = existing_asset_ids | set(assets_map.keys())
        assets_count = len(all_asset_ids)
        shadow_asset_ids = (
            existing_shadow_asset_ids
            - {aid for aid, a in assets_map.items() if a["inventory_status"] != "unmatched_shadow"}
        ) | {aid for aid, a in assets_map.items() if a["inventory_status"] == "unmatched_shadow"}
        shadow_count = len(shadow_asset_ids)
        unique_findings_count = len(findings_map)
        assets_map.clear()
        fid_cache.clear()
        asset_resolve_cache.clear()
        seen_target_tuples.clear()

        finding_buf: List[Tuple[Any, ...]] = []
        with conn.appender("findings") as f_app:
            for fid, f in findings_map.items():
                src_cnt = int(f.source_count)
                is_dedup = src_cnt > 1
                if is_dedup:
                    dedup_count += 1

                row_tuple = (
                    run_id,
                    fid,
                    f.asset_id,
                    f.scoring_track,
                    f.primary_cve,
                    _json_dumps_list(f.cves, json_list_cache),
                    _json_dumps_list(f.cwes, json_list_cache),
                    _json_dumps_list(f.ghsa_ids, json_list_cache),
                    f.title,
                    f.description,
                    f.solution,
                    f.plugin_output,
                    f.affected_port,
                    f.protocol,
                    f.service_name,
                    f.location_uri,
                    f.line_number,
                    f.package_purl,
                    f.scanner_severity,
                    f.scanner_cvss_score,
                    f.scanner_cvss_vector,
                    f.detection_mode,
                    f.signal_reliability,
                    f.ingestion_confidence,
                    f.fidelity_tier,
                    f.source_format,
                    _json_dumps_list(f.references, json_list_cache),
                    _json_dumps_list(f.tags, json_list_cache),
                    f.exploit_evidence,
                    is_dedup,
                    src_cnt,
                )
                if incremental and fid in existing_finding_ids:
                    update_finding_rows.append(row_tuple)
                else:
                    finding_buf.append(row_tuple)
                    if len(finding_buf) >= 25_000:
                        f_app.append_rows(finding_buf)
                        finding_buf.clear()
            if finding_buf:
                f_app.append_rows(finding_buf)
                finding_buf.clear()

        if update_finding_rows:
            conn.execute(
                """
                CREATE TEMP TABLE _stg_findings (
                    run_id VARCHAR, finding_id VARCHAR, asset_id VARCHAR, scoring_track VARCHAR,
                    primary_cve VARCHAR, cves_json VARCHAR, cwes_json VARCHAR, ghsa_ids_json VARCHAR,
                    title VARCHAR, description VARCHAR, solution VARCHAR, plugin_output VARCHAR,
                    affected_port INTEGER, protocol VARCHAR, service_name VARCHAR, location_uri VARCHAR,
                    line_number INTEGER, package_purl VARCHAR, scanner_severity VARCHAR,
                    scanner_cvss_score DOUBLE, scanner_cvss_vector VARCHAR, detection_mode VARCHAR,
                    signal_reliability DOUBLE, ingestion_confidence DOUBLE, fidelity_tier VARCHAR,
                    source_format VARCHAR, references_json VARCHAR, tags_json VARCHAR,
                    exploit_evidence BOOLEAN, is_deduplicated BOOLEAN, source_count INTEGER
                )
                """
            )
            with conn.appender("_stg_findings") as stg_f_app:
                for off in range(0, len(update_finding_rows), 25_000):
                    stg_f_app.append_rows(update_finding_rows[off : off + 25_000])
            conn.execute(
                """
                INSERT INTO findings
                SELECT * FROM _stg_findings
                ON CONFLICT (run_id, finding_id) DO UPDATE SET
                    cves_json = EXCLUDED.cves_json,
                    cwes_json = EXCLUDED.cwes_json,
                    ghsa_ids_json = EXCLUDED.ghsa_ids_json,
                    title = EXCLUDED.title,
                    description = EXCLUDED.description,
                    solution = EXCLUDED.solution,
                    plugin_output = EXCLUDED.plugin_output,
                    affected_port = EXCLUDED.affected_port,
                    protocol = EXCLUDED.protocol,
                    service_name = EXCLUDED.service_name,
                    location_uri = EXCLUDED.location_uri,
                    line_number = EXCLUDED.line_number,
                    package_purl = EXCLUDED.package_purl,
                    scanner_severity = EXCLUDED.scanner_severity,
                    scanner_cvss_score = EXCLUDED.scanner_cvss_score,
                    scanner_cvss_vector = EXCLUDED.scanner_cvss_vector,
                    detection_mode = EXCLUDED.detection_mode,
                    signal_reliability = EXCLUDED.signal_reliability,
                    ingestion_confidence = EXCLUDED.ingestion_confidence,
                    fidelity_tier = EXCLUDED.fidelity_tier,
                    source_format = EXCLUDED.source_format,
                    references_json = EXCLUDED.references_json,
                    tags_json = EXCLUDED.tags_json,
                    exploit_evidence = EXCLUDED.exploit_evidence,
                    is_deduplicated = EXCLUDED.is_deduplicated,
                    source_count = EXCLUDED.source_count
                """
            )
            conn.execute("DROP TABLE _stg_findings")
            update_finding_rows.clear()

        cve_buf: List[Tuple[str, str, str]] = []
        with conn.appender("finding_cves") as fc_app:
            if incremental:
                for fid, f in findings_map.items():
                    for cve_id in f.cves:
                        cve_norm = str(cve_id).strip().upper()
                        if not cve_norm:
                            continue
                        pair = (fid, cve_norm)
                        if pair not in existing_finding_cves:
                            existing_finding_cves.add(pair)
                            cve_buf.append((run_id, fid, cve_norm))
                            cve_links_count += 1
                            if len(cve_buf) >= 25_000:
                                fc_app.append_rows(cve_buf)
                                cve_buf.clear()
            else:
                for fid, f in findings_map.items():
                    f_cves = f.cves
                    if len(f_cves) == 1:
                        cve_norm = str(f_cves[0]).strip().upper()
                        if cve_norm:
                            cve_buf.append((run_id, fid, cve_norm))
                            cve_links_count += 1
                    elif f_cves:
                        seen_cves: Set[str] = set()
                        for cve_id in f_cves:
                            cve_norm = str(cve_id).strip().upper()
                            if cve_norm and cve_norm not in seen_cves:
                                seen_cves.add(cve_norm)
                                cve_buf.append((run_id, fid, cve_norm))
                                cve_links_count += 1
                    if len(cve_buf) >= 25_000:
                        fc_app.append_rows(cve_buf)
                        cve_buf.clear()
            if cve_buf:
                fc_app.append_rows(cve_buf)
                cve_buf.clear()

        existing_finding_cves.clear()
        findings_map.clear()
        json_list_cache.clear()
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise

    return {
        "run_id": run_id,
        "assets_ingested": assets_count,
        "shadow_assets": shadow_count,
        "raw_findings_ingested": raw_count,
        "unique_findings_ingested": unique_findings_count,
        "deduplicated_findings": dedup_count,
        "cve_links_ingested": cve_links_count,
    }


def upsert_enrichment_snapshots(db: Any, run_id: str, snapshots: Sequence[Dict[str, Any]]) -> int:
    """Bulk upsert CVE enrichment snapshots for a run."""
    if not snapshots:
        return 0
    conn = _get_conn(db)
    ensure_run(conn, run_id)
    rows: List[Tuple[Any, ...]] = []
    for s in snapshots:
        rows.append(
            (
                run_id,
                str(s["cve_id"]).upper(),
                _safe_float(s.get("cvss_score")),
                s.get("cvss_vector"),
                s.get("cvss_version"),
                s.get("cvss_provenance"),
                _safe_float(s.get("epss_score")),
                _safe_float(s.get("epss_percentile")),
                s.get("epss_model_version"),
                s.get("epss_date"),
                _safe_bool(s.get("in_kev")),
                s.get("kev_date_added"),
                s.get("kev_due_date"),
                s.get("kev_ransomware"),
                s.get("kev_required_action"),
                _safe_bool(s.get("verified_exploit")),
                _safe_bool(s.get("heuristic_exploit_mention")),
                json.dumps(s.get("exploit_refs") or [], ensure_ascii=True),
                json.dumps(s.get("ghsa_ids") or [], ensure_ascii=True),
                json.dumps(s.get("osv_ids") or [], ensure_ascii=True),
                _safe_float(s.get("enrichment_confidence")),
                json.dumps(s.get("sources") or [], ensure_ascii=True),
            )
        )
    conn.execute("BEGIN TRANSACTION")
    try:
        conn.execute(
            """
            CREATE TEMP TABLE _stg_enrich (
                run_id VARCHAR, cve_id VARCHAR, cvss_score DOUBLE, cvss_vector VARCHAR,
                cvss_version VARCHAR, cvss_provenance VARCHAR, epss_score DOUBLE,
                epss_percentile DOUBLE, epss_model_version VARCHAR, epss_date VARCHAR,
                in_kev BOOLEAN, kev_date_added VARCHAR, kev_due_date VARCHAR,
                kev_ransomware VARCHAR, kev_required_action VARCHAR, verified_exploit BOOLEAN,
                heuristic_exploit_mention BOOLEAN, exploit_refs_json VARCHAR, ghsa_ids_json VARCHAR,
                osv_ids_json VARCHAR, enrichment_confidence DOUBLE, sources_json VARCHAR
            )
            """
        )
        with conn.appender("_stg_enrich") as app:
            app.append_rows(rows)
        conn.execute(
            """
            INSERT INTO enrichment_snapshots
            SELECT * FROM _stg_enrich
            ON CONFLICT (run_id, cve_id) DO UPDATE SET
                cvss_score = EXCLUDED.cvss_score,
                cvss_vector = EXCLUDED.cvss_vector,
                cvss_version = EXCLUDED.cvss_version,
                cvss_provenance = EXCLUDED.cvss_provenance,
                epss_score = EXCLUDED.epss_score,
                epss_percentile = EXCLUDED.epss_percentile,
                epss_model_version = EXCLUDED.epss_model_version,
                epss_date = EXCLUDED.epss_date,
                in_kev = EXCLUDED.in_kev,
                kev_date_added = EXCLUDED.kev_date_added,
                kev_due_date = EXCLUDED.kev_due_date,
                kev_ransomware = EXCLUDED.kev_ransomware,
                kev_required_action = EXCLUDED.kev_required_action,
                verified_exploit = EXCLUDED.verified_exploit,
                heuristic_exploit_mention = EXCLUDED.heuristic_exploit_mention,
                exploit_refs_json = EXCLUDED.exploit_refs_json,
                ghsa_ids_json = EXCLUDED.ghsa_ids_json,
                osv_ids_json = EXCLUDED.osv_ids_json,
                enrichment_confidence = EXCLUDED.enrichment_confidence,
                sources_json = EXCLUDED.sources_json
            """
        )
        conn.execute("DROP TABLE _stg_enrich")
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    return len(rows)


def upsert_aci_signals(db: Any, run_id: str, signals: Sequence[Dict[str, Any]]) -> int:
    """Bulk upsert ACI signals for a run."""
    if not signals:
        return 0
    conn = _get_conn(db)
    rows = [
        (
            run_id,
            s["finding_id"],
            s["asset_id"],
            json.dumps(s.get("capabilities") or [], ensure_ascii=True),
            json.dumps(s.get("chains") or [], ensure_ascii=True),
            json.dumps(s.get("matched_tokens") or [], ensure_ascii=True),
            _safe_float(s.get("confidence")),
            _safe_float(s.get("uplift_score")),
        )
        for s in signals
    ]
    conn.execute("BEGIN TRANSACTION")
    try:
        conn.execute(
            """
            CREATE TEMP TABLE _stg_aci (
                run_id VARCHAR, finding_id VARCHAR, asset_id VARCHAR,
                capabilities_json VARCHAR, chains_json VARCHAR, matched_tokens_json VARCHAR,
                confidence DOUBLE, uplift_score DOUBLE
            )
            """
        )
        with conn.appender("_stg_aci") as app:
            app.append_rows(rows)
        conn.execute(
            """
            INSERT INTO aci_signals
            SELECT * FROM _stg_aci
            ON CONFLICT (run_id, finding_id) DO UPDATE SET
                asset_id = EXCLUDED.asset_id,
                capabilities_json = EXCLUDED.capabilities_json,
                chains_json = EXCLUDED.chains_json,
                matched_tokens_json = EXCLUDED.matched_tokens_json,
                confidence = EXCLUDED.confidence,
                uplift_score = EXCLUDED.uplift_score
            """
        )
        conn.execute("DROP TABLE _stg_aci")
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    return len(rows)


def upsert_scores(db: Any, run_id: str, scores: Sequence[Dict[str, Any]]) -> int:
    """Bulk upsert finding scores for a run."""
    if not scores:
        return 0
    conn = _get_conn(db)
    rows = [
        (
            run_id,
            s["finding_id"],
            s["asset_id"],
            s.get("scoring_track") or "cve_threat",
            _safe_float(s.get("raw_risk_score")),
            _safe_float(s.get("operational_score")),
            s.get("risk_band"),
            json.dumps(s.get("score_trace") or {}, sort_keys=True, ensure_ascii=True),
        )
        for s in scores
    ]
    conn.execute("BEGIN TRANSACTION")
    try:
        conn.execute(
            """
            CREATE TEMP TABLE _stg_scores (
                run_id VARCHAR, finding_id VARCHAR, asset_id VARCHAR,
                scoring_track VARCHAR, raw_risk_score DOUBLE, operational_score DOUBLE,
                risk_band VARCHAR, score_trace_json VARCHAR
            )
            """
        )
        with conn.appender("_stg_scores") as app:
            app.append_rows(rows)
        conn.execute(
            """
            INSERT INTO scores
            SELECT * FROM _stg_scores
            ON CONFLICT (run_id, finding_id) DO UPDATE SET
                asset_id = EXCLUDED.asset_id,
                scoring_track = EXCLUDED.scoring_track,
                raw_risk_score = EXCLUDED.raw_risk_score,
                operational_score = EXCLUDED.operational_score,
                risk_band = EXCLUDED.risk_band,
                score_trace_json = EXCLUDED.score_trace_json
            """
        )
        conn.execute("DROP TABLE _stg_scores")
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    return len(rows)


def upsert_triage_decisions(db: Any, run_id: str, decisions: Sequence[Dict[str, Any]]) -> int:
    """Bulk upsert triage decisions for a run."""
    if not decisions:
        return 0
    conn = _get_conn(db)
    rows = [
        (
            run_id,
            d["finding_id"],
            d["asset_id"],
            d.get("profile"),
            d.get("priority_tier"),
            d.get("oal_compat"),
            d.get("ssvc_action"),
            d.get("sla_bucket"),
            _safe_int(d.get("sla_days")),
            d.get("decision_status"),
            d.get("decision_id"),
            json.dumps(d.get("assumed_state") or {}, sort_keys=True, ensure_ascii=True),
            d.get("rationale_summary"),
        )
        for d in decisions
    ]
    conn.execute("BEGIN TRANSACTION")
    try:
        conn.execute(
            """
            CREATE TEMP TABLE _stg_td (
                run_id VARCHAR, finding_id VARCHAR, asset_id VARCHAR,
                profile VARCHAR, priority_tier VARCHAR, oal_compat VARCHAR,
                ssvc_action VARCHAR, sla_bucket VARCHAR, sla_days INTEGER,
                decision_status VARCHAR, decision_id VARCHAR, assumed_state_json VARCHAR,
                rationale_summary VARCHAR
            )
            """
        )
        with conn.appender("_stg_td") as app:
            app.append_rows(rows)
        conn.execute(
            """
            INSERT INTO triage_decisions
            SELECT * FROM _stg_td
            ON CONFLICT (run_id, finding_id) DO UPDATE SET
                asset_id = EXCLUDED.asset_id,
                profile = EXCLUDED.profile,
                priority_tier = EXCLUDED.priority_tier,
                oal_compat = EXCLUDED.oal_compat,
                ssvc_action = EXCLUDED.ssvc_action,
                sla_bucket = EXCLUDED.sla_bucket,
                sla_days = EXCLUDED.sla_days,
                decision_status = EXCLUDED.decision_status,
                decision_id = EXCLUDED.decision_id,
                assumed_state_json = EXCLUDED.assumed_state_json,
                rationale_summary = EXCLUDED.rationale_summary
            """
        )
        conn.execute("DROP TABLE _stg_td")
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    return len(rows)


def insert_ledger_events(db: Any, run_id: str, events: Sequence[Dict[str, Any]]) -> int:
    """Insert ledger events for a run."""
    if not events:
        return 0
    conn = _get_conn(db)
    rows = [
        (
            run_id,
            int(ev["seq"]),
            str(ev["ts"]),
            str(ev["component"]),
            str(ev["event_type"]),
            str(ev["subject_ref"]),
            ev.get("why") if isinstance(ev.get("why"), str) else json.dumps(ev.get("why") or {}, sort_keys=True, ensure_ascii=True),
            ev.get("evidence_digest"),
            ev.get("prev_hash"),
            ev.get("entry_hash"),
        )
        for ev in events
    ]
    conn.execute("BEGIN TRANSACTION")
    try:
        with conn.appender("ledger_events") as app:
            app.append_rows(rows)
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    return len(rows)


def insert_diff_events(
    db: Any,
    diff_id: str,
    base_run_id: str,
    target_run_id: str,
    events: Sequence[Dict[str, Any]],
) -> int:
    """Insert diff events comparing base_run_id and target_run_id."""
    if not events:
        return 0
    conn = _get_conn(db)
    rows = [
        (
            diff_id,
            base_run_id,
            target_run_id,
            str(ev["category"]),
            ev.get("finding_id"),
            ev.get("asset_id"),
            ev.get("cve_id"),
            json.dumps(ev.get("details") or {}, sort_keys=True, ensure_ascii=True),
        )
        for ev in events
    ]
    conn.execute("BEGIN TRANSACTION")
    try:
        with conn.appender("diff_events") as app:
            app.append_rows(rows)
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    return len(rows)


def query_findings_page(
    db: Any,
    run_id: str,
    priority_tier: Optional[str] = None,
    sla_bucket: Optional[str] = None,
    scoring_track: Optional[str] = None,
    in_kev: Optional[bool] = None,
    inventory_status: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Parameterized paged query over findings joined with asset, enrichment, score,
    triage_decision, and aci_signal views. Zero dynamic string interpolation of user inputs.
    """
    conn = _get_conn(db)
    bounded_limit = max(1, min(int(limit), 10_000))
    bounded_offset = max(0, int(offset))

    clauses = ["f.run_id = ?"]
    params: List[Any] = [str(run_id)]

    if priority_tier is not None:
        clauses.append("UPPER(COALESCE(td.priority_tier, '')) = UPPER(?)")
        params.append(str(priority_tier))
    if sla_bucket is not None:
        clauses.append("LOWER(COALESCE(td.sla_bucket, '')) = LOWER(?)")
        params.append(str(sla_bucket))
    if scoring_track is not None:
        clauses.append("f.scoring_track = ?")
        params.append(str(scoring_track))
    if in_kev is not None:
        clauses.append(
            "("
            "COALESCE(e.in_kev, FALSE) "
            "OR (fc_kev.finding_id IS NOT NULL) "
            f"OR ({_FAST_SCORE_TRACE_IN_KEV_SQL})"
            ") = ?"
        )
        params.append(bool(in_kev))
    if inventory_status is not None:
        clauses.append("a.inventory_status = ?")
        params.append(str(inventory_status))
    has_search = search is not None and bool(str(search).strip())
    if has_search:
        needle = str(search).strip().lower()
        clauses.append(
            "("
            "CONTAINS(LOWER(COALESCE(f.finding_id, '')), ?) OR "
            "CONTAINS(LOWER(COALESCE(NULLIF(json_extract_string(s.score_trace_json, '$.primary_cve'), ''), f.primary_cve, '')), ?) OR "
            "CONTAINS(LOWER(COALESCE(f.cves_json, '')), ?) OR "
            "CONTAINS(LOWER(COALESCE(f.title, '')), ?) OR "
            "CONTAINS(LOWER(COALESCE(f.package_purl, '')), ?) OR "
            "CONTAINS(LOWER(COALESCE(f.location_uri, '')), ?) OR "
            "CONTAINS(LOWER(COALESCE(a.hostname, '')), ?) OR "
            "CONTAINS(LOWER(COALESCE(a.ip_address, '')), ?) OR "
            "CONTAINS(LOWER(COALESCE(a.target_uri, '')), ?) OR "
            "CONTAINS(LOWER(COALESCE(a.image_or_repo, '')), ?)"
            ")"
        )
        params.extend([needle] * 10)

    where_sql = " AND ".join(clauses)
    need_a = (inventory_status is not None) or has_search
    need_s_count = (in_kev is not None) or has_search
    need_td_count = (priority_tier is not None) or (sla_bucket is not None)

    count_join_parts = ["FROM findings f"]
    count_prefix_params: List[Any] = []
    if need_a:
        count_join_parts.append("LEFT JOIN assets a ON a.run_id = f.run_id AND a.asset_id = f.asset_id")
    if need_s_count:
        count_join_parts.append("LEFT JOIN scores s ON s.run_id = f.run_id AND s.finding_id = f.finding_id")
    if in_kev is not None:
        count_join_parts.append(
            "LEFT JOIN enrichment_snapshots e ON e.run_id = f.run_id "
            f"AND UPPER(e.cve_id) = {_FAST_EFFECTIVE_PRIMARY_CVE_SQL}"
        )
        count_join_parts.append(
            "LEFT JOIN ("
            "SELECT DISTINCT fc.finding_id "
            "FROM finding_cves fc "
            "JOIN enrichment_snapshots es ON es.run_id = fc.run_id AND UPPER(es.cve_id) = UPPER(fc.cve_id) "
            "WHERE fc.run_id = ? AND COALESCE(es.in_kev, FALSE)"
            ") fc_kev ON fc_kev.finding_id = f.finding_id"
        )
        count_prefix_params.append(str(run_id))
    if need_td_count:
        count_join_parts.append("LEFT JOIN triage_decisions td ON td.run_id = f.run_id AND td.finding_id = f.finding_id")
    count_joins = " ".join(count_join_parts)

    total_count = int(
        conn.execute(f"SELECT COUNT(*) {count_joins} WHERE {where_sql}", [*count_prefix_params, *params]).fetchone()[0]
    )
    if total_count == 0:
        return [], 0

    paged_join_parts = [
        "FROM findings f",
        "LEFT JOIN scores s ON s.run_id = f.run_id AND s.finding_id = f.finding_id",
        "LEFT JOIN enrichment_snapshots e ON e.run_id = f.run_id "
        f"AND UPPER(e.cve_id) = {_FAST_EFFECTIVE_PRIMARY_CVE_SQL}",
        "LEFT JOIN triage_decisions td ON td.run_id = f.run_id AND td.finding_id = f.finding_id",
    ]
    paged_prefix_params: List[Any] = []
    if need_a:
        paged_join_parts.append("LEFT JOIN assets a ON a.run_id = f.run_id AND a.asset_id = f.asset_id")
    if in_kev is not None:
        paged_join_parts.append(
            "LEFT JOIN ("
            "SELECT DISTINCT fc.finding_id "
            "FROM finding_cves fc "
            "JOIN enrichment_snapshots es ON es.run_id = fc.run_id AND UPPER(es.cve_id) = UPPER(fc.cve_id) "
            "WHERE fc.run_id = ? AND COALESCE(es.in_kev, FALSE)"
            ") fc_kev ON fc_kev.finding_id = f.finding_id"
        )
        paged_prefix_params.append(str(run_id))
    paged_joins = " ".join(paged_join_parts)

    outer_joins = (
        "FROM paged p "
        "JOIN findings f ON f.run_id = p.run_id AND f.finding_id = p.finding_id "
        "LEFT JOIN assets a ON a.run_id = f.run_id AND a.asset_id = f.asset_id "
        "LEFT JOIN scores s ON s.run_id = f.run_id AND s.finding_id = f.finding_id "
        "LEFT JOIN enrichment_snapshots e ON e.run_id = f.run_id "
        "AND UPPER(e.cve_id) = COALESCE(UPPER(NULLIF(json_extract_string(s.score_trace_json, '$.primary_cve'), '')), UPPER(f.primary_cve)) "
        "LEFT JOIN ("
        "SELECT fc.finding_id, "
        "BOOL_OR(COALESCE(es.in_kev, FALSE)) AS fc_in_kev, "
        "BOOL_OR(COALESCE(es.verified_exploit, FALSE)) AS fc_verified_exploit, "
        "BOOL_OR(COALESCE(es.heuristic_exploit_mention, FALSE)) AS fc_heuristic_exploit, "
        "ARG_MIN(NULLIF(CAST(es.kev_date_added AS VARCHAR), ''), "
        "CASE WHEN COALESCE(es.in_kev, FALSE) AND NULLIF(CAST(es.kev_date_added AS VARCHAR), '') IS NOT NULL THEN UPPER(es.cve_id) END) AS fc_kev_date_added, "
        "ARG_MIN(NULLIF(CAST(es.kev_due_date AS VARCHAR), ''), "
        "CASE WHEN COALESCE(es.in_kev, FALSE) AND NULLIF(CAST(es.kev_due_date AS VARCHAR), '') IS NOT NULL THEN UPPER(es.cve_id) END) AS fc_kev_due_date, "
        "ARG_MIN(NULLIF(CAST(es.kev_ransomware AS VARCHAR), ''), "
        "CASE WHEN COALESCE(es.in_kev, FALSE) AND NULLIF(CAST(es.kev_ransomware AS VARCHAR), '') IS NOT NULL THEN UPPER(es.cve_id) END) AS fc_kev_ransomware "
        "FROM finding_cves fc "
        "JOIN enrichment_snapshots es ON es.run_id = fc.run_id AND UPPER(es.cve_id) = UPPER(fc.cve_id) "
        "WHERE fc.run_id = ? AND fc.finding_id IN (SELECT finding_id FROM paged) "
        "GROUP BY fc.finding_id"
        ") fc_agg ON fc_agg.finding_id = f.finding_id "
        "LEFT JOIN triage_decisions td ON td.run_id = f.run_id AND td.finding_id = f.finding_id "
        "LEFT JOIN aci_signals aci ON aci.run_id = f.run_id AND aci.finding_id = f.finding_id"
    )

    select_sql = (
        "WITH paged AS ("
        f"SELECT f.run_id, f.finding_id {paged_joins} "
        f"WHERE {where_sql} "
        f"ORDER BY {_PRIORITY_ORDER_SQL} "
        "LIMIT ? OFFSET ?"
        ") "
        "SELECT "
        "f.run_id, f.finding_id, f.asset_id, f.scoring_track, "
        "COALESCE(UPPER(NULLIF(json_extract_string(s.score_trace_json, '$.primary_cve'), '')), f.primary_cve) AS primary_cve, "
        "f.cves_json, f.cwes_json, f.ghsa_ids_json, f.title, f.description, f.solution, "
        "f.plugin_output, f.affected_port, f.protocol, f.service_name, f.location_uri, "
        "f.line_number, f.package_purl, f.scanner_severity, f.scanner_cvss_score, "
        "f.scanner_cvss_vector, f.detection_mode, f.signal_reliability, "
        "f.ingestion_confidence, f.fidelity_tier, f.source_format, f.references_json, "
        "f.tags_json, f.exploit_evidence, f.is_deduplicated, f.source_count, "
        "a.canonical_key, a.hostname, a.ip_address, a.target_uri, a.image_or_repo, "
        "a.os, a.declared_criticality, a.derived_criticality, a.internet_facing, "
        "a.owner, a.env_tags_json, a.inventory_status, a.matched_rule_id, "
        "e.cvss_score, e.cvss_vector, e.cvss_version, e.cvss_provenance, "
        "e.epss_score, e.epss_percentile, "
        "(COALESCE(e.in_kev, FALSE) OR COALESCE(fc_agg.fc_in_kev, FALSE) OR COALESCE(TRY_CAST(json_extract(s.score_trace_json, '$.in_kev') AS BOOLEAN), FALSE)) AS in_kev, "
        "CASE WHEN (COALESCE(e.in_kev, FALSE) OR COALESCE(fc_agg.fc_in_kev, FALSE) OR COALESCE(TRY_CAST(json_extract(s.score_trace_json, '$.in_kev') AS BOOLEAN), FALSE)) "
        "THEN COALESCE(CASE WHEN COALESCE(e.in_kev, FALSE) THEN NULLIF(CAST(e.kev_date_added AS VARCHAR), '') END, NULLIF(json_extract_string(s.score_trace_json, '$.kev_date_added'), ''), fc_agg.fc_kev_date_added) "
        "ELSE e.kev_date_added END AS kev_date_added, "
        "CASE WHEN (COALESCE(e.in_kev, FALSE) OR COALESCE(fc_agg.fc_in_kev, FALSE) OR COALESCE(TRY_CAST(json_extract(s.score_trace_json, '$.in_kev') AS BOOLEAN), FALSE)) "
        "THEN COALESCE(CASE WHEN COALESCE(e.in_kev, FALSE) THEN NULLIF(CAST(e.kev_due_date AS VARCHAR), '') END, NULLIF(json_extract_string(s.score_trace_json, '$.kev_due_date'), ''), fc_agg.fc_kev_due_date) "
        "ELSE e.kev_due_date END AS kev_due_date, "
        "CASE WHEN (COALESCE(e.in_kev, FALSE) OR COALESCE(fc_agg.fc_in_kev, FALSE) OR COALESCE(TRY_CAST(json_extract(s.score_trace_json, '$.in_kev') AS BOOLEAN), FALSE)) "
        "THEN COALESCE(CASE WHEN COALESCE(e.in_kev, FALSE) THEN NULLIF(CAST(e.kev_ransomware AS VARCHAR), '') END, NULLIF(json_extract_string(s.score_trace_json, '$.kev_ransomware'), ''), fc_agg.fc_kev_ransomware) "
        "ELSE e.kev_ransomware END AS kev_ransomware, "
        "(COALESCE(e.verified_exploit, FALSE) OR COALESCE(fc_agg.fc_verified_exploit, FALSE) OR COALESCE(TRY_CAST(json_extract(s.score_trace_json, '$.verified_exploit') AS BOOLEAN), FALSE)) AS verified_exploit, "
        "(COALESCE(e.heuristic_exploit_mention, FALSE) OR COALESCE(fc_agg.fc_heuristic_exploit, FALSE) OR COALESCE(TRY_CAST(json_extract(s.score_trace_json, '$.heuristic_exploit_mention') AS BOOLEAN), FALSE)) AS heuristic_exploit_mention, "
        "e.enrichment_confidence, "
        "s.raw_risk_score, s.operational_score, s.risk_band, s.score_trace_json, "
        "td.profile, td.priority_tier, td.oal_compat, td.ssvc_action, td.sla_bucket, "
        "td.sla_days, td.decision_status, td.decision_id, td.rationale_summary, "
        "aci.confidence AS aci_confidence, aci.uplift_score AS aci_uplift_score, "
        "aci.capabilities_json, aci.chains_json "
        f"{outer_joins} "
        f"ORDER BY {_PRIORITY_ORDER_SQL}"
    )
    cursor = conn.execute(select_sql, [*paged_prefix_params, *params, bounded_limit, bounded_offset, str(run_id)])
    cols = [d[0] for d in cursor.description]
    raw_rows = cursor.fetchall()

    results: List[Dict[str, Any]] = []
    for raw in raw_rows:
        item = dict(zip(cols, raw))
        item["cves"] = _json_loads_safe(item.pop("cves_json", None), [])
        item["cwes"] = _json_loads_safe(item.pop("cwes_json", None), [])
        item["ghsa_ids"] = _json_loads_safe(item.pop("ghsa_ids_json", None), [])
        item["references"] = _json_loads_safe(item.pop("references_json", None), [])
        item["tags"] = _json_loads_safe(item.pop("tags_json", None), [])
        item["env_tags"] = _json_loads_safe(item.pop("env_tags_json", None), {})
        item["capabilities"] = _json_loads_safe(item.pop("capabilities_json", None), [])
        item["chains"] = _json_loads_safe(item.pop("chains_json", None), [])
        score_trace = _json_loads_safe(item.pop("score_trace_json", None), {})
        if not isinstance(score_trace, dict):
            score_trace = {}
        eff_cvss, eff_prov, eff_ver, eff_vec = resolve_effective_cvss_fields(
            snap_cvss=item.get("cvss_score"),
            snap_prov=item.get("cvss_provenance"),
            snap_ver=item.get("cvss_version"),
            snap_vec=item.get("cvss_vector"),
            scanner_cvss=item.get("scanner_cvss_score"),
            scanner_vec=item.get("scanner_cvss_vector"),
            score_trace=score_trace,
        )
        item["cvss_score"] = eff_cvss
        item["cvss_provenance"] = eff_prov
        item["cvss_version"] = eff_ver
        item["cvss_vector"] = eff_vec
        if item.get("in_kev"):
            item["kev_date_added"] = item.get("kev_date_added") or score_trace.get("kev_date_added")
            item["kev_due_date"] = item.get("kev_due_date") or score_trace.get("kev_due_date")
            if item.get("kev_ransomware") is None or item.get("kev_ransomware") == "":
                item["kev_ransomware"] = score_trace.get("kev_ransomware")
        results.append(item)

    return results, total_count


def get_finding_detail(db: Any, run_id: str, finding_id: str) -> Optional[Dict[str, Any]]:
    """Fetch complete detail for a single finding, including all raw evidence and CVEs."""
    conn = _get_conn(db)
    cursor = conn.execute(
        """
        SELECT
            f.run_id, f.finding_id, f.asset_id, f.scoring_track,
            COALESCE(UPPER(NULLIF(json_extract_string(s.score_trace_json, '$.primary_cve'), '')), f.primary_cve) AS primary_cve,
            f.cves_json, f.cwes_json, f.ghsa_ids_json, f.title, f.description, f.solution,
            f.plugin_output, f.affected_port, f.protocol, f.service_name, f.location_uri,
            f.line_number, f.package_purl, f.scanner_severity, f.scanner_cvss_score,
            f.scanner_cvss_vector, f.detection_mode, f.signal_reliability,
            f.ingestion_confidence, f.fidelity_tier, f.source_format, f.references_json,
            f.tags_json, f.exploit_evidence, f.is_deduplicated, f.source_count,
            a.canonical_key, a.hostname, a.ip_address, a.target_uri, a.image_or_repo,
            a.os, a.declared_criticality, a.derived_criticality, a.internet_facing,
            a.owner, a.env_tags_json, a.inventory_status, a.matched_rule_id, a.open_ports_json,
            e.cvss_score, e.cvss_vector, e.cvss_version, e.cvss_provenance,
            e.epss_score, e.epss_percentile, e.epss_model_version, e.epss_date,
            (
                COALESCE(e.in_kev, FALSE)
                OR COALESCE(fc_agg.fc_in_kev, FALSE)
                OR COALESCE(TRY_CAST(json_extract(s.score_trace_json, '$.in_kev') AS BOOLEAN), FALSE)
            ) AS in_kev,
            CASE
                WHEN (
                    COALESCE(e.in_kev, FALSE)
                    OR COALESCE(fc_agg.fc_in_kev, FALSE)
                    OR COALESCE(TRY_CAST(json_extract(s.score_trace_json, '$.in_kev') AS BOOLEAN), FALSE)
                )
                THEN COALESCE(
                    CASE WHEN COALESCE(e.in_kev, FALSE) THEN NULLIF(CAST(e.kev_date_added AS VARCHAR), '') END,
                    NULLIF(json_extract_string(s.score_trace_json, '$.kev_date_added'), ''),
                    fc_agg.fc_kev_date_added
                )
                ELSE e.kev_date_added
            END AS kev_date_added,
            CASE
                WHEN (
                    COALESCE(e.in_kev, FALSE)
                    OR COALESCE(fc_agg.fc_in_kev, FALSE)
                    OR COALESCE(TRY_CAST(json_extract(s.score_trace_json, '$.in_kev') AS BOOLEAN), FALSE)
                )
                THEN COALESCE(
                    CASE WHEN COALESCE(e.in_kev, FALSE) THEN NULLIF(CAST(e.kev_due_date AS VARCHAR), '') END,
                    NULLIF(json_extract_string(s.score_trace_json, '$.kev_due_date'), ''),
                    fc_agg.fc_kev_due_date
                )
                ELSE e.kev_due_date
            END AS kev_due_date,
            CASE
                WHEN (
                    COALESCE(e.in_kev, FALSE)
                    OR COALESCE(fc_agg.fc_in_kev, FALSE)
                    OR COALESCE(TRY_CAST(json_extract(s.score_trace_json, '$.in_kev') AS BOOLEAN), FALSE)
                )
                THEN COALESCE(
                    CASE WHEN COALESCE(e.in_kev, FALSE) THEN NULLIF(CAST(e.kev_ransomware AS VARCHAR), '') END,
                    NULLIF(json_extract_string(s.score_trace_json, '$.kev_ransomware'), ''),
                    fc_agg.fc_kev_ransomware
                )
                ELSE e.kev_ransomware
            END AS kev_ransomware,
            e.kev_required_action,
            (
                COALESCE(e.verified_exploit, FALSE)
                OR COALESCE(fc_agg.fc_verified_exploit, FALSE)
                OR COALESCE(TRY_CAST(json_extract(s.score_trace_json, '$.verified_exploit') AS BOOLEAN), FALSE)
            ) AS verified_exploit,
            (
                COALESCE(e.heuristic_exploit_mention, FALSE)
                OR COALESCE(fc_agg.fc_heuristic_exploit, FALSE)
                OR COALESCE(TRY_CAST(json_extract(s.score_trace_json, '$.heuristic_exploit_mention') AS BOOLEAN), FALSE)
            ) AS heuristic_exploit_mention,
            e.exploit_refs_json, e.ghsa_ids_json AS enriched_ghsa_ids_json,
            e.osv_ids_json, e.enrichment_confidence, e.sources_json,
            s.raw_risk_score, s.operational_score, s.risk_band, s.score_trace_json,
            td.profile, td.priority_tier, td.oal_compat, td.ssvc_action, td.sla_bucket,
            td.sla_days, td.decision_status, td.decision_id, td.assumed_state_json,
            td.rationale_summary,
            aci.capabilities_json, aci.chains_json, aci.matched_tokens_json,
            aci.confidence AS aci_confidence, aci.uplift_score AS aci_uplift_score
        FROM findings f
        LEFT JOIN assets a ON a.run_id = f.run_id AND a.asset_id = f.asset_id
        LEFT JOIN scores s ON s.run_id = f.run_id AND s.finding_id = f.finding_id
        LEFT JOIN enrichment_snapshots e ON e.run_id = f.run_id
            AND UPPER(e.cve_id) = COALESCE(UPPER(NULLIF(json_extract_string(s.score_trace_json, '$.primary_cve'), '')), UPPER(f.primary_cve))
        LEFT JOIN (
            SELECT
                fc.finding_id,
                BOOL_OR(COALESCE(es.in_kev, FALSE)) AS fc_in_kev,
                BOOL_OR(COALESCE(es.verified_exploit, FALSE)) AS fc_verified_exploit,
                BOOL_OR(COALESCE(es.heuristic_exploit_mention, FALSE)) AS fc_heuristic_exploit,
                ARG_MIN(
                    NULLIF(CAST(es.kev_date_added AS VARCHAR), ''),
                    CASE
                        WHEN COALESCE(es.in_kev, FALSE) AND NULLIF(CAST(es.kev_date_added AS VARCHAR), '') IS NOT NULL
                        THEN UPPER(es.cve_id)
                    END
                ) AS fc_kev_date_added,
                ARG_MIN(
                    NULLIF(CAST(es.kev_due_date AS VARCHAR), ''),
                    CASE
                        WHEN COALESCE(es.in_kev, FALSE) AND NULLIF(CAST(es.kev_due_date AS VARCHAR), '') IS NOT NULL
                        THEN UPPER(es.cve_id)
                    END
                ) AS fc_kev_due_date,
                ARG_MIN(
                    NULLIF(CAST(es.kev_ransomware AS VARCHAR), ''),
                    CASE
                        WHEN COALESCE(es.in_kev, FALSE) AND NULLIF(CAST(es.kev_ransomware AS VARCHAR), '') IS NOT NULL
                        THEN UPPER(es.cve_id)
                    END
                ) AS fc_kev_ransomware
            FROM finding_cves fc
            JOIN enrichment_snapshots es ON es.run_id = fc.run_id AND UPPER(es.cve_id) = UPPER(fc.cve_id)
            WHERE fc.run_id = ? AND fc.finding_id = ?
            GROUP BY fc.finding_id
        ) fc_agg ON fc_agg.finding_id = f.finding_id
        LEFT JOIN triage_decisions td ON td.run_id = f.run_id AND td.finding_id = f.finding_id
        LEFT JOIN aci_signals aci ON aci.run_id = f.run_id AND aci.finding_id = f.finding_id
        WHERE f.run_id = ? AND f.finding_id = ?
        """,
        [str(run_id), str(finding_id), str(run_id), str(finding_id)],
    )
    row = cursor.fetchone()
    if row is None:
        return None

    cols = [d[0] for d in cursor.description]
    detail = dict(zip(cols, row))

    detail["cves"] = _json_loads_safe(detail.pop("cves_json", None), [])
    detail["cwes"] = _json_loads_safe(detail.pop("cwes_json", None), [])
    detail["ghsa_ids"] = _json_loads_safe(detail.pop("ghsa_ids_json", None), [])
    detail["references"] = _json_loads_safe(detail.pop("references_json", None), [])
    detail["tags"] = _json_loads_safe(detail.pop("tags_json", None), [])
    detail["env_tags"] = _json_loads_safe(detail.pop("env_tags_json", None), [])
    detail["open_ports"] = _json_loads_safe(detail.pop("open_ports_json", None), [])
    detail["exploit_refs"] = _json_loads_safe(detail.pop("exploit_refs_json", None), [])
    detail["enriched_ghsa_ids"] = _json_loads_safe(detail.pop("enriched_ghsa_ids_json", None), [])
    detail["osv_ids"] = _json_loads_safe(detail.pop("osv_ids_json", None), [])
    detail["enrichment_sources"] = _json_loads_safe(detail.pop("sources_json", None), [])
    detail["score_trace"] = _json_loads_safe(detail.pop("score_trace_json", None), {})
    score_trace_dict = detail["score_trace"] if isinstance(detail["score_trace"], dict) else {}
    eff_cvss, eff_prov, eff_ver, eff_vec = resolve_effective_cvss_fields(
        snap_cvss=detail.get("cvss_score"),
        snap_prov=detail.get("cvss_provenance"),
        snap_ver=detail.get("cvss_version"),
        snap_vec=detail.get("cvss_vector"),
        scanner_cvss=detail.get("scanner_cvss_score"),
        scanner_vec=detail.get("scanner_cvss_vector"),
        score_trace=score_trace_dict,
    )
    detail["cvss_score"] = eff_cvss
    detail["cvss_provenance"] = eff_prov
    detail["cvss_version"] = eff_ver
    detail["cvss_vector"] = eff_vec
    if detail.get("in_kev"):
        detail["kev_date_added"] = detail.get("kev_date_added") or score_trace_dict.get("kev_date_added")
        detail["kev_due_date"] = detail.get("kev_due_date") or score_trace_dict.get("kev_due_date")
        if detail.get("kev_ransomware") is None or detail.get("kev_ransomware") == "":
            detail["kev_ransomware"] = score_trace_dict.get("kev_ransomware")
    detail["assumed_state"] = _json_loads_safe(detail.pop("assumed_state_json", None), {})
    detail["capabilities"] = _json_loads_safe(detail.pop("capabilities_json", None), [])
    detail["chains"] = _json_loads_safe(detail.pop("chains_json", None), [])
    detail["matched_tokens"] = _json_loads_safe(detail.pop("matched_tokens_json", None), [])

    ev_cursor = conn.execute(
        """
        SELECT evidence_idx, source_format, scanner_sig, raw_severity, raw_cvss, raw_location, evidence_excerpt
        FROM finding_evidence
        WHERE run_id = ? AND finding_id = ?
        ORDER BY evidence_idx ASC
        """,
        [str(run_id), str(finding_id)],
    )
    ev_cols = [d[0] for d in ev_cursor.description]
    detail["evidence"] = [dict(zip(ev_cols, r)) for r in ev_cursor.fetchall()]

    detail["finding_cves"] = [
        r[0]
        for r in conn.execute(
            "SELECT DISTINCT cve_id FROM finding_cves WHERE run_id = ? AND finding_id = ? ORDER BY cve_id ASC",
            [str(run_id), str(finding_id)],
        ).fetchall()
    ]

    if detail.get("asset_id"):
        al_cursor = conn.execute(
            "SELECT alias_type, alias_value FROM asset_aliases WHERE run_id = ? AND asset_id = ? ORDER BY alias_type ASC, alias_value ASC",
            [str(run_id), str(detail["asset_id"])],
        )
        detail["asset_aliases"] = [{"alias_type": r[0], "alias_value": r[1]} for r in al_cursor.fetchall()]
    else:
        detail["asset_aliases"] = []

    return detail


def get_run_summary_counts(db: Any, run_id: str) -> Dict[str, Any]:
    """Return aggregate counts and breakdown buckets for a run."""
    conn = _get_conn(db)
    rid = str(run_id)

    asset_row = conn.execute(
        """
        SELECT
            COUNT(*) AS total_assets,
            SUM(CASE WHEN inventory_status = 'matched' THEN 1 ELSE 0 END) AS matched_assets,
            SUM(CASE WHEN inventory_status = 'unmatched_shadow' THEN 1 ELSE 0 END) AS shadow_assets
        FROM assets WHERE run_id = ?
        """,
        [rid],
    ).fetchone()

    finding_row = conn.execute(
        _KEV_CTES_SQL
        + """
        SELECT
            COUNT(*) AS total_findings,
            SUM(CASE WHEN f.scoring_track = 'cve_threat' THEN 1 ELSE 0 END) AS cve_findings,
            SUM(CASE WHEN f.scoring_track = 'exposure_weakness' THEN 1 ELSE 0 END) AS exposure_findings,
            SUM(CASE WHEN f.is_deduplicated THEN 1 ELSE 0 END) AS deduplicated_findings,
            SUM(
                CASE
                    WHEN (
                        (e_kev.cve_u IS NOT NULL)
                        OR (fc_kev.finding_id IS NOT NULL)
                        OR (s_kev.finding_id IS NOT NULL)
                    ) THEN 1
                    ELSE 0
                END
            ) AS kev_findings
        FROM findings f
        LEFT JOIN e_kev ON e_kev.cve_u = UPPER(f.primary_cve)
        LEFT JOIN fc_kev ON fc_kev.finding_id = f.finding_id
        LEFT JOIN s_kev ON s_kev.finding_id = f.finding_id
        WHERE f.run_id = ?
        """,
        [rid, rid, rid, rid],
    ).fetchone()

    by_priority_tier: Dict[str, int] = {}
    by_sla_bucket: Dict[str, int] = {}
    by_decision_status: Dict[str, int] = {}
    for g_tier, g_sla, g_stat, p_tier, sla_b, d_stat, cnt in conn.execute(
        """
        SELECT
            GROUPING(priority_tier),
            GROUPING(sla_bucket),
            GROUPING(decision_status),
            priority_tier,
            sla_bucket,
            decision_status,
            COUNT(*)
        FROM triage_decisions
        WHERE run_id = ?
        GROUP BY GROUPING SETS ((priority_tier), (sla_bucket), (decision_status))
        """,
        [rid],
    ).fetchall():
        c = int(cnt)
        if g_tier == 0 and p_tier is not None:
            by_priority_tier[str(p_tier)] = c
        elif g_sla == 0 and sla_b is not None:
            by_sla_bucket[str(sla_b)] = c
        elif g_stat == 0 and d_stat is not None:
            by_decision_status[str(d_stat)] = c

    by_risk_band: Dict[str, int] = {}
    for k, cnt in conn.execute(
        "SELECT risk_band, COUNT(*) FROM scores WHERE run_id = ? GROUP BY risk_band",
        [rid],
    ).fetchall():
        if k is not None:
            by_risk_band[str(k)] = int(cnt)

    by_severity: Dict[str, int] = {}
    by_scoring_track: Dict[str, int] = {}
    for g_sev, g_trk, sev, trk, cnt in conn.execute(
        """
        SELECT
            GROUPING(scanner_severity),
            GROUPING(scoring_track),
            scanner_severity,
            scoring_track,
            COUNT(*)
        FROM findings
        WHERE run_id = ?
        GROUP BY GROUPING SETS ((scanner_severity), (scoring_track))
        """,
        [rid],
    ).fetchall():
        c = int(cnt)
        if g_sev == 0 and sev is not None:
            by_severity[str(sev)] = c
        elif g_trk == 0 and trk is not None:
            by_scoring_track[str(trk)] = c

    return {
        "run_id": rid,
        "total_assets": int(asset_row[0] or 0),
        "matched_assets": int(asset_row[1] or 0),
        "shadow_assets": int(asset_row[2] or 0),
        "total_findings": int(finding_row[0] or 0),
        "cve_findings": int(finding_row[1] or 0),
        "exposure_findings": int(finding_row[2] or 0),
        "deduplicated_findings": int(finding_row[3] or 0),
        "kev_findings": int(finding_row[4] or 0),
        "by_priority_tier": by_priority_tier,
        "by_sla_bucket": by_sla_bucket,
        "by_decision_status": by_decision_status,
        "by_risk_band": by_risk_band,
        "by_severity": by_severity,
        "by_scoring_track": by_scoring_track,
    }


def get_shadow_assets(db: Any, run_id: str) -> List[Dict[str, Any]]:
    """Return all unmatched shadow assets for a run with finding counts and max operational score."""
    conn = _get_conn(db)
    rid = str(run_id)
    cursor = conn.execute(
        _KEV_CTES_SQL
        + """
        SELECT
            a.run_id, a.asset_id, a.canonical_key, a.hostname, a.ip_address,
            a.target_uri, a.image_or_repo, a.os, a.declared_criticality,
            a.derived_criticality, a.internet_facing, a.owner, a.env_tags_json,
            a.inventory_status, a.open_ports_json,
            COUNT(f.finding_id) AS finding_count,
            MAX(s.operational_score) AS max_operational_score,
            SUM(
                CASE
                    WHEN (
                        (e_kev.cve_u IS NOT NULL)
                        OR (fc_kev.finding_id IS NOT NULL)
                        OR (s_kev.finding_id IS NOT NULL)
                    ) THEN 1
                    ELSE 0
                END
            ) AS kev_count
        FROM assets a
        LEFT JOIN findings f ON f.run_id = a.run_id AND f.asset_id = a.asset_id
        LEFT JOIN scores s ON s.run_id = f.run_id AND s.finding_id = f.finding_id
        LEFT JOIN e_kev ON e_kev.cve_u = UPPER(f.primary_cve)
        LEFT JOIN fc_kev ON fc_kev.finding_id = f.finding_id
        LEFT JOIN s_kev ON s_kev.finding_id = f.finding_id
        WHERE a.run_id = ? AND a.inventory_status = 'unmatched_shadow'
        GROUP BY
            a.run_id, a.asset_id, a.canonical_key, a.hostname, a.ip_address,
            a.target_uri, a.image_or_repo, a.os, a.declared_criticality,
            a.derived_criticality, a.internet_facing, a.owner, a.env_tags_json,
            a.inventory_status, a.open_ports_json
        ORDER BY max_operational_score DESC NULLS LAST, finding_count DESC, a.asset_id ASC
        """,
        [rid, rid, rid, rid],
    )
    cols = [d[0] for d in cursor.description]
    out: List[Dict[str, Any]] = []
    for raw in cursor.fetchall():
        item = dict(zip(cols, raw))
        item["env_tags"] = _json_loads_safe(item.pop("env_tags_json", None), {})
        item["open_ports"] = _json_loads_safe(item.pop("open_ports_json", None), [])
        item["finding_count"] = int(item.get("finding_count") or 0)
        item["kev_count"] = int(item.get("kev_count") or 0)
        out.append(item)
    return out


def list_runs(db: Any) -> List[Dict[str, Any]]:
    """List recorded runs ordered newest-first with asset and finding counts."""
    conn = _get_conn(db)
    cursor = conn.execute(
        """
        SELECT
            r.run_id, r.created_at_utc, r.vpp_version, r.profile,
            r.config_sha256, r.assets_sha256, r.decisions_sha256,
            r.intel_metadata_json, r.manifest_digest, r.input_files_json,
            r.baseline_run_id,
            COALESCE(ac.cnt, 0) AS asset_count,
            COALESCE(fc.cnt, 0) AS finding_count
        FROM runs r
        LEFT JOIN (SELECT run_id, COUNT(*) AS cnt FROM assets GROUP BY run_id) ac ON ac.run_id = r.run_id
        LEFT JOIN (SELECT run_id, COUNT(*) AS cnt FROM findings GROUP BY run_id) fc ON fc.run_id = r.run_id
        ORDER BY r.created_at_utc DESC, r.run_id ASC
        """
    )
    cols = [d[0] for d in cursor.description]
    out: List[Dict[str, Any]] = []
    for raw in cursor.fetchall():
        item = dict(zip(cols, raw))
        item["intel_metadata"] = _json_loads_safe(item.pop("intel_metadata_json", None), {})
        item["input_files"] = _json_loads_safe(item.pop("input_files_json", None), [])
        item["asset_count"] = int(item.get("asset_count") or 0)
        item["finding_count"] = int(item.get("finding_count") or 0)
        out.append(item)
    return out
