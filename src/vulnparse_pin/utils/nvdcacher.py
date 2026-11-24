# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations
import contextlib
import gzip
import json
from datetime import datetime, timezone, timedelta
import math
import re
import io
import threading
import concurrent.futures, os
import sqlite3
import hashlib
import hmac
import stat
from typing import Any, Dict, List, TYPE_CHECKING, Optional, Set, Tuple
from vulnparse_pin.utils.cvss_utils import compute_cvss_base_score, detect_cvss_exact_version

try:
    import ijson
except ImportError as exc:
    ijson = None
    print(f"ijson dependency is missing; for runtime optimization, install ijson 'pip install ijson': {exc}")

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext

_YEAR_KEY_RE = re.compile(r"^nvd\.year\.(\d{4})$")
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_SQLITE_CHUNK_SIZE = 900
_NVD_CVSS_TIERS: Tuple[Tuple[str, str], ...] = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)
_NVD_RECORD_MIGRATIONS: Tuple[Tuple[str, str], ...] = (
    ("cvss_version", "TEXT"),
    ("cvss_provenance", "TEXT"),
    ("source_identifier", "TEXT"),
)

class NVDFeedCache:
    '''
    Feed-based NVD Cache.
    - Pulls feed list + TTL policy from config.yaml
    - Uses FeedCacheManager for caching/integrity/refresh/offline
    - Parses cached raw .json.gz feeds into in-memory lookup for O(1) enrichment
    '''

    def __init__(self, ctx: "RunContext") -> None:
        self.ctx = ctx
        self.lookup: Dict[str, Dict[str, Any]] = {}
        self.target_cves: Optional[Set[str]] = None  # CVEs to index (if filtering)
        # lock to protect lookup when parsing in parallel
        self._lock = threading.Lock()
        self._sqlite_enabled = False
        self._sqlite_path: Optional[str] = None
        self._sqlite_sig_path: Optional[str] = None
        self._init_sqlite_index()

    def _sqlite_secret(self) -> Optional[bytes]:
        """Optional secret for HMAC signing (recommended in production)."""
        raw = os.getenv("VP_SQLITE_HMAC_KEY")
        if not raw:
            return None
        return raw.encode("utf-8")

    def _sqlite_security_policy(self) -> Dict[str, Any]:
        services = getattr(self.ctx, "services", None)
        cfg = getattr(services, "global_config", None)
        if not isinstance(cfg, dict):
            cfg = getattr(self.ctx, "config", {}) or {}
        nvd = _cfg_get(cfg, ["feed_cache", "feeds", "nvd"], {}) or {}
        return {
            "enforce_permissions": _cfg_bool(cfg, ["feed_cache", "feeds", "nvd", "sqlite_enforce_permissions"], True),
            "max_age_hours": _cfg_int(cfg, ["feed_cache", "feeds", "nvd", "sqlite_max_age_hours"], 24 * 14),
            "max_rows": _cfg_int(cfg, ["feed_cache", "feeds", "nvd", "sqlite_max_rows"], 500000),
            "file_mode": str(nvd.get("sqlite_file_mode", "0o600")),
        }

    def _sqlite_harden_permissions(self) -> None:
        if not self._sqlite_path:
            return
        pol = self._sqlite_security_policy()
        if not pol["enforce_permissions"]:
            return

        sqlite_path = self._sqlite_path

        if os.name == "nt":
            self.ctx.pfh.ensure_readable_file(sqlite_path, label="NVD SQLite Index")
            if not os.access(sqlite_path, os.W_OK):
                raise PermissionError("NVD SQLite index is not writable on Windows.")
            return

        # Best-effort mode enforcement; Windows ACLs are handled by OS policy.
        try:
            mode_value = int(pol["file_mode"], 8)
            os.chmod(sqlite_path, mode_value)
        except (OSError, ValueError):
            pass

        try:
            self.ctx.pfh.ensure_readable_file(sqlite_path, label="NVD SQLite Index")
            st = os.stat(sqlite_path)
            if bool(st.st_mode & stat.S_IWOTH):
                raise PermissionError("NVD SQLite index is world-writable; refusing to continue.")
        except OSError as exc:
            raise PermissionError(f"NVD SQLite permission check failed: {exc}") from exc

    def _sqlite_prune(self) -> None:
        if not self._sqlite_enabled or not self._sqlite_path:
            return
        pol = self._sqlite_security_policy()
        max_age_hours = max(int(pol["max_age_hours"]), 0)
        max_rows = max(int(pol["max_rows"]), 0)

        try:
            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    if max_age_hours > 0:
                        cutoff = (datetime.now(timezone.utc) - timedelta(hours=max_age_hours)).isoformat().replace("+00:00", "Z")
                        conn.execute(
                            "DELETE FROM nvd_records WHERE updated_at < ?",
                            (cutoff,),
                        )

                    if max_rows > 0:
                        row_count = conn.execute("SELECT COUNT(*) FROM nvd_records").fetchone()[0]
                        if row_count > max_rows:
                            trim = row_count - max_rows
                            conn.execute(
                                """
                                DELETE FROM nvd_records
                                WHERE cve_id IN (
                                    SELECT cve_id FROM nvd_records
                                    ORDER BY COALESCE(updated_at, '') ASC
                                    LIMIT ?
                                )
                                """,
                                (trim,),
                            )
        except (OSError, sqlite3.DatabaseError, ValueError, TypeError) as exc:
            self.ctx.logger.warning(
                "NVD SQLite prune failed; continuing without prune: %s",
                exc,
                extra={"vp_label": "NVD Optimization"},
            )

    def _sqlite_compute_digest(self) -> Optional[str]:
        if not self._sqlite_path:
            return None
        digest = hashlib.sha256()
        with self.ctx.pfh.open_for_read(self._sqlite_path, mode="rb", label="NVD SQLite Index", log=False) as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _sqlite_write_signature(self) -> None:
        if not self._sqlite_enabled or not self._sqlite_path or not self._sqlite_sig_path:
            return

        digest = self._sqlite_compute_digest()
        if not digest:
            return

        sig_mode = "sha256"
        sig_value = digest
        secret = self._sqlite_secret()
        if secret is not None:
            sig_mode = "hmac-sha256"
            sig_value = hmac.new(secret, digest.encode("utf-8"), hashlib.sha256).hexdigest()

        payload = {
            "mode": sig_mode,
            "signature": sig_value,
            "digest": digest,
            "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "schema": 1,
        }

        sig_path = self.ctx.pfh.ensure_writable_file(
            self._sqlite_sig_path,
            label="NVD SQLite Signature",
            create_parents=True,
            overwrite=True,
        )
        with self.ctx.pfh.open_for_write(sig_path, mode="w", encoding="utf-8", label="NVD SQLite Signature") as f:
            json.dump(payload, f, indent=2)
        if os.name != "nt":
            try:
                os.chmod(sig_path, 0o600)
            except OSError:
                pass

    def _sqlite_verify_signature(self) -> bool:
        """Verify index signature integrity; returns False when missing, downgraded, or tampered."""
        if not self._sqlite_enabled or not self._sqlite_path:
            return False

        if not self._sqlite_sig_path or not os.path.exists(self._sqlite_sig_path):
            return False

        try:
            if os.name != "nt":
                st = os.stat(self._sqlite_sig_path)
                if bool(st.st_mode & stat.S_IWOTH):
                    return False
            with self.ctx.pfh.open_for_read(self._sqlite_sig_path, mode="r", encoding="utf-8", label="NVD SQLite Signature", log=False) as f:
                payload = json.load(f)
            if not isinstance(payload, dict):
                return False

            mode = str(payload.get("mode", "")).strip()
            expected_sig = str(payload.get("signature", ""))
            expected_digest = str(payload.get("digest", ""))
            current_digest = self._sqlite_compute_digest()
            if not current_digest:
                return False

            if not hmac.compare_digest(expected_digest, current_digest):
                return False

            secret = self._sqlite_secret()
            if secret is not None and mode != "hmac-sha256":
                return False

            if mode == "hmac-sha256":
                if secret is None:
                    return False
                current_sig = hmac.new(secret, current_digest.encode("utf-8"), hashlib.sha256).hexdigest()
            elif mode == "sha256":
                current_sig = current_digest
            else:
                return False

            return hmac.compare_digest(expected_sig, current_sig)
        except (OSError, ValueError, TypeError, json.JSONDecodeError, PermissionError):
            return False

    @staticmethod
    def _ensure_nvd_schema(conn: sqlite3.Connection) -> bool:
        """Create/migrate nvd_records table cleanly; returns True if schema changed."""
        changed = False
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS nvd_records (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                cvss_version TEXT,
                cvss_provenance TEXT,
                source_identifier TEXT,
                published TEXT,
                last_modified TEXT,
                updated_at TEXT
            )
            """
        )
        existing_cols = {
            row[1]
            for row in conn.execute("PRAGMA table_info(nvd_records)").fetchall()
            if len(row) > 1
        }
        for col_name, col_type in _NVD_RECORD_MIGRATIONS:
            if col_name not in existing_cols:
                conn.execute(f"ALTER TABLE nvd_records ADD COLUMN {col_name} {col_type}")
                changed = True
        conn.execute("CREATE INDEX IF NOT EXISTS idx_nvd_updated_at ON nvd_records(updated_at)")
        return changed

    def _sqlite_quarantine_and_reset(self) -> None:
        """Quarantine tampered files and reinitialize a clean SQLite index."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        try:
            if self._sqlite_path and os.path.exists(self._sqlite_path):
                os.replace(self._sqlite_path, f"{self._sqlite_path}.tampered.{ts}")
            if self._sqlite_sig_path and os.path.exists(self._sqlite_sig_path):
                os.replace(self._sqlite_sig_path, f"{self._sqlite_sig_path}.tampered.{ts}")
        except OSError:
            pass

        if not self._sqlite_path:
            return

        with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
            with conn:
                self._ensure_nvd_schema(conn)

        self._sqlite_harden_permissions()
        self._sqlite_write_signature()

    def _is_valid_cve_id(self, cve_id: str) -> bool:
        if not isinstance(cve_id, str):
            return False
        return _CVE_ID_RE.match(cve_id.strip()) is not None

    def _filter_valid_cves(self, target_cves: Optional[Set[str]]) -> Optional[Set[str]]:
        if target_cves is None:
            return None
        out: Set[str] = set()
        for raw in target_cves:
            if not isinstance(raw, str):
                continue
            cand = raw.strip().upper()
            if self._is_valid_cve_id(cand):
                out.add(cand)
        return out

    def _init_sqlite_index(self) -> None:
        """Initialize optional SQLite index for warm-run acceleration."""
        try:
            paths = getattr(self.ctx, "paths", None)
            cache_dir = getattr(paths, "cache_dir", None) if paths else None
            if not cache_dir or not isinstance(cache_dir, (str, os.PathLike)):
                return

            from pathlib import Path
            db_path = Path(cache_dir) / "nvd_cache.sqlite3"
            sig_path = f"{db_path}.sig.json"
            db_existed = db_path.exists()

            if not db_existed:
                db_path = Path(
                    self.ctx.pfh.ensure_writable_file(
                        db_path,
                        label="NVD SQLite Index",
                        create_parents=True,
                        overwrite=False,
                    )
                )
            else:
                self.ctx.pfh.ensure_readable_file(db_path, label="NVD SQLite Index")
                if not os.access(db_path, os.W_OK):
                    raise PermissionError(
                        f"NVD SQLite index is not writable: {self.ctx.pfh.format_for_log(db_path)}"
                    )

            self._sqlite_enabled = True
            self._sqlite_path = str(db_path)
            self._sqlite_sig_path = sig_path

            if db_existed:
                self._sqlite_harden_permissions()
                if not self._sqlite_verify_signature():
                    self.ctx.logger.warning(
                        "NVD SQLite signature verification failed; quarantining and rebuilding index.",
                        extra={"vp_label": "NVD Optimization"},
                    )
                    self._sqlite_quarantine_and_reset()
                else:
                    with contextlib.closing(sqlite3.connect(str(db_path))) as conn:
                        with conn:
                            self._ensure_nvd_schema(conn)
                            conn.execute("PRAGMA integrity_check")
            else:
                with contextlib.closing(sqlite3.connect(str(db_path))) as conn:
                    with conn:
                        self._ensure_nvd_schema(conn)
                        conn.execute("PRAGMA integrity_check")

            self._sqlite_harden_permissions()
            self._sqlite_prune()
            self._sqlite_write_signature()

            self.ctx.logger.debug(
                "NVD SQLite index enabled at %s",
                self.ctx.pfh.format_for_log(db_path),
                extra={"vp_label": "NVD Optimization"},
            )
        except PermissionError:
            raise
        except (OSError, sqlite3.DatabaseError, ValueError, TypeError, AttributeError) as exc:
            self._sqlite_enabled = False
            self._sqlite_path = None
            self._sqlite_sig_path = None
            self.ctx.logger.warning(
                "NVD SQLite index disabled (init failed): %s",
                exc,
                extra={"vp_label": "NVD Optimization"},
            )

    def _sqlite_hydrate_targets(self, target_cves: Set[str]) -> Set[str]:
        """Hydrate in-memory lookup from SQLite and return unresolved valid target CVEs."""
        valid_targets = self._filter_valid_cves(target_cves) or set()
        if not valid_targets:
            return set()

        if not self._sqlite_enabled or not self._sqlite_path:
            return set(valid_targets)

        if not self._sqlite_verify_signature():
            self.ctx.logger.warning(
                "NVD SQLite signature verification failed during hydrate; rebuilding local index.",
                extra={"vp_label": "NVD Optimization"},
            )
            self._sqlite_quarantine_and_reset()
            return set(valid_targets)

        unresolved = set(valid_targets)
        try:
            all_rows: List[Tuple[Any, ...]] = []
            batch = sorted(valid_targets)
            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    for i in range(0, len(batch), _SQLITE_CHUNK_SIZE):
                        chunk = batch[i:i + _SQLITE_CHUNK_SIZE]
                        placeholders = ",".join("?" for _ in chunk)
                        sql = (
                            "SELECT cve_id, description, cvss_score, cvss_vector, "
                            "cvss_version, cvss_provenance, source_identifier, published, last_modified "
                            f"FROM nvd_records WHERE cve_id IN ({placeholders})"
                        )
                        all_rows.extend(conn.execute(sql, tuple(chunk)).fetchall())

            for row in all_rows:
                (
                    cve_id,
                    description,
                    cvss_score,
                    cvss_vector,
                    cvss_version,
                    cvss_provenance,
                    source_identifier,
                    published,
                    last_modified,
                ) = row
                self.lookup[cve_id] = {
                    "id": cve_id,
                    "description": description or "",
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "cvss_version": cvss_version,
                    "cvss_provenance": cvss_provenance,
                    "source_identifier": source_identifier,
                    "published": published,
                    "last_modified": last_modified,
                }
                unresolved.discard(cve_id)

            if all_rows:
                self.ctx.logger.debug(
                    "NVD SQLite warm-hit: hydrated=%d unresolved=%d",
                    len(all_rows),
                    len(unresolved),
                    extra={"vp_label": "NVD Optimization"},
                )
        except (OSError, sqlite3.DatabaseError, ValueError, TypeError) as exc:
            self.ctx.logger.warning(
                "NVD SQLite hydrate failed; continuing with feed parse: %s",
                exc,
                extra={"vp_label": "NVD Optimization"},
            )
        return unresolved

    def _sqlite_upsert(self, records: List[Dict[str, Any]]) -> None:
        """Persist parsed records to SQLite index in batch."""
        if not self._sqlite_enabled or not self._sqlite_path or not records:
            return

        if not self._sqlite_verify_signature():
            self.ctx.logger.warning(
                "NVD SQLite signature verification failed during upsert; rebuilding local index.",
                extra={"vp_label": "NVD Optimization"},
            )
            self._sqlite_quarantine_and_reset()

        now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        payload = [
            (
                r.get("id"),
                r.get("description", ""),
                r.get("cvss_score"),
                r.get("cvss_vector"),
                r.get("cvss_version"),
                r.get("cvss_provenance"),
                r.get("source_identifier"),
                r.get("published"),
                r.get("last_modified"),
                now_utc,
            )
            for r in records
            if r.get("id")
        ]

        if not payload:
            return

        try:
            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    conn.executemany(
                        """
                        INSERT INTO nvd_records (
                            cve_id, description, cvss_score, cvss_vector,
                            cvss_version, cvss_provenance, source_identifier,
                            published, last_modified, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(cve_id) DO UPDATE SET
                            description=excluded.description,
                            cvss_score=excluded.cvss_score,
                            cvss_vector=excluded.cvss_vector,
                            cvss_version=excluded.cvss_version,
                            cvss_provenance=excluded.cvss_provenance,
                            source_identifier=excluded.source_identifier,
                            published=excluded.published,
                            last_modified=excluded.last_modified,
                            updated_at=excluded.updated_at
                        """,
                        payload,
                    )
            self._sqlite_prune()
            self._sqlite_write_signature()
        except (OSError, sqlite3.DatabaseError, ValueError, TypeError) as exc:
            self.ctx.logger.warning(
                "NVD SQLite upsert failed; in-memory index remains available: %s",
                exc,
                extra={"vp_label": "NVD Optimization"},
            )

    def _sqlite_get_one(self, cve_id: str) -> Optional[Dict[str, Any]]:
        if not self._sqlite_enabled or not self._sqlite_path:
            return None
        if not self._is_valid_cve_id(cve_id):
            return None
        normalized = cve_id.strip().upper()
        if not self._sqlite_verify_signature():
            self.ctx.logger.warning(
                "NVD SQLite signature verification failed during lookup; rebuilding local index.",
                extra={"vp_label": "NVD Optimization"},
            )
            self._sqlite_quarantine_and_reset()
            return None
        try:
            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    row = conn.execute(
                        "SELECT cve_id, description, cvss_score, cvss_vector, "
                        "cvss_version, cvss_provenance, source_identifier, published, last_modified "
                        "FROM nvd_records WHERE cve_id = ?",
                        (normalized,),
                    ).fetchone()

            if not row:
                return None
            cve, desc, cvss, vector, ver, prov, src_id, pub, mod = row
            return {
                "id": cve,
                "description": desc or "",
                "cvss_score": cvss,
                "cvss_vector": vector,
                "cvss_version": ver,
                "cvss_provenance": prov,
                "source_identifier": src_id,
                "published": pub,
                "last_modified": mod,
            }
        except (OSError, sqlite3.DatabaseError, ValueError, TypeError):
            return None

    def refresh(self, *, config: dict, feed_cache, refresh_cache: bool, offline: bool, years: Optional[Set[int]] = None, include_modified: bool = True, target_cves: Optional[Set[str]] = None) -> None:
        feeds = nvd_feed_plan(config)

        if not feeds:
            self.ctx.logger.print_info("NVD disabled via config.")
            return

        if years is not None:
            feeds = self._filter_feeds_by_years(feeds, years, include_modified=include_modified)
            if not feeds:
                self.ctx.logger.info("Enabled, but no feeds selected by plan; skipping...", extra={"vp_label": "NVD Feed Loader"})
                return

        missing: List[str] = []
        effective_targets = target_cves if target_cves is not None else self.target_cves
        valid_targets = self._filter_valid_cves(effective_targets)
        if effective_targets is not None:
            if not valid_targets:
                self.target_cves = set()
                self.ctx.logger.debug(
                    "NVD refresh skipped: target_cves contained no valid CVE IDs.",
                    extra={"vp_label": "NVD Optimization"},
                )
                return
            unresolved = self._sqlite_hydrate_targets(valid_targets)
            if not unresolved:
                self.target_cves = set()
                self.ctx.logger.debug(
                    "NVD refresh short-circuited: all target CVEs resolved from SQLite.",
                    extra={"vp_label": "NVD Optimization"},
                )
                return
            self.target_cves = unresolved
            self.ctx.logger.debug(
                f"NVD index filtered to {len(unresolved)} unresolved valid CVEs from scan",
                extra={"vp_label": "NVD Optimization"}
            )
        else:
            self.target_cves = None

        # first resolve all feed paths so that we can handle missing ones
        resolved_paths: List[str] = []
        for f in feeds:
            try:
                path = feed_cache.resolve_nvd_feed(
                    key=f["key"],
                    ttl_hours=int(f["ttl_hours"]),
                    refresh_cache=refresh_cache,
                    offline=offline,
                )
            except FileNotFoundError:
                missing.append(f["fname"])
                continue
            resolved_paths.append(path)

        # parse each path; use threads when there is more than one to reduce wall time
        if resolved_paths:
            if len(resolved_paths) > 1:
                max_workers = min(len(resolved_paths), os.cpu_count() or 1)
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
                    futures = {pool.submit(self._parse_feed, p): p for p in resolved_paths}
                    for fut in concurrent.futures.as_completed(futures):
                        # propagate exceptions
                        fut.result()
            else:
                self._parse_feed(resolved_paths[0])

        if offline and missing:
            self.ctx.logger.warning(
                f"Offline mode: {len(missing)} feed(s) missing: {', '.join(missing)}."
            )
    # NOTE(perf): NVD feed parse builds in-mem O(1) index at startup.
    # Uses ijson streaming to parse one CVE at a time (no full load into RAM).
    # With target_cves filtering, only parses CVEs needed by the scan.
    def _parse_feed(self, path: str) -> None:
        """Parse NVD 2.0 feed into lookup dict with streaming and optional CVE filtering."""
        ctx = self.ctx
        parsed_count = 0
        skipped_count = 0
        sqlite_batch: List[Dict[str, Any]] = []

        # Determine if this feed is year-specific so we can fast-skip
        year = None
        path_str = str(path)
        m = re.search(r"year\.(\d{4})", path_str)
        if m:
            try:
                year = int(m.group(1))
            except ValueError:
                year = None

        # Compute remaining targets for this feed (used for early termination)
        target_set = self._filter_valid_cves(self.target_cves)
        remaining: Optional[Set[str]] = None
        if target_set is not None:
            if not target_set:
                return
            if year is not None:
                prefix = f"CVE-{year}-"
                remaining = {c for c in target_set if c.startswith(prefix)}
                if not remaining:
                    # nothing to index in this year's file
                    ctx.logger.debug(
                        f"Skipping {year} feed; no CVEs from scan match this year.",
                        extra={"vp_label": "NVD Optimization"}
                    )
                    return
            else:
                # modified feed: we need to look for any remaining CVEs
                remaining = set(target_set)

        # open_for_read already validates path; suppress redundant log message
        with ctx.pfh.open_for_read(path, mode="rb", label="NVD Feed (.json.gz)", log=False) as raw:
            # Open gzip in binary mode for ijson efficiency
            with gzip.open(raw, mode="rb") as f:
                # Use ijson for streaming if available, fallback to json.load
                if ijson is not None:
                    vulnerabilities = ijson.items(f, "vulnerabilities.item")
                else:
                    text_f = io.TextIOWrapper(f, encoding="utf-8")
                    data = json.load(text_f)
                    vulnerabilities = data.get("vulnerabilities", [])

                # Parse pertinent information from feeds.
                for item in vulnerabilities:
                    cve = (item or {}).get("cve", {}) or {}
                    raw_cve_id = cve.get("id")
                    if not raw_cve_id:
                        continue
                    cve_id = str(raw_cve_id).strip().upper()

                    # Early exit: skip if filtering and CVE not in target set
                    if target_set is not None and cve_id not in target_set:
                        skipped_count += 1
                    else:
                        parsed_count += 1

                        # Description (prefer English)
                        desc = ""
                        descs = cve.get("descriptions") or []
                        if descs:
                            en_desc = next(
                                (
                                    (d or {}).get("value")
                                    for d in descs
                                    if isinstance(d, dict) and str(d.get("lang", "")).lower() == "en"
                                ),
                                None,
                            )
                            desc = en_desc if en_desc is not None else ((descs[0] or {}).get("value", "") or "")
                        # Published/lastMod
                        published = cve.get("published")
                        last_mod = cve.get("lastModified")
                        cve_source_identifier = str(cve.get("sourceIdentifier") or "").strip() or None
                        # CVSS Metrics (v4.0 > v3.1 > v3.0 > v2.0 with NVD vs CNA provenance)
                        metrics = cve.get("metrics", {}) or {}
                        cvss, vector, cvss_version, cvss_provenance, metric_source = self._choose_cvss(
                            metrics,
                            default_source_identifier=cve_source_identifier,
                        )

                        # Create O(1) Lookup (thread-safe)
                        record = {
                            "id": cve_id,
                            "description": desc,
                            "cvss_score": cvss,
                            "cvss_vector": vector,
                            "cvss_version": cvss_version,
                            "cvss_provenance": cvss_provenance,
                            "source_identifier": metric_source or cve_source_identifier,
                            "published": published,
                            "last_modified": last_mod,
                        }

                        with self._lock:
                            self.lookup[cve_id] = record

                        sqlite_batch.append(record)

                        if remaining is not None and cve_id in remaining:
                            remaining.remove(cve_id)
                            if not remaining:
                                ctx.logger.debug(
                                    f"Early termination: all target CVEs for {'year ' + str(year) if year else 'modified feed'} indexed after {parsed_count + skipped_count} items",
                                    extra={"vp_label": "NVD Optimization"}
                                )
                                break

        # Log parse statistics
        if target_set is not None and skipped_count > 0:
            ctx.logger.debug(
                f"NVD parse: indexed {parsed_count} CVEs, skipped {skipped_count} (not in scan)",
                extra={"vp_label": "NVD Optimization"}
            )

        if sqlite_batch:
            self._sqlite_upsert(sqlite_batch)

    @staticmethod
    def _parse_valid_score(raw: Any) -> Optional[float]:
        if raw is None or isinstance(raw, bool):
            return None
        try:
            val = float(raw)
        except (TypeError, ValueError):
            return None
        if not math.isfinite(val) or val < 0.0 or val > 10.0:
            return None
        return val

    @staticmethod
    def _metric_rank(
        m: Dict[str, Any],
        *,
        tier_idx: int = 0,
        default_source_identifier: Optional[str] = None,
    ) -> Tuple[int, int, int]:
        m_type = str(m.get("type") or "").strip().lower()
        m_source = str(m.get("source") or default_source_identifier or "").strip().lower()
        is_nvd_src = "nvd@nist.gov" in m_source
        is_primary = m_type == "primary"
        if is_primary and is_nvd_src:
            prov_rank = 0
        elif is_nvd_src:
            prov_rank = 1
        else:
            prov_rank = 2
        type_rank = 0 if is_primary else 1
        return (prov_rank, tier_idx, type_rank)

    @classmethod
    def _pick_metric_from_tier(cls, metrics_list: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Within a CVSS version tier, prefer NVD Primary, then NVD Secondary, then CNA Primary, then Secondary."""
        candidates = [m for m in (metrics_list or []) if isinstance(m, dict) and isinstance(m.get("cvssData"), dict)]
        if not candidates:
            return None
        return min(candidates, key=lambda m: cls._metric_rank(m))

    def _choose_cvss(
        self,
        metrics: Any,
        *,
        default_source_identifier: Optional[str] = None,
    ) -> Tuple[Optional[float], Optional[str], Optional[str], Optional[str], Optional[str]]:
        """
        Select CVSS enforcing NVD > CNA across all CVSS version tiers
        (cvssMetricV40 > cvssMetricV31 > cvssMetricV30 > cvssMetricV2 within each provenance tier).
        Returns (score, vector, cvss_version, cvss_provenance, source_identifier).
        """
        chosen: Optional[Dict[str, Any]] = None
        tier_version: Optional[str] = None

        if isinstance(metrics, dict):
            ranked_candidates: List[Tuple[Tuple[int, int, int], int, Optional[str], Dict[str, Any]]] = []
            seq = 0
            for tier_idx, (key, version_str) in enumerate(_NVD_CVSS_TIERS):
                tier_list = metrics.get(key)
                if not isinstance(tier_list, list):
                    continue
                for m in tier_list:
                    if not isinstance(m, dict) or not isinstance(m.get("cvssData"), dict):
                        continue
                    data = m["cvssData"]
                    raw_vec = data.get("vectorString")
                    has_vec = isinstance(raw_vec, str) and bool(raw_vec.strip())
                    has_score = self._parse_valid_score(data.get("baseScore")) is not None
                    if not has_vec and not has_score:
                        continue
                    rank = self._metric_rank(
                        m,
                        tier_idx=tier_idx,
                        default_source_identifier=default_source_identifier,
                    )
                    ranked_candidates.append((rank, seq, version_str, m))
                    seq += 1
            if ranked_candidates:
                _, _, tier_version, chosen = min(ranked_candidates, key=lambda item: (item[0], item[1]))
        elif isinstance(metrics, list) and metrics:
            chosen = self._pick_metric_from_tier(metrics)

        if not chosen or not isinstance(chosen.get("cvssData"), dict):
            return None, None, None, None, default_source_identifier

        data = chosen["cvssData"]
        vector = data.get("vectorString")
        if isinstance(vector, str):
            vector = vector.strip() or None
        else:
            vector = None

        score = self._parse_valid_score(data.get("baseScore"))
        if score is None and vector:
            score = compute_cvss_base_score(vector)

        if score is None and not vector:
            return None, None, None, None, default_source_identifier

        cvss_version = tier_version
        if cvss_version is None and vector:
            cvss_version = detect_cvss_exact_version(vector)
        if cvss_version is None and data.get("version") is not None:
            cvss_version = str(data.get("version")).strip() or None

        m_type = str(chosen.get("type") or "").strip()
        m_source = str(chosen.get("source") or default_source_identifier or "").strip()
        provenance = "NVD" if (m_type.lower() == "primary" and "nvd@nist.gov" in m_source.lower()) else "CNA"
        source_id = m_source or default_source_identifier
        return score, vector, cvss_version, provenance, source_id

    def get(self, cve_id: str) -> dict[str, Any]:
        """Lookup CVE from cache.
        Always return a normalized dict with expected keys, even if the CVE is missing
        (values default to None and found=False).
        """
        default_record: Dict[str, Any] = {
            "id": cve_id,
            "description": "",
            "cvss_score": None,
            "cvss_vector": None,
            "cvss_version": None,
            "cvss_provenance": None,
            "source_identifier": None,
            "published": None,
            "last_modified": None,
            "found": False,
        }

        if not isinstance(cve_id, str) or not cve_id.strip():
            return default_record

        normalized = cve_id.strip().upper()
        record = self.lookup.get(cve_id) or self.lookup.get(normalized)
        if not record:
            sqlite_record = self._sqlite_get_one(normalized)
            if sqlite_record:
                self.lookup[normalized] = sqlite_record
                record = sqlite_record
        if not record:
            return default_record

        merged = {**default_record, **record}
        merged["found"] = True
        return merged

    def _filter_feeds_by_years(self, feeds: List[Dict], years: Set[int], *, include_modified: bool) -> List[Dict]:
        output: List[Dict] = []
        for f in feeds:
            key = str(f.get("key", ""))

            if key == "nvd.modified":
                if include_modified:
                    output.append(f)
                continue

            m = _YEAR_KEY_RE.match(key)
            if m and int(m.group(1)) in years:
                output.append(f)

        return output

def _cfg_get(config: Dict[str, Any], path: List[str], default = None):
    cur = config
    for k in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
        if cur is None:
            return default
    return cur

def _cfg_int(config: Dict[str, Any], path: List[str], default: int) -> int:
    v = _cfg_get(config, path, default)
    try:
        return int(v)
    except Exception:
        return default

def _cfg_bool(config: Dict[str, Any], path: List[str], default: bool) -> bool:
    v = _cfg_get(config, path, default)
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "y", "on")
    return default

def nvd_policy_from_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pulls NVD policy config values from the config.
    Prefers centralized keys under feed_cache.feeds.nvd, with legacy fallbacks.
    """
    enabled = _cfg_bool(
        config,
        ["feed_cache", "feeds", "nvd", "enabled"],
        _cfg_bool(config, ["feed_cache", "nvd", "enabled"], True),
    )

    ttl_default = _cfg_int(config, ["feed_cache", "defaults", "ttl_hours"], 24)

    ttl_yearly = _cfg_int(
        config,
        ["feed_cache", "feeds", "nvd", "ttl_yearly"],
        _cfg_int(
            config,
            ["feed_cache", "nvd", "ttl_yearly"],
            _cfg_int(config, ["feed_cache", "ttl_hours", "nvd_yearly"], ttl_default),
        ),
    )

    legacy_modified = _cfg_get(config, ["feed_cache", "ttl_hours", "nvd_modified"], None)
    if legacy_modified is None:
        legacy_modified = _cfg_get(config, ["feed_cache", "ttl_hours", "mvd_modified"], None)
    ttl_modified = _cfg_int(
        config,
        ["feed_cache", "feeds", "nvd", "ttl_modified"],
        _cfg_int(
            config,
            ["feed_cache", "nvd", "ttl_modified"],
            int(legacy_modified) if legacy_modified is not None else min(2, ttl_default),
        ),
    )


    now_year = datetime.now(timezone.utc).year
    start_year = _cfg_int(
        config,
        ["feed_cache", "feeds", "nvd", "start_year"],
        _cfg_int(config, ["feed_cache", "nvd", "start_year"], now_year),
    )
    end_year = _cfg_int(
        config,
        ["feed_cache", "feeds", "nvd", "end_year"],
        _cfg_int(config, ["feed_cache", "nvd", "end_year"], now_year),
    )


    if start_year > end_year:
        start_year, end_year = end_year, start_year
    if end_year > now_year:
        end_year = now_year

    return {
        "enabled": enabled,
        "ttl_default": ttl_default,
        "ttl_yearly": ttl_yearly,
        "ttl_modified": ttl_modified,
        "start_year": start_year,
        "end_year": end_year,
        "sqlite_enforce_permissions": _cfg_bool(config, ["feed_cache", "feeds", "nvd", "sqlite_enforce_permissions"], True),
        "sqlite_max_age_hours": _cfg_int(config, ["feed_cache", "feeds", "nvd", "sqlite_max_age_hours"], 24 * 14),
        "sqlite_max_rows": _cfg_int(config, ["feed_cache", "feeds", "nvd", "sqlite_max_rows"], 500000),
    }

def nvd_feed_plan(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Returns the NVD Feed plan based off the YAML config parameters.

    :param config: Global config YAML
    :type config: Dict[str, Any]
    :return: A list of nvd feed params based on YAML config.
    :rtype: List[Dict[str, Any]]
    """
    p = nvd_policy_from_config(config)
    if not p["enabled"]:
        return []

    feeds = [{
        "key": "nvd.modified",
        "fname": "modified.json.gz",
        "ttl_hours": p["ttl_modified"],
    }]

    for y in range(p["start_year"], p["end_year"] + 1):
        feeds.append({
            "key": f"nvd.year.{y}",
            "fname": f"{y}.json.gz",
            "ttl_hours": p["ttl_yearly"],
        })

    return feeds
