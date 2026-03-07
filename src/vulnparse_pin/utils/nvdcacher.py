# VulnParse-Pin – Vulnerability Parsing and Triage Engine
# Copyright (C) 2025 Shade216

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.
from __future__ import annotations
import gzip
import json
from datetime import datetime, timezone, timedelta
import re
import io
import threading
import concurrent.futures, os
import sqlite3
import hashlib
import hmac
import stat
from typing import Any, Dict, List, TYPE_CHECKING, Optional, Set
try:
    import ijson
except ImportError as exc:
    ijson = None
    print(f"ijson dependency is missing; for runtime optimization, install ijson 'pip install ijson': {exc}")

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext

_YEAR_KEY_RE = re.compile(r"^nvd\.year\.(\d{4})$")
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

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
            with sqlite3.connect(self._sqlite_path) as conn:
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
        with self.ctx.pfh.open_for_write(sig_path, mode="w", encoding="utf-8", label="NVD SQLite Signature", log=False) as f:
            json.dump(payload, f, indent=2)

    def _sqlite_verify_signature(self) -> bool:
        """Verify index signature integrity; returns False when tampering/corruption is detected."""
        if not self._sqlite_enabled or not self._sqlite_path:
            return False

        if not self._sqlite_sig_path or not os.path.exists(self._sqlite_sig_path):
            # Bootstrap legacy/first-run index by signing current file.
            self._sqlite_write_signature()
            return True

        try:
            with self.ctx.pfh.open_for_read(self._sqlite_sig_path, mode="r", encoding="utf-8", label="NVD SQLite Signature", log=False) as f:
                payload = json.load(f)

            mode = str(payload.get("mode", "sha256"))
            expected_sig = str(payload.get("signature", ""))
            expected_digest = str(payload.get("digest", ""))
            current_digest = self._sqlite_compute_digest()
            if not current_digest:
                return False

            if not hmac.compare_digest(expected_digest, current_digest):
                return False

            if mode == "hmac-sha256":
                secret = self._sqlite_secret()
                if secret is None:
                    return False
                current_sig = hmac.new(secret, current_digest.encode("utf-8"), hashlib.sha256).hexdigest()
            else:
                current_sig = current_digest

            return hmac.compare_digest(expected_sig, current_sig)
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return False

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

        with sqlite3.connect(self._sqlite_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS nvd_records (
                    cve_id TEXT PRIMARY KEY,
                    description TEXT,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    published TEXT,
                    last_modified TEXT,
                    updated_at TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_nvd_updated_at ON nvd_records(updated_at)")

        self._sqlite_write_signature()

    def _is_valid_cve_id(self, cve_id: str) -> bool:
        if not isinstance(cve_id, str):
            return False
        return _CVE_ID_RE.match(cve_id.strip()) is not None

    def _init_sqlite_index(self) -> None:
        """Initialize optional SQLite index for warm-run acceleration."""
        try:
            paths = getattr(self.ctx, "paths", None)
            if not paths or not getattr(paths, "cache_dir", None):
                return

            db_path = paths.cache_dir / "nvd_cache.sqlite3"
            if not db_path.exists():
                db_path = self.ctx.pfh.ensure_writable_file(
                    db_path,
                    label="NVD SQLite Index",
                    create_parents=True,
                    overwrite=False,
                )
            else:
                self.ctx.pfh.ensure_readable_file(db_path, label="NVD SQLite Index")
                if not os.access(db_path, os.W_OK):
                    raise PermissionError(
                        f"NVD SQLite index is not writable: {self.ctx.pfh.format_for_log(db_path)}"
                    )

            with sqlite3.connect(str(db_path)) as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS nvd_records (
                        cve_id TEXT PRIMARY KEY,
                        description TEXT,
                        cvss_score REAL,
                        cvss_vector TEXT,
                        published TEXT,
                        last_modified TEXT,
                        updated_at TEXT
                    )
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_nvd_updated_at ON nvd_records(updated_at)"
                )
                conn.execute("PRAGMA integrity_check")

            self._sqlite_enabled = True
            self._sqlite_path = str(db_path)
            self._sqlite_sig_path = f"{self._sqlite_path}.sig.json"
            self._sqlite_harden_permissions()

            if not self._sqlite_verify_signature():
                self.ctx.logger.warning(
                    "NVD SQLite signature verification failed; quarantining and rebuilding index.",
                    extra={"vp_label": "NVD Optimization"},
                )
                self._sqlite_quarantine_and_reset()

            self._sqlite_prune()

            self.ctx.logger.debug(
                "NVD SQLite index enabled at %s",
                self.ctx.pfh.format_for_log(db_path),
                extra={"vp_label": "NVD Optimization"},
            )
        except (OSError, sqlite3.DatabaseError, ValueError, TypeError) as exc:
            self._sqlite_enabled = False
            self._sqlite_path = None
            self.ctx.logger.warning(
                "NVD SQLite index disabled (init failed): %s",
                exc,
                extra={"vp_label": "NVD Optimization"},
            )

    def _sqlite_hydrate_targets(self, target_cves: Set[str]) -> Set[str]:
        """Hydrate in-memory lookup from SQLite and return unresolved target CVEs."""
        if not self._sqlite_enabled or not self._sqlite_path or not target_cves:
            return set(target_cves)

        if not self._sqlite_verify_signature():
            self.ctx.logger.warning(
                "NVD SQLite signature verification failed during hydrate; rebuilding local index.",
                extra={"vp_label": "NVD Optimization"},
            )
            self._sqlite_quarantine_and_reset()
            return set(target_cves)

        valid_targets = {c for c in target_cves if self._is_valid_cve_id(c)}
        if not valid_targets:
            return set(target_cves)

        unresolved = set(target_cves)
        try:
            with sqlite3.connect(self._sqlite_path) as conn:
                placeholders = ",".join("?" for _ in valid_targets)
                sql = (
                    f"SELECT cve_id, description, cvss_score, cvss_vector, published, last_modified "
                    f"FROM nvd_records WHERE cve_id IN ({placeholders})"
                )
                rows = conn.execute(sql, tuple(valid_targets)).fetchall()

            for row in rows:
                cve_id, description, cvss_score, cvss_vector, published, last_modified = row
                self.lookup[cve_id] = {
                    "id": cve_id,
                    "description": description or "",
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "published": published,
                    "last_modified": last_modified,
                }
                unresolved.discard(cve_id)

            if rows:
                self.ctx.logger.debug(
                    "NVD SQLite warm-hit: hydrated=%d unresolved=%d",
                    len(rows),
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
            with sqlite3.connect(self._sqlite_path) as conn:
                conn.executemany(
                    """
                    INSERT INTO nvd_records (
                        cve_id, description, cvss_score, cvss_vector, published, last_modified, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                        description=excluded.description,
                        cvss_score=excluded.cvss_score,
                        cvss_vector=excluded.cvss_vector,
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
        if not self._sqlite_verify_signature():
            self.ctx.logger.warning(
                "NVD SQLite signature verification failed during lookup; rebuilding local index.",
                extra={"vp_label": "NVD Optimization"},
            )
            self._sqlite_quarantine_and_reset()
            return None
        try:
            with sqlite3.connect(self._sqlite_path) as conn:
                row = conn.execute(
                    "SELECT cve_id, description, cvss_score, cvss_vector, published, last_modified FROM nvd_records WHERE cve_id = ?",
                    (cve_id,),
                ).fetchone()

            if not row:
                return None
            cve, desc, cvss, vector, pub, mod = row
            return {
                "id": cve,
                "description": desc or "",
                "cvss_score": cvss,
                "cvss_vector": vector,
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
        self.target_cves = target_cves

        if target_cves:
            unresolved = self._sqlite_hydrate_targets(target_cves)
            if not unresolved:
                self.ctx.logger.debug(
                    "NVD refresh short-circuited: all target CVEs resolved from SQLite.",
                    extra={"vp_label": "NVD Optimization"},
                )
                return
            self.target_cves = unresolved

        if target_cves:
            self.ctx.logger.debug(
                f"NVD index filtered to {len(target_cves)} CVEs from scan",
                extra={"vp_label": "NVD Optimization"}
            )

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
        remaining: Optional[Set[str]] = None
        if self.target_cves is not None:
            if year is not None:
                prefix = f"CVE-{year}-"
                remaining = {c for c in self.target_cves if c.startswith(prefix)}
                if not remaining:
                    # nothing to index in this year's file
                    ctx.logger.debug(
                        f"Skipping {year} feed; no CVEs from scan match this year.",
                        extra={"vp_label": "NVD Optimization"}
                    )
                    return
            else:
                # modified feed: we need to look for any remaining CVEs
                remaining = set(self.target_cves)

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
                    cve_id = cve.get("id")
                    if not cve_id:
                        continue

                    # Early exit: skip if filtering and CVE not in target set
                    if self.target_cves is not None and cve_id not in self.target_cves:
                        skipped_count += 1
                    else:
                        parsed_count += 1

                        # Description
                        desc = ""
                        descs = cve.get("descriptions") or []
                        if descs:
                            desc = (descs[0] or {}).get("value", "") or ""
                        # Published/lastMod
                        published = cve.get("published")
                        last_mod = cve.get("lastModified")
                        # CVSS Metrics
                        metrics = cve.get("metrics", {}) or {}
                        cvss, vector = None, None
                        # Break out CVSS Version Prioritization
                        if "cvssMetricV31" in metrics:
                            cvss, vector = self._choose_cvss(metrics["cvssMetricV31"])
                        elif "cvssMetricV30" in metrics:
                            cvss, vector = self._choose_cvss(metrics["cvssMetricV30"])
                        elif "cvssMetricV2" in metrics:
                            cvss, vector = self._choose_cvss(metrics["cvssMetricV2"])

                        # Create O(1) Lookup (thread-safe)
                        record = {
                            "id": cve_id,
                            "description": desc,
                            "cvss_score": cvss,
                            "cvss_vector": vector,
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
        if self.target_cves is not None and skipped_count > 0:
            ctx.logger.debug(
                f"NVD parse: indexed {parsed_count} CVEs, skipped {skipped_count} (not in scan)",
                extra={"vp_label": "NVD Optimization"}
            )

        if sqlite_batch:
            self._sqlite_upsert(sqlite_batch)

    def _choose_cvss(self, metrics_list) -> tuple | tuple[None, None]:
        """Pick Primary cvss first, fallback to Secondary."""
        primary = next((m for m in metrics_list if m.get("type") == "Primary"), None)
        if not primary and metrics_list:
            primary = metrics_list[0]
        if primary and "cvssData" in primary:
            d = primary["cvssData"]
            return d.get("baseScore"), d.get("vectorString")
        return None, None

    def get(self, cve_id: str) -> dict[str, Any]:
        """Lookup CVE from cache.
        Always return a normalized dict with expected keys, even if the CVE is missing
        (values default to None).
        """

        default_record = {
        "id": cve_id,
        "description": "",
        "cvss_score": None,
        "cvss_vector": None,
        "published": None,
        "last_Modified": None,
        "found": False,
        }

        record = self.lookup.get(cve_id, {})
        if not record:
            sqlite_record = self._sqlite_get_one(cve_id)
            if sqlite_record:
                self.lookup[cve_id] = sqlite_record
                record = sqlite_record
        if record is None:
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


    now_year = datetime.now().year
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
