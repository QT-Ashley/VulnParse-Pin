# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

"""
Optional offline OSV (Open Source Vulnerabilities) enrichment cache.

Supports local OSV JSON files, ecosystem directories, and .zip bundles with
strict zip-bomb and path-traversal protections, backed by a 0o600 HMAC-signed
SQLite cache (`osv_cache.sqlite3`) with <=900-parameter chunked queries.
"""

from __future__ import annotations

import contextlib
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
import zipfile

from vulnparse_pin.core.classes.dataclass import RunContext, ScanResult
from vulnparse_pin.utils.cvss_utils import (
    compute_cvss_base_score,
    detect_cvss_exact_version,
    is_valid_cvss_vector,
)
from vulnparse_pin.utils.ghsa_enrichment import parse_purl

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_GHSA_RE = re.compile(r"^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$", re.IGNORECASE)
_PKG_TOKEN_RE = re.compile(r"[a-zA-Z0-9_.+-]{3,}")
_SQLITE_CHUNK_SIZE = 900
_CVSS_VERSION_RANK = {"4.0": 0, "3.1": 1, "3.0": 2, "2.0": 3}

DEFAULT_MAX_ZIP_ENTRIES = 250_000
DEFAULT_MAX_ZIP_ENTRY_BYTES = 50 * 1024 * 1024
DEFAULT_MAX_ZIP_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_MAX_ZIP_RATIO = 500


class OSVSecurityError(ValueError):
    """Raised when OSV archive/file validation detects path traversal, symlink, or zip-bomb hazards."""


class OSVEnrichmentSource:
    """Offline OSV advisory enrichment source with signed SQLite indexing."""

    def __init__(
        self,
        ctx: RunContext,
        *,
        max_zip_entries: int = DEFAULT_MAX_ZIP_ENTRIES,
        max_zip_entry_bytes: int = DEFAULT_MAX_ZIP_ENTRY_BYTES,
        max_zip_total_bytes: int = DEFAULT_MAX_ZIP_TOTAL_BYTES,
        max_zip_ratio: int = DEFAULT_MAX_ZIP_RATIO,
    ) -> None:
        self.ctx = ctx
        self.max_zip_entries = max_zip_entries
        self.max_zip_entry_bytes = max_zip_entry_bytes
        self.max_zip_total_bytes = max_zip_total_bytes
        self.max_zip_ratio = max_zip_ratio

        self.osv_by_cve: Dict[str, List[Dict[str, Any]]] = {}
        self.osv_by_ghsa: Dict[str, List[Dict[str, Any]]] = {}
        self.osv_by_package: Dict[str, List[Dict[str, Any]]] = {}
        self.osv_by_ecosystem_package: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        self._is_loaded = False

        self._sqlite_enabled = False
        self._sqlite_path: Optional[str] = None
        self._sqlite_sig_path: Optional[str] = None
        self._init_sqlite_index()

    # ------------------------------------------------------------------
    # SQLite security contract (0o600, S_IWOTH reject, HMAC .sig.json, tamper quarantine)
    # ------------------------------------------------------------------

    @staticmethod
    def _sqlite_secret() -> Optional[bytes]:
        raw = os.getenv("VP_SQLITE_HMAC_KEY")
        return raw.encode("utf-8") if raw else None

    @staticmethod
    def _ensure_schema(conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS osv_advisories (
                osv_id TEXT PRIMARY KEY,
                summary TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                cvss_version TEXT,
                aliases_json TEXT,
                references_json TEXT,
                advisory_json TEXT NOT NULL,
                updated_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS osv_cve_index (
                cve_id TEXT NOT NULL,
                osv_id TEXT NOT NULL,
                updated_at TEXT,
                PRIMARY KEY (cve_id, osv_id)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_osv_cve_id ON osv_cve_index(cve_id)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS osv_ghsa_index (
                ghsa_id TEXT NOT NULL,
                osv_id TEXT NOT NULL,
                updated_at TEXT,
                PRIMARY KEY (ghsa_id, osv_id)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_osv_ghsa_id ON osv_ghsa_index(ghsa_id)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS osv_package_index (
                ecosystem TEXT NOT NULL,
                package_name TEXT NOT NULL,
                osv_id TEXT NOT NULL,
                cve_id TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                cvss_version TEXT,
                summary TEXT,
                updated_at TEXT,
                PRIMARY KEY (ecosystem, package_name, osv_id)
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_osv_pkg ON osv_package_index(ecosystem, package_name)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_osv_pkg_name ON osv_package_index(package_name)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS osv_sources (
                source_key TEXT PRIMARY KEY,
                updated_at TEXT
            )
            """
        )

    def _sqlite_cache_policy(self) -> Dict[str, int]:
        cfg = getattr(self.ctx, "config", {}) or {}
        if not isinstance(cfg, dict):
            services = getattr(self.ctx, "services", None)
            cfg = getattr(services, "global_config", {}) or {}
        enrichment = cfg.get("enrichment", {}) if isinstance(cfg, dict) else {}
        osv_cache = enrichment.get("osv_cache", {}) if isinstance(enrichment, dict) else {}

        def _as_int(value: Any, default: int) -> int:
            try:
                return int(value)
            except (TypeError, ValueError):
                return default

        return {
            "max_age_hours": max(_as_int(osv_cache.get("sqlite_max_age_hours"), 24 * 14), 0),
            "max_rows": max(_as_int(osv_cache.get("sqlite_max_rows"), 500000), 0),
        }

    def _sqlite_harden_permissions(self) -> None:
        if not self._sqlite_path:
            return
        if os.name == "nt":
            self.ctx.pfh.ensure_readable_file(self._sqlite_path, label="OSV SQLite Index")
            if not os.access(self._sqlite_path, os.W_OK):
                raise PermissionError("OSV SQLite index is not writable on Windows.")
            return
        try:
            os.chmod(self._sqlite_path, 0o600)
        except OSError:
            pass
        try:
            self.ctx.pfh.ensure_readable_file(self._sqlite_path, label="OSV SQLite Index")
            st = os.stat(self._sqlite_path)
            if bool(st.st_mode & stat.S_IWOTH):
                raise PermissionError("OSV SQLite index is world-writable; refusing to continue.")
        except OSError as exc:
            raise PermissionError(f"OSV SQLite permission check failed: {exc}") from exc

    def _sqlite_compute_digest(self) -> Optional[str]:
        if not self._sqlite_path:
            return None
        digest = hashlib.sha256()
        with self.ctx.pfh.open_for_read(self._sqlite_path, mode="rb", label="OSV SQLite Index", log=False) as f:
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
            label="OSV SQLite Signature",
            create_parents=True,
            overwrite=True,
        )
        with self.ctx.pfh.open_for_write(
            sig_path,
            mode="w",
            encoding="utf-8",
            label="OSV SQLite Signature",
        ) as f:
            json.dump(payload, f, indent=2)
        if os.name != "nt":
            try:
                os.chmod(sig_path, 0o600)
            except OSError:
                pass

    def _sqlite_verify_signature(self) -> bool:
        if not self._sqlite_enabled or not self._sqlite_path:
            return False
        if not self._sqlite_sig_path or not os.path.exists(self._sqlite_sig_path):
            return False
        try:
            if os.name != "nt":
                st = os.stat(self._sqlite_sig_path)
                if bool(st.st_mode & stat.S_IWOTH):
                    return False
            with self.ctx.pfh.open_for_read(
                self._sqlite_sig_path,
                mode="r",
                encoding="utf-8",
                label="OSV SQLite Signature",
                log=False,
            ) as f:
                payload = json.load(f)
            if not isinstance(payload, dict):
                return False
            mode = str(payload.get("mode", "")).strip()
            expected_sig = str(payload.get("signature", ""))
            expected_digest = str(payload.get("digest", ""))
            current_digest = self._sqlite_compute_digest()
            if not current_digest or not hmac.compare_digest(expected_digest, current_digest):
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

    def _sqlite_quarantine_and_reset(self) -> None:
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
                self._ensure_schema(conn)
        self._sqlite_harden_permissions()
        self._sqlite_write_signature()

    def _sqlite_prune(self) -> None:
        if not self._sqlite_enabled or not self._sqlite_path:
            return
        policy = self._sqlite_cache_policy()
        max_age_hours = policy["max_age_hours"]
        max_rows = policy["max_rows"]
        try:
            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    if max_age_hours > 0:
                        cutoff = (datetime.now(timezone.utc) - timedelta(hours=max_age_hours)).isoformat().replace("+00:00", "Z")
                        for tbl in ("osv_advisories", "osv_cve_index", "osv_ghsa_index", "osv_package_index"):
                            conn.execute(f"DELETE FROM {tbl} WHERE updated_at < ?", (cutoff,))
                    if max_rows > 0:
                        cnt = conn.execute("SELECT COUNT(*) FROM osv_advisories").fetchone()[0]
                        if cnt > max_rows:
                            trim = cnt - max_rows
                            conn.execute(
                                """
                                DELETE FROM osv_advisories
                                WHERE osv_id IN (
                                    SELECT osv_id FROM osv_advisories
                                    ORDER BY COALESCE(updated_at, '') ASC
                                    LIMIT ?
                                )
                                """,
                                (trim,),
                            )
        except (OSError, sqlite3.DatabaseError) as exc:
            if getattr(self.ctx, "logger", None) is not None:
                self.ctx.logger.warning(f"OSV SQLite prune failed: {exc}")

    def _init_sqlite_index(self) -> None:
        try:
            paths = getattr(self.ctx, "paths", None)
            cache_dir = getattr(paths, "cache_dir", None) if paths else None
            if not cache_dir or not isinstance(cache_dir, (str, os.PathLike)):
                return

            db_path = Path(cache_dir) / "osv_cache.sqlite3"
            sig_path = f"{db_path}.sig.json"
            db_existed = db_path.exists()

            if not db_existed:
                db_path = Path(
                    self.ctx.pfh.ensure_writable_file(
                        db_path,
                        label="OSV SQLite Index",
                        create_parents=True,
                        overwrite=False,
                    )
                )
            else:
                self.ctx.pfh.ensure_readable_file(db_path, label="OSV SQLite Index")
                if not os.access(db_path, os.W_OK):
                    raise PermissionError(f"OSV SQLite index is not writable: {db_path}")

            self._sqlite_enabled = True
            self._sqlite_path = str(db_path)
            self._sqlite_sig_path = sig_path

            if db_existed:
                self._sqlite_harden_permissions()
                if not self._sqlite_verify_signature():
                    if getattr(self.ctx, "logger", None) is not None:
                        self.ctx.logger.warning("OSV SQLite signature failed; quarantining and rebuilding index.")
                    self._sqlite_quarantine_and_reset()
                else:
                    with contextlib.closing(sqlite3.connect(str(db_path))) as conn:
                        with conn:
                            self._ensure_schema(conn)
                            conn.execute("PRAGMA integrity_check")
            else:
                with contextlib.closing(sqlite3.connect(str(db_path))) as conn:
                    with conn:
                        self._ensure_schema(conn)
                        conn.execute("PRAGMA integrity_check")

            self._sqlite_harden_permissions()
            self._sqlite_prune()
            self._sqlite_write_signature()
        except PermissionError:
            raise
        except (OSError, sqlite3.DatabaseError, ValueError, TypeError, AttributeError) as exc:
            self._sqlite_enabled = False
            self._sqlite_path = None
            self._sqlite_sig_path = None
            if getattr(self.ctx, "logger", None) is not None:
                self.ctx.logger.warning(f"OSV SQLite index disabled: {exc}")

    # ------------------------------------------------------------------
    # Parsing & Extraction Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_valid_cve_id(value: str) -> bool:
        return isinstance(value, str) and _CVE_RE.match(value.strip()) is not None

    @staticmethod
    def _is_valid_ghsa_id(value: str) -> bool:
        return isinstance(value, str) and _GHSA_RE.match(value.strip()) is not None

    @staticmethod
    def _extract_identifiers(advisory: Dict[str, Any]) -> Tuple[str, List[str], List[str]]:
        osv_id = str(advisory.get("id") or advisory.get("osv_id") or "").strip()
        if not osv_id:
            canonical = json.dumps(advisory, sort_keys=True, separators=(",", ":"))
            osv_id = "OSV-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

        cves: List[str] = []
        ghsas: List[str] = []
        candidates: List[Any] = [osv_id, advisory.get("cve"), advisory.get("cve_id"), advisory.get("ghsa_id")]
        for list_key in ("aliases", "upstream", "related"):
            vals = advisory.get(list_key)
            if isinstance(vals, list):
                candidates.extend(vals)

        for item in candidates:
            if not isinstance(item, str):
                continue
            norm = item.strip().upper()
            if _CVE_RE.match(norm):
                cves.append(norm)
            elif norm.startswith("GHSA-"):
                ghsas.append(norm)

        return osv_id, list(dict.fromkeys(cves)), list(dict.fromkeys(ghsas))

    @staticmethod
    def _extract_packages(advisory: Dict[str, Any]) -> List[Tuple[str, str]]:
        out: List[Tuple[str, str]] = []
        pkg_name = advisory.get("package_name")
        if isinstance(pkg_name, str) and pkg_name.strip():
            eco = str(advisory.get("ecosystem") or "").strip().lower()
            out.append((eco, pkg_name.strip().lower()))

        affected = advisory.get("affected")
        if isinstance(affected, list):
            for item in affected:
                if not isinstance(item, dict):
                    continue
                package = item.get("package")
                if not isinstance(package, dict):
                    continue
                eco = str(package.get("ecosystem") or "").strip().lower()
                name = package.get("name")
                if isinstance(name, str) and name.strip():
                    out.append((eco, name.strip().lower()))
                purl = package.get("purl")
                if isinstance(purl, str) and purl.strip():
                    p_eco, p_name = parse_purl(purl)
                    if p_name:
                        out.append((p_eco or eco, p_name))
        return list(dict.fromkeys(out))

    @staticmethod
    def _extract_cvss(advisory: Dict[str, Any]) -> Tuple[Optional[float], Optional[str], Optional[str]]:
        best_rank = (99, 1)
        best: Tuple[Optional[float], Optional[str], Optional[str]] = (None, None, None)

        def _consider(vector: Any, score_raw: Any) -> None:
            nonlocal best_rank, best
            vec = vector.strip() if isinstance(vector, str) and vector.strip() else None
            score: Optional[float] = None
            if score_raw is not None and not isinstance(score_raw, bool):
                try:
                    parsed_score = float(score_raw)
                    if math.isfinite(parsed_score) and 0.0 <= parsed_score <= 10.0:
                        score = parsed_score
                except (TypeError, ValueError):
                    score = None
            ver: Optional[str] = None
            if vec and is_valid_cvss_vector(vec):
                ver = detect_cvss_exact_version(vec)
                computed = compute_cvss_base_score(vec)
                if computed is not None:
                    score = computed
            elif vec is not None:
                vec = None
            if vec is None and score is None:
                return
            rank = (_CVSS_VERSION_RANK.get(ver or "", 50), 0 if vec else 1)
            if rank < best_rank:
                best_rank = rank
                best = (score, vec, ver)

        sev = advisory.get("severity")
        if isinstance(sev, list):
            for entry in sev:
                if isinstance(entry, dict):
                    _consider(entry.get("score"), None)
        _consider(advisory.get("cvss_vector"), advisory.get("cvss_score"))
        db_spec = advisory.get("database_specific")
        if isinstance(db_spec, dict) and isinstance(db_spec.get("cvss"), dict):
            c = db_spec["cvss"]
            _consider(c.get("vectorString") or c.get("vector_string"), c.get("score") or c.get("baseScore"))
        return best

    @staticmethod
    def _extract_references(advisory: Dict[str, Any], osv_id: str) -> List[str]:
        refs: List[str] = []
        if osv_id and not osv_id.startswith("OSV-"):
            refs.append(f"https://osv.dev/vulnerability/{osv_id}")
        elif osv_id:
            refs.append(f"https://osv.dev/vulnerability/{osv_id}")
        for ref in advisory.get("references", []) or []:
            if isinstance(ref, str) and ref.strip():
                refs.append(ref.strip())
            elif isinstance(ref, dict):
                url = ref.get("url")
                if isinstance(url, str) and url.strip():
                    refs.append(url.strip())
        return list(dict.fromkeys(refs))

    def _index_advisory(self, advisory: Dict[str, Any]) -> None:
        osv_id, cves, ghsas = self._extract_identifiers(advisory)
        score, vec, ver = self._extract_cvss(advisory)
        enriched = dict(advisory)
        enriched.setdefault("id", osv_id)
        if score is not None:
            enriched.setdefault("cvss_score", score)
        if vec is not None:
            enriched.setdefault("cvss_vector", vec)
        if ver is not None:
            enriched.setdefault("cvss_version", ver)
        enriched["cvss_provenance"] = "OSV"

        for cve in cves:
            self.osv_by_cve.setdefault(cve, []).append(enriched)
        for ghsa in ghsas:
            self.osv_by_ghsa.setdefault(ghsa, []).append(enriched)
        for eco, pkg_name in self._extract_packages(advisory):
            self.osv_by_package.setdefault(pkg_name, []).append(enriched)
            if eco:
                self.osv_by_ecosystem_package.setdefault((eco, pkg_name), []).append(enriched)

    # ------------------------------------------------------------------
    # ZIP Safety Validation (path traversal, symlinks, zip-bomb)
    # ------------------------------------------------------------------

    def _validate_zip_member(self, info: zipfile.ZipInfo) -> None:
        name = info.filename
        if "\x00" in name:
            raise OSVSecurityError(f"Zip entry contains NUL byte: {name!r}")
        if name.startswith("/") or name.startswith("\\") or "\\" in name:
            raise OSVSecurityError(f"Zip entry uses unsafe absolute or backslash path: {name}")
        if ":" in name:
            raise OSVSecurityError(f"Zip entry contains drive/colon prefix: {name}")
        posix_parts = PurePosixPath(name).parts
        if ".." in posix_parts:
            raise OSVSecurityError(f"Zip entry contains path traversal '..': {name}")
        # Check POSIX symlink mode in upper 16 bits of external_attr
        unix_mode = (info.external_attr >> 16) & 0o170000
        if unix_mode == stat.S_IFLNK:
            raise OSVSecurityError(f"Zip entry is a forbidden symlink: {name}")
        if info.file_size > self.max_zip_entry_bytes:
            raise OSVSecurityError(
                f"Zip entry {name} declared size {info.file_size} exceeds limit {self.max_zip_entry_bytes}"
            )
        if info.compress_size > 0 and info.file_size > 10 * 1024 * 1024:
            ratio = info.file_size / float(info.compress_size)
            if ratio > self.max_zip_ratio:
                raise OSVSecurityError(
                    f"Zip entry {name} compression ratio {ratio:.1f} exceeds safety limit {self.max_zip_ratio}"
                )

    def _iter_zip_advisories(self, zip_path: Path) -> Iterable[Dict[str, Any]]:
        validated_path = self.ctx.pfh.ensure_readable_file(zip_path, label="OSV ZIP Bundle")
        with self.ctx.pfh.open_for_read(validated_path, mode="rb", label="OSV ZIP Bundle") as fh:
            with zipfile.ZipFile(fh, mode="r") as zf:
                infos = zf.infolist()
                if len(infos) > self.max_zip_entries:
                    raise OSVSecurityError(
                        f"OSV zip entry count {len(infos)} exceeds limit {self.max_zip_entries}"
                    )

                total_read = 0
                for info in infos:
                    self._validate_zip_member(info)
                    if info.is_dir() or not info.filename.lower().endswith(".json"):
                        continue

                    entry_chunks: List[bytes] = []
                    entry_bytes = 0
                    with zf.open(info, mode="r") as member:
                        while True:
                            chunk = member.read(256 * 1024)
                            if not chunk:
                                break
                            entry_bytes += len(chunk)
                            total_read += len(chunk)
                            if entry_bytes > self.max_zip_entry_bytes:
                                raise OSVSecurityError(
                                    f"OSV zip entry {info.filename} exceeds max entry size {self.max_zip_entry_bytes}"
                                )
                            if total_read > self.max_zip_total_bytes:
                                raise OSVSecurityError(
                                    f"OSV zip bundle total decompressed size exceeds limit {self.max_zip_total_bytes}"
                                )
                            entry_chunks.append(chunk)

                    try:
                        payload = json.loads(b"".join(entry_chunks).decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue

                    if isinstance(payload, dict):
                        if isinstance(payload.get("vulns"), list):
                            for item in payload["vulns"]:
                                if isinstance(item, dict):
                                    yield item
                        else:
                            yield payload
                    elif isinstance(payload, list):
                        for item in payload:
                            if isinstance(item, dict):
                                yield item

    def _iter_json_advisories(self, json_path: Path) -> Iterable[Dict[str, Any]]:
        validated_path = self.ctx.pfh.ensure_readable_file(json_path, label="OSV JSON Advisory")
        with self.ctx.pfh.open_for_read(validated_path, mode="r", encoding="utf-8", label="OSV JSON Advisory") as fh:
            payload = json.load(fh)
        if isinstance(payload, dict):
            if isinstance(payload.get("vulns"), list):
                for item in payload["vulns"]:
                    if isinstance(item, dict):
                        yield item
            else:
                yield payload
        elif isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict):
                    yield item

    # ------------------------------------------------------------------
    # SQLite Batch Persistence & Chunked Warm Queries
    # ------------------------------------------------------------------

    def _sqlite_upsert_advisories(self, advisories: List[Dict[str, Any]]) -> None:
        if not self._sqlite_enabled or not self._sqlite_path or not advisories:
            return
        if not self._sqlite_verify_signature():
            self._sqlite_quarantine_and_reset()

        now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        adv_rows: List[Tuple[Any, ...]] = []
        cve_rows: List[Tuple[str, str, str]] = []
        ghsa_rows: List[Tuple[str, str, str]] = []
        pkg_rows: List[Tuple[Any, ...]] = []

        for adv in advisories:
            osv_id, cves, ghsas = self._extract_identifiers(adv)
            score, vec, ver = self._extract_cvss(adv)
            summary = adv.get("summary")
            if summary is not None and not isinstance(summary, str):
                summary = str(summary)
            aliases = list(dict.fromkeys([*cves, *ghsas]))
            refs = self._extract_references(adv, osv_id)
            adv_json = json.dumps(adv, separators=(",", ":"))
            adv_rows.append(
                (
                    osv_id,
                    summary,
                    score,
                    vec,
                    ver,
                    json.dumps(aliases),
                    json.dumps(refs),
                    adv_json,
                    now_utc,
                )
            )
            for cve in cves:
                cve_rows.append((cve, osv_id, now_utc))
            for ghsa in ghsas:
                ghsa_rows.append((ghsa, osv_id, now_utc))
            first_cve = cves[0] if cves else None
            for eco, pkg_name in self._extract_packages(adv):
                pkg_rows.append((eco, pkg_name, osv_id, first_cve, score, vec, ver, summary, now_utc))

        try:
            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    if adv_rows:
                        conn.executemany(
                            """
                            INSERT INTO osv_advisories (
                                osv_id, summary, cvss_score, cvss_vector, cvss_version,
                                aliases_json, references_json, advisory_json, updated_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ON CONFLICT(osv_id) DO UPDATE SET
                                summary=excluded.summary,
                                cvss_score=excluded.cvss_score,
                                cvss_vector=excluded.cvss_vector,
                                cvss_version=excluded.cvss_version,
                                aliases_json=excluded.aliases_json,
                                references_json=excluded.references_json,
                                advisory_json=excluded.advisory_json,
                                updated_at=excluded.updated_at
                            """,
                            adv_rows,
                        )
                    if cve_rows:
                        conn.executemany(
                            """
                            INSERT INTO osv_cve_index (cve_id, osv_id, updated_at)
                            VALUES (?, ?, ?)
                            ON CONFLICT(cve_id, osv_id) DO UPDATE SET updated_at=excluded.updated_at
                            """,
                            cve_rows,
                        )
                    if ghsa_rows:
                        conn.executemany(
                            """
                            INSERT INTO osv_ghsa_index (ghsa_id, osv_id, updated_at)
                            VALUES (?, ?, ?)
                            ON CONFLICT(ghsa_id, osv_id) DO UPDATE SET updated_at=excluded.updated_at
                            """,
                            ghsa_rows,
                        )
                    if pkg_rows:
                        conn.executemany(
                            """
                            INSERT INTO osv_package_index (
                                ecosystem, package_name, osv_id, cve_id,
                                cvss_score, cvss_vector, cvss_version, summary, updated_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ON CONFLICT(ecosystem, package_name, osv_id) DO UPDATE SET
                                cve_id=excluded.cve_id,
                                cvss_score=excluded.cvss_score,
                                cvss_vector=excluded.cvss_vector,
                                cvss_version=excluded.cvss_version,
                                summary=excluded.summary,
                                updated_at=excluded.updated_at
                            """,
                            pkg_rows,
                        )
            self._sqlite_prune()
            self._sqlite_write_signature()
        except (OSError, sqlite3.DatabaseError) as exc:
            if getattr(self.ctx, "logger", None) is not None:
                self.ctx.logger.warning(f"OSV SQLite upsert failed: {exc}")

    def _sqlite_has_rows(self) -> bool:
        if not self._sqlite_enabled or not self._sqlite_path:
            return False
        if not self._sqlite_verify_signature():
            self._sqlite_quarantine_and_reset()
            return False
        try:
            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    cnt = conn.execute("SELECT COUNT(*) FROM osv_advisories").fetchone()[0]
            return cnt > 0
        except (OSError, sqlite3.DatabaseError):
            return False

    def _sqlite_clear(self) -> None:
        if not self._sqlite_enabled or not self._sqlite_path:
            return
        try:
            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    for tbl in ("osv_advisories", "osv_cve_index", "osv_ghsa_index", "osv_package_index", "osv_sources"):
                        conn.execute(f"DELETE FROM {tbl}")
            self._sqlite_write_signature()
        except (OSError, sqlite3.DatabaseError):
            pass

    def _sqlite_has_source(self, source_key: str) -> bool:
        if not self._sqlite_enabled or not self._sqlite_path:
            return False
        if not self._sqlite_verify_signature():
            self._sqlite_quarantine_and_reset()
            return False
        try:
            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    row = conn.execute("SELECT 1 FROM osv_sources WHERE source_key = ?", (source_key,)).fetchone()
            return row is not None
        except (OSError, sqlite3.DatabaseError):
            return False

    def _sqlite_record_source(self, source_key: str) -> None:
        if not self._sqlite_enabled or not self._sqlite_path:
            return
        now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        try:
            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    conn.execute(
                        "INSERT OR REPLACE INTO osv_sources (source_key, updated_at) VALUES (?, ?)",
                        (source_key, now_utc),
                    )
            self._sqlite_write_signature()
        except (OSError, sqlite3.DatabaseError):
            pass

    def _sqlite_hydrate_targets(
        self,
        *,
        target_cves: Optional[Set[str]] = None,
        target_ghsa_ids: Optional[Set[str]] = None,
        target_purls: Optional[Set[str]] = None,
        target_packages: Optional[Set[str]] = None,
    ) -> None:
        if not self._sqlite_enabled or not self._sqlite_path:
            return
        if not self._sqlite_verify_signature():
            self._sqlite_quarantine_and_reset()
            return

        valid_cves = sorted({c.strip().upper() for c in (target_cves or set()) if self._is_valid_cve_id(c)})
        valid_ghsas = sorted({g.strip().upper() for g in (target_ghsa_ids or set()) if isinstance(g, str) and g.strip().upper().startswith("GHSA-")})
        pkg_names: Set[str] = {p.strip().lower() for p in (target_packages or set()) if isinstance(p, str) and p.strip()}
        eco_pkg_pairs: Set[Tuple[str, str]] = set()
        for purl in target_purls or set():
            eco, name = parse_purl(purl)
            if name:
                pkg_names.add(name)
                if eco:
                    eco_pkg_pairs.add((eco, name))

        try:
            def _hydrate_advisory(
                adv_json: str,
                db_score: Any,
                db_vector: Any,
                db_version: Any,
            ) -> Optional[Dict[str, Any]]:
                try:
                    adv = json.loads(adv_json)
                except json.JSONDecodeError:
                    return None
                if not isinstance(adv, dict):
                    return None
                score, vec, ver = db_score, db_vector, db_version
                if score is None or vec is None or ver is None:
                    ext_score, ext_vec, ext_ver = self._extract_cvss(adv)
                    score = score if score is not None else ext_score
                    vec = vec if vec is not None else ext_vec
                    ver = ver if ver is not None else ext_ver
                if score is not None and not isinstance(score, bool):
                    try:
                        parsed_s = float(score)
                        if math.isfinite(parsed_s) and 0.0 <= parsed_s <= 10.0:
                            adv.setdefault("cvss_score", parsed_s)
                    except (TypeError, ValueError):
                        pass
                if vec is not None:
                    adv.setdefault("cvss_vector", str(vec))
                if ver is not None:
                    adv.setdefault("cvss_version", str(ver))
                adv["cvss_provenance"] = "OSV"
                return adv

            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    for i in range(0, len(valid_cves), _SQLITE_CHUNK_SIZE):
                        chunk = valid_cves[i:i + _SQLITE_CHUNK_SIZE]
                        placeholders = ",".join("?" for _ in chunk)
                        rows = conn.execute(
                            f"""
                            SELECT c.cve_id, a.advisory_json, a.cvss_score, a.cvss_vector, a.cvss_version
                            FROM osv_cve_index c
                            JOIN osv_advisories a ON c.osv_id = a.osv_id
                            WHERE c.cve_id IN ({placeholders})
                            """,
                            tuple(chunk),
                        ).fetchall()
                        for cve_id, adv_json, db_score, db_vector, db_version in rows:
                            adv = _hydrate_advisory(adv_json, db_score, db_vector, db_version)
                            if adv is not None:
                                self.osv_by_cve.setdefault(cve_id, []).append(adv)

                    for i in range(0, len(valid_ghsas), _SQLITE_CHUNK_SIZE):
                        chunk = valid_ghsas[i:i + _SQLITE_CHUNK_SIZE]
                        placeholders = ",".join("?" for _ in chunk)
                        rows = conn.execute(
                            f"""
                            SELECT g.ghsa_id, a.advisory_json, a.cvss_score, a.cvss_vector, a.cvss_version
                            FROM osv_ghsa_index g
                            JOIN osv_advisories a ON g.osv_id = a.osv_id
                            WHERE g.ghsa_id IN ({placeholders})
                            """,
                            tuple(chunk),
                        ).fetchall()
                        for ghsa_id, adv_json, db_score, db_vector, db_version in rows:
                            adv = _hydrate_advisory(adv_json, db_score, db_vector, db_version)
                            if adv is not None:
                                self.osv_by_ghsa.setdefault(ghsa_id, []).append(adv)

                    pkg_batch = sorted(pkg_names)
                    target_pkg_names_lower = {p.strip().lower() for p in (target_packages or set()) if isinstance(p, str) and p.strip()}
                    for i in range(0, len(pkg_batch), _SQLITE_CHUNK_SIZE):
                        chunk = pkg_batch[i:i + _SQLITE_CHUNK_SIZE]
                        placeholders = ",".join("?" for _ in chunk)
                        rows = conn.execute(
                            f"""
                            SELECT p.ecosystem, p.package_name, a.advisory_json, a.cvss_score, a.cvss_vector, a.cvss_version
                            FROM osv_package_index p
                            JOIN osv_advisories a ON p.osv_id = a.osv_id
                            WHERE LOWER(p.package_name) IN ({placeholders})
                            """,
                            tuple(chunk),
                        ).fetchall()
                        for eco, pkg_name, adv_json, db_score, db_vector, db_version in rows:
                            eco_norm = str(eco or "").strip().lower()
                            pkg_norm = str(pkg_name or "").strip().lower()
                            if eco_pkg_pairs and eco_norm and (eco_norm, pkg_norm) not in eco_pkg_pairs and pkg_norm not in target_pkg_names_lower:
                                continue
                            adv = _hydrate_advisory(adv_json, db_score, db_vector, db_version)
                            if adv is None:
                                continue
                            self.osv_by_package.setdefault(pkg_norm, []).append(adv)
                            if eco_norm:
                                self.osv_by_ecosystem_package.setdefault((eco_norm, pkg_norm), []).append(adv)
        except (OSError, sqlite3.DatabaseError) as exc:
            if getattr(self.ctx, "logger", None) is not None:
                self.ctx.logger.warning(f"OSV SQLite hydrate failed: {exc}")

    # ------------------------------------------------------------------
    # Public Load & Lookup APIs
    # ------------------------------------------------------------------

    def load_offline(
        self,
        *,
        db_path: Optional[str] = None,
        target_cves: Optional[Set[str]] = None,
        target_ghsa_ids: Optional[Set[str]] = None,
        target_purls: Optional[Set[str]] = None,
        target_packages: Optional[Set[str]] = None,
        force_reindex: bool = False,
    ) -> bool:
        """
        Load OSV advisories from a local JSON file, ecosystem directory, or .zip bundle.
        Raises OSVSecurityError (ValueError) immediately on zip traversal / zip-bomb hazards.
        """
        if not db_path:
            return False

        source_path = Path(db_path)
        has_targets = bool(target_cves or target_ghsa_ids or target_purls or target_packages)

        if source_path.is_dir():
            source_dir = self.ctx.pfh.ensure_readable_dir(source_path, label="OSV Advisory Directory")
            sqlite_had_rows = self._sqlite_has_rows()
            if force_reindex and self._sqlite_enabled:
                self._sqlite_clear()
                sqlite_had_rows = False

            if self._sqlite_enabled and (not force_reindex) and sqlite_had_rows and has_targets:
                self._sqlite_hydrate_targets(
                    target_cves=target_cves,
                    target_ghsa_ids=target_ghsa_ids,
                    target_purls=target_purls,
                    target_packages=target_packages,
                )
                self._is_loaded = True
                return True

            batch: List[Dict[str, Any]] = []
            loaded_count = 0
            for zp in sorted(source_dir.rglob("*.zip")):
                for adv in self._iter_zip_advisories(zp):
                    self._index_advisory(adv)
                    batch.append(adv)
                    loaded_count += 1
                    if len(batch) >= 2000:
                        self._sqlite_upsert_advisories(batch)
                        batch.clear()
            for jp in sorted(source_dir.rglob("*.json")):
                try:
                    for adv in self._iter_json_advisories(jp):
                        self._index_advisory(adv)
                        batch.append(adv)
                        loaded_count += 1
                        if len(batch) >= 2000:
                            self._sqlite_upsert_advisories(batch)
                            batch.clear()
                except (OSError, json.JSONDecodeError):
                    continue
            if batch:
                self._sqlite_upsert_advisories(batch)

            if has_targets and self._sqlite_enabled:
                self.osv_by_cve = {}
                self.osv_by_ghsa = {}
                self.osv_by_package = {}
                self.osv_by_ecosystem_package = {}
                self._sqlite_hydrate_targets(
                    target_cves=target_cves,
                    target_ghsa_ids=target_ghsa_ids,
                    target_purls=target_purls,
                    target_packages=target_packages,
                )

            if loaded_count <= 0 and not self.osv_by_cve and not self.osv_by_package:
                return False
            self._is_loaded = True
            return True

        if source_path.is_file():
            batch = []
            loaded_count = 0
            if source_path.suffix.lower() == ".zip":
                st = source_path.stat()
                source_key = f"{source_path.resolve()}:{st.st_mtime_ns}:{st.st_size}"
                if force_reindex and self._sqlite_enabled:
                    self._sqlite_clear()
                if self._sqlite_enabled and (not force_reindex) and has_targets and self._sqlite_has_source(source_key):
                    self._sqlite_hydrate_targets(
                        target_cves=target_cves,
                        target_ghsa_ids=target_ghsa_ids,
                        target_purls=target_purls,
                        target_packages=target_packages,
                    )
                    self._is_loaded = True
                    return True
                for adv in self._iter_zip_advisories(source_path):
                    self._index_advisory(adv)
                    batch.append(adv)
                    loaded_count += 1
                    if len(batch) >= 2000:
                        self._sqlite_upsert_advisories(batch)
                        batch.clear()
                if batch:
                    self._sqlite_upsert_advisories(batch)
                    batch = []
                if loaded_count > 0:
                    self._sqlite_record_source(source_key)
            else:
                try:
                    for adv in self._iter_json_advisories(source_path):
                        self._index_advisory(adv)
                        batch.append(adv)
                        loaded_count += 1
                except (OSError, json.JSONDecodeError):
                    return False
                if batch:
                    self._sqlite_upsert_advisories(batch)

            if has_targets and self._sqlite_enabled:
                self.osv_by_cve = {}
                self.osv_by_ghsa = {}
                self.osv_by_package = {}
                self.osv_by_ecosystem_package = {}
                self._sqlite_hydrate_targets(
                    target_cves=target_cves,
                    target_ghsa_ids=target_ghsa_ids,
                    target_purls=target_purls,
                    target_packages=target_packages,
                )

            if loaded_count <= 0 and not self.osv_by_cve and not self.osv_by_package:
                return False
            self._is_loaded = True
            return True

        return False

    def lookup_by_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        norm = str(cve_id or "").strip().upper()
        if not self._is_valid_cve_id(norm):
            return []
        if norm not in self.osv_by_cve and self._sqlite_enabled:
            self._sqlite_hydrate_targets(target_cves={norm})
        return list(self.osv_by_cve.get(norm, []))

    def lookup_by_ghsa(self, ghsa_id: str) -> List[Dict[str, Any]]:
        norm = str(ghsa_id or "").strip().upper()
        if not norm.startswith("GHSA-"):
            return []
        if norm not in self.osv_by_ghsa and self._sqlite_enabled:
            self._sqlite_hydrate_targets(target_ghsa_ids={norm})
        return list(self.osv_by_ghsa.get(norm, []))

    def lookup_by_purl(self, purl: str) -> List[Dict[str, Any]]:
        eco, pkg_name = parse_purl(purl)
        if not pkg_name:
            return []
        if eco and (eco, pkg_name) in self.osv_by_ecosystem_package:
            return list(self.osv_by_ecosystem_package[(eco, pkg_name)])
        if self._sqlite_enabled:
            self._sqlite_hydrate_targets(target_purls={purl})
            if eco and (eco, pkg_name) in self.osv_by_ecosystem_package:
                return list(self.osv_by_ecosystem_package[(eco, pkg_name)])
        return list(self.osv_by_package.get(pkg_name, []))

    def lookup_by_package(
        self,
        *,
        ecosystem: Optional[str] = None,
        package_name: Optional[str] = None,
        purl: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        if purl:
            return self.lookup_by_purl(purl)
        pkg_norm = str(package_name or "").strip().lower()
        if not pkg_norm:
            return []
        eco_norm = str(ecosystem or "").strip().lower()
        if eco_norm:
            if (eco_norm, pkg_norm) not in self.osv_by_ecosystem_package and self._sqlite_enabled:
                self._sqlite_hydrate_targets(target_packages={pkg_norm})
            if (eco_norm, pkg_norm) in self.osv_by_ecosystem_package:
                return list(self.osv_by_ecosystem_package[(eco_norm, pkg_norm)])
        if pkg_norm not in self.osv_by_package and self._sqlite_enabled:
            self._sqlite_hydrate_targets(target_packages={pkg_norm})
        return list(self.osv_by_package.get(pkg_norm, []))

    def enrich_finding(
        self,
        finding: Any,
        *,
        by_cve: bool = True,
        by_ghsa: bool = True,
        by_package: bool = True,
    ) -> Optional[Dict[str, Any]]:
        if not self._is_loaded and not self._sqlite_has_rows():
            return None

        advisories: List[Dict[str, Any]] = []
        match_type: Optional[str] = None

        if by_cve and getattr(finding, "cves", None):
            for cve in finding.cves:
                hits = self.lookup_by_cve(cve)
                if hits:
                    advisories.extend(hits)
                    match_type = "cve"
                    break

        if not advisories and by_ghsa and getattr(finding, "ghsa_ids", None):
            for gid in finding.ghsa_ids:
                hits = self.lookup_by_ghsa(gid)
                if hits:
                    advisories.extend(hits)
                    match_type = "ghsa"
                    break

        if not advisories and by_package:
            purl = getattr(finding, "package_purl", None)
            if isinstance(purl, str) and purl.strip():
                hits = self.lookup_by_purl(purl)
                if hits:
                    advisories.extend(hits)
                    match_type = "purl"

            if not advisories:
                fields = [
                    getattr(finding, "title", "") or "",
                    getattr(finding, "description", "") or "",
                    getattr(finding, "solution", "") or "",
                    getattr(finding, "plugin_output", "") or "",
                ]
                tokens = {t.lower() for t in _PKG_TOKEN_RE.findall("\n".join(str(x) for x in fields if x))}
                for tok in sorted(tokens):
                    hits = self.lookup_by_package(package_name=tok)
                    if hits:
                        advisories.extend(hits)
                        match_type = "package"
                        break

        if not advisories:
            return None

        advisory_ids: List[str] = []
        refs: List[str] = []
        best_score: Optional[float] = None
        best_vector: Optional[str] = None
        best_version: Optional[str] = None
        best_rank = (99, 1)

        for adv in advisories:
            oid, _, _ = self._extract_identifiers(adv)
            advisory_ids.append(oid)
            refs.extend(self._extract_references(adv, oid))
            sc, vec, ver = self._extract_cvss(adv)
            if vec or sc is not None:
                rank = (_CVSS_VERSION_RANK.get(ver or "", 50), 0 if vec else 1)
                if rank < best_rank:
                    best_rank = rank
                    best_score, best_vector, best_version = sc, vec, ver

        return {
            "source": "osv",
            "match_type": match_type,
            "advisories": advisories,
            "advisory_ids": list(dict.fromkeys(advisory_ids)),
            "advisory_count": len(advisories),
            "references": list(dict.fromkeys(refs)),
            "cvss_score": best_score,
            "cvss_vector": best_vector,
            "cvss_version": best_version,
            "cvss_provenance": "OSV" if (best_vector or best_score is not None) else "Missing",
        }

    def enrich_scan(self, scan: ScanResult) -> Dict[str, Dict[str, Any]]:
        enrichments: Dict[str, Dict[str, Any]] = {}
        for asset in scan.assets:
            for finding in asset.findings:
                hit = self.enrich_finding(finding)
                if hit:
                    enrichments[finding.finding_id] = hit
        return enrichments
