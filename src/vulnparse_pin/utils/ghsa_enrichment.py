# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

"""
GitHub Security Advisory (GHSA) hybrid enrichment source.

Provides enrichment via GHSA vulnerability advisory data.
Supports both online (GitHub REST API) and offline (local database) modes.
"""

from typing import Dict, Optional, List, Any, Set, Tuple
from pathlib import Path
from datetime import datetime, timezone, timedelta
from urllib.parse import unquote
import concurrent.futures
import contextlib
import math
import os
import re
import requests
import json
import sqlite3
import hashlib
import hmac
import stat
import threading

from vulnparse_pin.core.classes.dataclass import RunContext, ScanResult
from vulnparse_pin.utils.cvss_utils import compute_cvss_base_score, detect_cvss_exact_version, is_valid_cvss_vector
from vulnparse_pin.utils.logger import colorize
from vulnparse_pin import UA

_SQLITE_CHUNK_SIZE = 900
_PURL_ECOSYSTEM_ALIASES: Dict[str, str] = {
    "pypi": "pypi",
    "npm": "npm",
    "golang": "go",
    "go": "go",
    "maven": "maven",
    "nuget": "nuget",
    "gem": "rubygems",
    "rubygems": "rubygems",
    "cargo": "crates.io",
    "crates.io": "crates.io",
    "composer": "packagist",
    "packagist": "packagist",
    "pub": "pub",
    "hex": "hex",
    "swift": "swift",
    "apk": "alpine",
    "deb": "debian",
    "rpm": "redhat",
    "github": "github actions",
}


def parse_purl(purl: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Parse a Package URL (PURL) into normalized (ecosystem, package_name).
    Example: 'pkg:pypi/requests@2.31.0' -> ('pypi', 'requests')
             'pkg:npm/%40babel/core@7.24.0' -> ('npm', '@babel/core')
             'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1' -> ('maven', 'org.apache.logging.log4j:log4j-core')
    """
    if not isinstance(purl, str):
        return None, None
    raw = purl.strip()
    if not raw.lower().startswith("pkg:"):
        return None, None
    body = raw[4:].lstrip("/")
    body = body.split("#", 1)[0].split("?", 1)[0]
    if "/" not in body:
        return None, None
    eco_raw, rest = body.split("/", 1)
    eco = _PURL_ECOSYSTEM_ALIASES.get(eco_raw.strip().lower(), eco_raw.strip().lower())
    if not eco or not rest:
        return None, None
    # Strip version suffix '@...' from the final segment (after namespace if any)
    if "@" in rest:
        idx = rest.rfind("@")
        # Be careful with scoped npm packages like '@scope/pkg@1.0.0' or '@scope/pkg'
        slash_idx = rest.rfind("/")
        if idx > slash_idx:
            rest = rest[:idx]
    decoded = unquote(rest).strip("/")
    if not decoded:
        return eco, None
    if eco == "maven" and "/" in decoded:
        ns, name = decoded.split("/", 1)
        decoded = f"{ns}:{name}"
    return eco, decoded.lower()

_GHSA_ID_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz-")
_CVE_PREFIX = "CVE-"
_PKG_TOKEN_RE = re.compile(r"[a-zA-Z0-9_.+-]{3,}")
_ENV_VAR_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_HEADER_UNSAFE_RE = re.compile(r"[\r\n]")
_GITHUB_TOKEN_RE = re.compile(
    r"^(?:"
    r"gh[pousr]_[A-Za-z0-9_]{20,255}"
    r"|"
    r"github_pat_[A-Za-z0-9_]{20,255}"
    r")$"
)


class GHSAEnrichmentSource:
    """
    GHSA (GitHub Security Advisory) enrichment source for hybrid CVE/package vulnerability data.
    
    GitHub publishes structured security advisory data that includes:
    - CVE identifiers (where applicable)
    - Package names and affected versions
    - Severity ratings
    - References and remediation guidance
    
    This source can operate in two modes:
    1. Online: Query GitHub's REST API (https://api.github.com/advisories/GHSA_ID)
    2. Offline: Load from pre-downloaded GHSA database JSON files

    """
    
    GHSA_API_BASE = "https://api.github.com/advisories"
    GHSA_HEADERS = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
    }
    
    def __init__(self, ctx: RunContext, token_env_name: Optional[str] = None):
        self.ctx = ctx
        self._token_log_emitted = False
        self._token_warning_emitted: Set[Tuple[str, str]] = set()
        self._token_rejection_count = 0
        self.token_env_name = self._sanitize_token_env_name(token_env_name)
        self.ghsa_by_cve: Dict[str, List[Dict[str, Any]]] = {}
        self.ghsa_by_package: Dict[str, List[Dict[str, Any]]] = {}
        self.ghsa_by_ecosystem_package: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        self._is_loaded = False
        self._advisory_cache: Dict[str, Dict[str, Any]] = {}
        self._cve_search_cache: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = threading.Lock()
        self._sqlite_enabled = False
        self._sqlite_path: Optional[str] = None
        self._sqlite_sig_path: Optional[str] = None
        self._sqlite_prune_stats: Dict[str, int] = {
            "runs": 0,
            "age_deleted": 0,
            "cap_deleted": 0,
            "last_row_count": 0,
        }
        self._init_sqlite_index()

    # ------------------------------------------------------------------
    # SQLite init
    # ------------------------------------------------------------------

    @staticmethod
    def _ensure_ghsa_schema(conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ghsa_cve_index (
                cve_id    TEXT NOT NULL,
                advisory_id TEXT NOT NULL,
                advisory_json TEXT NOT NULL,
                updated_at TEXT,
                PRIMARY KEY (cve_id, advisory_id)
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ghsa_cve_id ON ghsa_cve_index(cve_id)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ghsa_package_index (
                ecosystem TEXT NOT NULL,
                package_name TEXT NOT NULL,
                advisory_id TEXT NOT NULL,
                cve_id TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                severity TEXT,
                summary TEXT,
                advisory_json TEXT,
                updated_at TEXT,
                PRIMARY KEY (ecosystem, package_name, advisory_id)
            )
            """
        )
        existing_pkg_cols = {
            row[1]
            for row in conn.execute("PRAGMA table_info(ghsa_package_index)").fetchall()
            if len(row) > 1
        }
        for col_name, col_type in (("advisory_json", "TEXT"), ("updated_at", "TEXT")):
            if col_name not in existing_pkg_cols:
                conn.execute(f"ALTER TABLE ghsa_package_index ADD COLUMN {col_name} {col_type}")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ghsa_pkg_name ON ghsa_package_index(package_name)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ghsa_pkg_eco_name ON ghsa_package_index(ecosystem, package_name)"
        )

    def _init_sqlite_index(self) -> None:
        """Initialize optional GHSA SQLite index for warm-run CVE & package/PURL lookups."""
        try:
            paths = getattr(self.ctx, "paths", None)
            cache_dir = getattr(paths, "cache_dir", None) if paths else None
            if not cache_dir or not isinstance(cache_dir, (str, os.PathLike)):
                return

            db_path = Path(cache_dir) / "ghsa_cache.sqlite3"
            sig_path = f"{db_path}.sig.json"
            db_existed = db_path.exists()

            if not db_existed:
                db_path = Path(
                    self.ctx.pfh.ensure_writable_file(
                        db_path,
                        label="GHSA SQLite Index",
                        create_parents=True,
                        overwrite=False,
                    )
                )
            else:
                self.ctx.pfh.ensure_readable_file(db_path, label="GHSA SQLite Index")
                if not os.access(db_path, os.W_OK):
                    raise PermissionError(
                        f"GHSA SQLite index is not writable: {self.ctx.pfh.format_for_log(db_path)}"
                    )

            self._sqlite_enabled = True
            self._sqlite_path = str(db_path)
            self._sqlite_sig_path = sig_path

            if db_existed:
                self._sqlite_harden_permissions()
                if not self._sqlite_verify_signature():
                    self.ctx.logger.warning(
                        "GHSA SQLite signature verification failed; quarantining and rebuilding index."
                    )
                    self._sqlite_quarantine_and_reset()
                else:
                    with contextlib.closing(sqlite3.connect(str(db_path))) as conn:
                        with conn:
                            self._ensure_ghsa_schema(conn)
                            conn.execute("PRAGMA integrity_check")
            else:
                with contextlib.closing(sqlite3.connect(str(db_path))) as conn:
                    with conn:
                        self._ensure_ghsa_schema(conn)
                        conn.execute("PRAGMA integrity_check")

            self._sqlite_harden_permissions()
            self._sqlite_prune()

            # Re-sign after all schema operations so the sig reflects the
            # post-init file state (schema-DDL no-ops can touch SQLite header bytes).
            self._sqlite_write_signature()

            self.ctx.logger.debug(
                f"GHSA SQLite index enabled at {self.ctx.pfh.format_for_log(db_path)}"
            )
        except PermissionError:
            raise
        except (OSError, sqlite3.DatabaseError, ValueError, TypeError, AttributeError) as e:
            self._sqlite_enabled = False
            self._sqlite_path = None
            self._sqlite_sig_path = None
            self.ctx.logger.warning(f"GHSA SQLite index disabled (init failed): {e}")

    # ------------------------------------------------------------------
    # SQLite integrity / hardening
    # ------------------------------------------------------------------

    def _sqlite_secret(self) -> Optional[bytes]:
        """Optional HMAC key from environment for signature strengthening."""
        raw = os.getenv("VP_SQLITE_HMAC_KEY")
        return raw.encode("utf-8") if raw else None

    def _warn_token_rejection_once(self, env_name: str, reason: str) -> None:
        key = (env_name, reason)
        if key in self._token_warning_emitted:
            return
        self._token_warning_emitted.add(key)
        self._token_rejection_count += 1
        self.ctx.logger.warning(
            f"GHSA token from env '{env_name}' rejected: {reason}"
        )

    @property
    def token_rejection_count(self) -> int:
        return int(self._token_rejection_count)

    def _sanitize_token_env_name(self, token_env_name: Optional[str]) -> Optional[str]:
        if token_env_name is None:
            return None
        name = str(token_env_name).strip()
        if not name:
            return None
        if not _ENV_VAR_NAME_RE.fullmatch(name):
            self.ctx.logger.warning(
                "Configured ghsa_token_env is invalid. Falling back to GITHUB_TOKEN. "
                "Expected shell env-var format [A-Za-z_][A-Za-z0-9_]{0,127}."
            )
            return None
        return name

    def _is_header_safe(self, value: str) -> bool:
        return bool(value) and _HEADER_UNSAFE_RE.search(value) is None

    def _is_valid_github_token_shape(self, token: str) -> bool:
        # Pin to known GitHub token prefixes to reduce accidental secret leakage
        # and reject malformed/unexpected credential strings.
        return _GITHUB_TOKEN_RE.fullmatch(token) is not None

    def _github_token_candidates(self) -> List[str]:
        candidates: List[str] = []
        if self.token_env_name:
            candidates.append(self.token_env_name)
        if "GITHUB_TOKEN" not in candidates:
            candidates.append("GITHUB_TOKEN")
        return candidates

    def _get_github_token(self) -> Optional[str]:
        for env_name in self._github_token_candidates():
            raw = os.getenv(env_name)
            if raw and raw.strip():
                token = raw.strip()
                if not self._is_header_safe(token):
                    self._warn_token_rejection_once(env_name, "unsafe control characters in token")
                    continue
                if not self._is_valid_github_token_shape(token):
                    self._warn_token_rejection_once(
                        env_name,
                        "token does not match known GitHub token format (ghp_/gho_/ghu_/ghs_/ghr_/github_pat_)",
                    )
                    continue
                if not self._token_log_emitted:
                    self.ctx.logger.debug(
                        f"GHSA API token detected in env '{env_name}'; using authenticated GitHub advisory requests."
                    )
                    self._token_log_emitted = True
                return token
        return None

    def _build_headers(self) -> Dict[str, str]:
        headers = dict(self.GHSA_HEADERS)
        headers["User-Agent"] = UA or "VulnParse-Pin/2.0"
        token = self._get_github_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _sqlite_cache_policy(self) -> Dict[str, int]:
        """Resolve GHSA SQLite retention policy from runtime config with safe defaults."""
        cfg = getattr(self.ctx, "config", {}) or {}
        enrichment = cfg.get("enrichment", {}) if isinstance(cfg, dict) else {}
        ghsa_cache = enrichment.get("ghsa_cache", {}) if isinstance(enrichment, dict) else {}

        def _as_int(value: Any, default: int) -> int:
            try:
                return int(value)
            except (TypeError, ValueError):
                return default

        return {
            "max_age_hours": max(_as_int(ghsa_cache.get("sqlite_max_age_hours"), 24 * 14), 0),
            "max_rows": max(_as_int(ghsa_cache.get("sqlite_max_rows"), 500000), 0),
        }

    def _sqlite_prune(self) -> None:
        """Prune stale and excess GHSA SQLite rows per retention policy."""
        if not self._sqlite_enabled or not self._sqlite_path:
            return

        policy = self._sqlite_cache_policy()
        max_age_hours = policy["max_age_hours"]
        max_rows = policy["max_rows"]

        try:
            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    before_changes = conn.total_changes
                    if max_age_hours > 0:
                        cutoff = (datetime.now(timezone.utc) - timedelta(hours=max_age_hours)).isoformat().replace("+00:00", "Z")
                        conn.execute("DELETE FROM ghsa_cve_index WHERE updated_at < ?", (cutoff,))
                        conn.execute("DELETE FROM ghsa_package_index WHERE updated_at < ?", (cutoff,))
                    after_age_changes = conn.total_changes
                    age_deleted = max(after_age_changes - before_changes, 0)

                    if max_rows > 0:
                        row_count = conn.execute("SELECT COUNT(*) FROM ghsa_cve_index").fetchone()[0]
                        if row_count > max_rows:
                            trim = row_count - max_rows
                            conn.execute(
                                """
                                DELETE FROM ghsa_cve_index
                                WHERE rowid IN (
                                    SELECT rowid FROM ghsa_cve_index
                                    ORDER BY COALESCE(updated_at, '') ASC
                                    LIMIT ?
                                )
                                """,
                                (trim,),
                            )
                        pkg_count = conn.execute("SELECT COUNT(*) FROM ghsa_package_index").fetchone()[0]
                        if pkg_count > max_rows:
                            pkg_trim = pkg_count - max_rows
                            conn.execute(
                                """
                                DELETE FROM ghsa_package_index
                                WHERE rowid IN (
                                    SELECT rowid FROM ghsa_package_index
                                    ORDER BY COALESCE(updated_at, '') ASC
                                    LIMIT ?
                                )
                                """,
                                (pkg_trim,),
                            )
                    after_cap_changes = conn.total_changes
                    cap_deleted = max(after_cap_changes - after_age_changes, 0)
                    final_row_count = conn.execute("SELECT COUNT(*) FROM ghsa_cve_index").fetchone()[0]

            self._sqlite_prune_stats["runs"] += 1
            self._sqlite_prune_stats["age_deleted"] += age_deleted
            self._sqlite_prune_stats["cap_deleted"] += cap_deleted
            self._sqlite_prune_stats["last_row_count"] = int(final_row_count)

            self.ctx.logger.debug(
                "GHSA SQLite prune stats: runs=%d age_deleted=%d cap_deleted=%d last_row_count=%d",
                self._sqlite_prune_stats["runs"],
                self._sqlite_prune_stats["age_deleted"],
                self._sqlite_prune_stats["cap_deleted"],
                self._sqlite_prune_stats["last_row_count"],
            )
        except (OSError, sqlite3.DatabaseError, ValueError, TypeError) as e:
            self.ctx.logger.warning(f"GHSA SQLite prune failed; continuing without prune: {e}")

    def _sqlite_harden_permissions(self) -> None:
        if not self._sqlite_path:
            return
        if os.name == "nt":
            # Windows: just verify PFH readability; ACLs handled by OS policy.
            self.ctx.pfh.ensure_readable_file(self._sqlite_path, label="GHSA SQLite Index")
            return
        try:
            os.chmod(self._sqlite_path, 0o600)
        except OSError:
            pass
        try:
            self.ctx.pfh.ensure_readable_file(self._sqlite_path, label="GHSA SQLite Index")
            st = os.stat(self._sqlite_path)
            if bool(st.st_mode & stat.S_IWOTH):
                raise PermissionError("GHSA SQLite index is world-writable; refusing to continue.")
        except OSError as exc:
            raise PermissionError(f"GHSA SQLite permission check failed: {exc}") from exc

    def _sqlite_compute_digest(self) -> Optional[str]:
        if not self._sqlite_path:
            return None
        digest = hashlib.sha256()
        with self.ctx.pfh.open_for_read(self._sqlite_path, mode="rb", label="GHSA SQLite Index", log=False) as f:
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
            label="GHSA SQLite Signature",
            create_parents=True,
            overwrite=True,
        )
        with self.ctx.pfh.open_for_write(sig_path, mode="w", encoding="utf-8", label="GHSA SQLite Signature") as f:
            json.dump(payload, f, indent=2)
        if os.name != "nt":
            try:
                os.chmod(sig_path, 0o600)
            except OSError:
                pass

    def _sqlite_verify_signature(self) -> bool:
        """Return False when signature is missing, downgraded, tampered, or corrupt."""
        if not self._sqlite_enabled or not self._sqlite_path:
            return False
        if not self._sqlite_sig_path or not os.path.exists(self._sqlite_sig_path):
            return False
        try:
            if os.name != "nt":
                st = os.stat(self._sqlite_sig_path)
                if bool(st.st_mode & stat.S_IWOTH):
                    return False
            with self.ctx.pfh.open_for_read(self._sqlite_sig_path, mode="r", encoding="utf-8", label="GHSA SQLite Signature", log=False) as f:
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

    def _sqlite_quarantine_and_reset(self) -> None:
        """Rename tampered files and rebuild a clean empty index."""
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
                self._ensure_ghsa_schema(conn)
        self._sqlite_harden_permissions()
        self._sqlite_write_signature()

    def _normalize_target_cves(self, target_cves: Optional[Set[str]]) -> Set[str]:
        if not target_cves:
            return set()
        return {
            c.strip().upper()
            for c in target_cves
            if isinstance(c, str) and self._is_valid_cve_id(c)
        }

    def _sqlite_has_rows(self) -> bool:
        if not self._sqlite_enabled or not self._sqlite_path:
            return False
        if not self._sqlite_verify_signature():
            self.ctx.logger.warning(
                "GHSA SQLite signature check failed during row-count; quarantining and rebuilding."
            )
            self._sqlite_quarantine_and_reset()
            return False
        try:
            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    cve_count = conn.execute("SELECT COUNT(*) FROM ghsa_cve_index").fetchone()[0]
                    pkg_count = conn.execute("SELECT COUNT(*) FROM ghsa_package_index").fetchone()[0]
            return (cve_count + pkg_count) > 0
        except (OSError, sqlite3.DatabaseError):
            return False

    def _sqlite_hydrate_targets(self, target_cves: Set[str]) -> Set[str]:
        """Hydrate in-memory CVE index from SQLite and return unresolved targets."""
        if not self._sqlite_enabled or not self._sqlite_path or not target_cves:
            return set(target_cves)

        if not self._sqlite_verify_signature():
            self.ctx.logger.warning(
                "GHSA SQLite signature check failed during hydrate; quarantining and rebuilding."
            )
            self._sqlite_quarantine_and_reset()
            return set(target_cves)

        unresolved = set(target_cves)
        # Only look up well-formed CVE IDs; user-supplied strings are not used in queries.
        valid_targets = {c for c in target_cves if self._is_valid_cve_id(c)}
        if not valid_targets:
            return unresolved

        try:
            all_rows: List[Tuple[str, str]] = []
            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    batch = list(valid_targets)
                    for i in range(0, len(batch), _SQLITE_CHUNK_SIZE):
                        chunk = batch[i:i + _SQLITE_CHUNK_SIZE]
                        placeholders = ",".join("?" for _ in chunk)
                        sql = f"SELECT cve_id, advisory_json FROM ghsa_cve_index WHERE cve_id IN ({placeholders})"
                        rows = conn.execute(sql, tuple(chunk)).fetchall()
                        all_rows.extend(rows)

            for cve_id, advisory_json in all_rows:
                try:
                    advisory = json.loads(advisory_json)
                except json.JSONDecodeError:
                    continue
                self.ghsa_by_cve.setdefault(cve_id, []).append(advisory)
                unresolved.discard(cve_id)

            if all_rows:
                self.ctx.logger.debug(
                    f"GHSA SQLite warm-hit: hydrated={len(all_rows)} unresolved={len(unresolved)}"
                )
        except Exception as e:
            self.ctx.logger.warning(f"GHSA SQLite hydrate failed; falling back to JSON source parse: {e}")

        return unresolved

    @staticmethod
    def _extract_advisory_cvss_fields(advisory: Dict[str, Any]) -> Tuple[Optional[float], Optional[str]]:
        vec: Optional[str] = None
        score: Optional[float] = None

        def _try_vec(raw_vec: Any, raw_score: Any = None) -> bool:
            nonlocal vec, score
            if isinstance(raw_vec, str) and is_valid_cvss_vector(raw_vec.strip()):
                vec = raw_vec.strip()
                computed = compute_cvss_base_score(vec)
                if computed is not None:
                    score = computed
                    return True
            if raw_score is not None and score is None and not isinstance(raw_score, bool):
                try:
                    parsed_score = float(raw_score)
                    if math.isfinite(parsed_score) and 0.0 <= parsed_score <= 10.0:
                        score = parsed_score
                except (TypeError, ValueError):
                    pass
            return False

        sev = advisory.get("severity")
        if isinstance(sev, list):
            for entry in sev:
                if isinstance(entry, dict) and _try_vec(entry.get("score")):
                    return score, vec
        cvss_sevs = advisory.get("cvss_severities")
        if isinstance(cvss_sevs, dict):
            for key in ("cvss_v4", "cvss_v3", "cvss_v2"):
                item = cvss_sevs.get(key)
                if isinstance(item, dict) and _try_vec(item.get("vector_string") or item.get("vectorString"), item.get("score")):
                    return score, vec
        cvss_obj = advisory.get("cvss")
        if isinstance(cvss_obj, dict) and _try_vec(
            cvss_obj.get("vector_string") or cvss_obj.get("vectorString"),
            cvss_obj.get("score") or cvss_obj.get("baseScore"),
        ):
            return score, vec
        _try_vec(advisory.get("cvss_vector"), advisory.get("cvss_score"))
        return score, vec

    @staticmethod
    def _extract_severity_label(advisory: Dict[str, Any]) -> Optional[str]:
        sev = advisory.get("severity")
        if isinstance(sev, str) and sev.strip():
            return sev.strip().upper()
        db_spec = advisory.get("database_specific")
        if isinstance(db_spec, dict) and isinstance(db_spec.get("severity"), str):
            return db_spec["severity"].strip().upper()
        return None

    @staticmethod
    def _extract_package_entries(advisory: Dict[str, Any]) -> List[Tuple[str, str]]:
        """Extract normalized (ecosystem, package_name) tuples from an advisory."""
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
                name = package.get("name")
                eco = str(package.get("ecosystem") or "").strip().lower()
                if isinstance(name, str) and name.strip():
                    out.append((eco, name.strip().lower()))
                purl = package.get("purl")
                if isinstance(purl, str) and purl.strip():
                    p_eco, p_name = parse_purl(purl)
                    if p_name:
                        out.append((p_eco or eco, p_name))
        return list(dict.fromkeys(out))

    @staticmethod
    def _advisory_id(advisory: Dict[str, Any]) -> str:
        aid = advisory.get("ghsa_id") or advisory.get("id")
        if isinstance(aid, str) and aid.strip():
            return aid.strip()
        canonical = json.dumps(advisory, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _sqlite_rows_for_advisory(self, advisory: Dict[str, Any]) -> List[Tuple[str, str, str, str]]:
        cves = self._extract_cves(advisory)
        if not cves:
            return []
        advisory_id = self._advisory_id(advisory)
        advisory_json = json.dumps(advisory, separators=(",", ":"))
        updated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        return [(cve, advisory_id, advisory_json, updated_at) for cve in cves]

    def _sqlite_package_rows_for_advisory(self, advisory: Dict[str, Any]) -> List[Tuple[Any, ...]]:
        pkg_entries = self._extract_package_entries(advisory)
        if not pkg_entries:
            return []
        advisory_id = self._advisory_id(advisory)
        cves = self._extract_cves(advisory)
        cve_id = cves[0] if cves else None
        cvss_score, cvss_vector = self._extract_advisory_cvss_fields(advisory)
        severity = self._extract_severity_label(advisory)
        summary = advisory.get("summary")
        if summary is not None and not isinstance(summary, str):
            summary = str(summary)
        advisory_json = json.dumps(advisory, separators=(",", ":"))
        updated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        return [
            (
                eco,
                pkg_name,
                advisory_id,
                cve_id,
                cvss_score,
                cvss_vector,
                severity,
                summary,
                advisory_json,
                updated_at,
            )
            for eco, pkg_name in pkg_entries
        ]

    def _sqlite_upsert_rows(
        self,
        rows: List[Tuple[str, str, str, str]],
        package_rows: Optional[List[Tuple[Any, ...]]] = None,
    ) -> None:
        if not self._sqlite_enabled or not self._sqlite_path or (not rows and not package_rows):
            return
        if not self._sqlite_verify_signature():
            self.ctx.logger.warning(
                "GHSA SQLite signature check failed during upsert; quarantining and rebuilding."
            )
            self._sqlite_quarantine_and_reset()
        try:
            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    if rows:
                        conn.executemany(
                            """
                            INSERT INTO ghsa_cve_index (cve_id, advisory_id, advisory_json, updated_at)
                            VALUES (?, ?, ?, ?)
                            ON CONFLICT(cve_id, advisory_id) DO UPDATE SET
                                advisory_json=excluded.advisory_json,
                                updated_at=excluded.updated_at
                            """,
                            rows,
                        )
                    if package_rows:
                        conn.executemany(
                            """
                            INSERT INTO ghsa_package_index (
                                ecosystem, package_name, advisory_id, cve_id,
                                cvss_score, cvss_vector, severity, summary,
                                advisory_json, updated_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ON CONFLICT(ecosystem, package_name, advisory_id) DO UPDATE SET
                                cve_id=excluded.cve_id,
                                cvss_score=excluded.cvss_score,
                                cvss_vector=excluded.cvss_vector,
                                severity=excluded.severity,
                                summary=excluded.summary,
                                advisory_json=excluded.advisory_json,
                                updated_at=excluded.updated_at
                            """,
                            package_rows,
                        )
            self._sqlite_prune()
            self._sqlite_write_signature()
        except (OSError, sqlite3.DatabaseError) as e:
            self.ctx.logger.warning(f"GHSA SQLite upsert failed; continuing with in-memory index only: {e}")

    def _sqlite_hydrate_packages(
        self,
        *,
        target_packages: Optional[Set[str]] = None,
        target_purls: Optional[Set[str]] = None,
    ) -> int:
        """Hydrate ghsa_by_package & ghsa_by_ecosystem_package from SQLite ghsa_package_index."""
        if not self._sqlite_enabled or not self._sqlite_path:
            return 0

        pkg_names: Set[str] = set()
        eco_pkg_pairs: Set[Tuple[str, str]] = set()
        for raw_pkg in target_packages or set():
            if isinstance(raw_pkg, str) and raw_pkg.strip():
                pkg_names.add(raw_pkg.strip().lower())
        for raw_purl in target_purls or set():
            eco, name = parse_purl(raw_purl)
            if name:
                pkg_names.add(name)
                if eco:
                    eco_pkg_pairs.add((eco, name))

        if not pkg_names and not eco_pkg_pairs:
            return 0

        if not self._sqlite_verify_signature():
            self.ctx.logger.warning(
                "GHSA SQLite signature check failed during package hydrate; quarantining and rebuilding."
            )
            self._sqlite_quarantine_and_reset()
            return 0

        hydrated = 0
        try:
            all_rows: List[Tuple[Any, ...]] = []
            batch = sorted(pkg_names)
            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    for i in range(0, len(batch), _SQLITE_CHUNK_SIZE):
                        chunk = batch[i:i + _SQLITE_CHUNK_SIZE]
                        placeholders = ",".join("?" for _ in chunk)
                        sql = (
                            "SELECT ecosystem, package_name, advisory_id, cve_id, "
                            "cvss_score, cvss_vector, severity, summary, advisory_json "
                            f"FROM ghsa_package_index WHERE LOWER(package_name) IN ({placeholders})"
                        )
                        all_rows.extend(conn.execute(sql, tuple(chunk)).fetchall())

            for eco, pkg_name, adv_id, cve_id, cvss_score, cvss_vector, severity, summary, adv_json in all_rows:
                eco_norm = str(eco or "").strip().lower()
                pkg_norm = str(pkg_name or "").strip().lower()
                target_pkg_names_lower = {str(p).strip().lower() for p in (target_packages or set()) if p}
                if eco_pkg_pairs and eco_norm and (eco_norm, pkg_norm) not in eco_pkg_pairs and pkg_norm not in target_pkg_names_lower:
                    continue
                advisory: Optional[Dict[str, Any]] = None
                if isinstance(adv_json, str) and adv_json:
                    try:
                        advisory = json.loads(adv_json)
                    except json.JSONDecodeError:
                        advisory = None
                if advisory is None:
                    advisory = {
                        "id": adv_id,
                        "ghsa_id": adv_id,
                        "cve": cve_id,
                        "aliases": [cve_id] if cve_id else [],
                        "package_name": pkg_norm,
                        "ecosystem": eco_norm,
                        "cvss_score": cvss_score,
                        "cvss_vector": cvss_vector,
                        "severity": severity,
                        "summary": summary,
                    }

                existing_pkg_list = self.ghsa_by_package.setdefault(pkg_norm, [])
                if not any(self._advisory_id(a) == adv_id for a in existing_pkg_list):
                    existing_pkg_list.append(advisory)
                if eco_norm:
                    eco_list = self.ghsa_by_ecosystem_package.setdefault((eco_norm, pkg_norm), [])
                    if not any(self._advisory_id(a) == adv_id for a in eco_list):
                        eco_list.append(advisory)
                hydrated += 1
        except Exception as e:
            self.ctx.logger.warning(f"GHSA SQLite package hydrate failed: {e}")

        return hydrated

    def _sqlite_clear(self) -> None:
        if not self._sqlite_enabled or not self._sqlite_path:
            return
        try:
            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    conn.execute("DELETE FROM ghsa_cve_index")
                    conn.execute("DELETE FROM ghsa_package_index")
            self._sqlite_write_signature()
        except (OSError, sqlite3.DatabaseError) as e:
            self.ctx.logger.warning(f"GHSA SQLite reset failed: {e}")

    # ------------------------------------------------------------------
    # Input validation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_valid_cve_id(cve_id: str) -> bool:
        """Accept only well-formed CVE IDs to prevent unexpected SQLite query patterns."""
        if not isinstance(cve_id, str):
            return False
        parts = cve_id.strip().upper().split("-")
        # Format: CVE-YYYY-NNNN(+)
        if len(parts) != 3 or parts[0] != "CVE":
            return False
        return parts[1].isdigit() and len(parts[1]) == 4 and parts[2].isdigit() and len(parts[2]) >= 4

    @staticmethod
    def _extract_cves(advisory: Dict[str, Any]) -> List[str]:
        out: List[str] = []
        cve = advisory.get("cve") or advisory.get("cve_id")
        if isinstance(cve, str) and cve.strip().upper().startswith("CVE-"):
            out.append(cve.strip().upper())
        aliases = advisory.get("aliases")
        if isinstance(aliases, list):
            for alias in aliases:
                if isinstance(alias, str) and alias.strip().upper().startswith("CVE-"):
                    out.append(alias.strip().upper())
        # Preserve order while deduplicating
        return list(dict.fromkeys(out))

    @staticmethod
    def _extract_packages(advisory: Dict[str, Any]) -> List[str]:
        pkgs: List[str] = []
        pkg_name = advisory.get("package_name")
        if isinstance(pkg_name, str) and pkg_name.strip():
            pkgs.append(pkg_name.strip())

        affected = advisory.get("affected")
        if isinstance(affected, list):
            for item in affected:
                if not isinstance(item, dict):
                    continue
                package = item.get("package")
                if isinstance(package, dict):
                    name = package.get("name")
                    if isinstance(name, str) and name.strip():
                        pkgs.append(name.strip())
        return list(dict.fromkeys(pkgs))

    def _index_advisory(self, advisory: Dict[str, Any]) -> None:
        for cve in self._extract_cves(advisory):
            self.ghsa_by_cve.setdefault(cve, []).append(advisory)
        for package_name in self._extract_packages(advisory):
            self.ghsa_by_package.setdefault(package_name, []).append(advisory)
        for eco, pkg_norm in self._extract_package_entries(advisory):
            if eco:
                self.ghsa_by_ecosystem_package.setdefault((eco, pkg_norm), []).append(advisory)

    def _load_json_file(self, path: Path, *, label: str) -> Optional[Any]:
        """Load JSON content via PFH-governed file access."""
        try:
            validated = self.ctx.pfh.ensure_readable_file(path, label=label)
            with self.ctx.pfh.open_for_read(validated, "r", encoding="utf-8", label=label) as handle:
                return json.load(handle)
        except (IOError, json.JSONDecodeError) as e:
            self.ctx.logger.debug(f"GHSA JSON read failed for {path}: {e}")
            return None
        except Exception as e:
            # PFH policy violations and access issues are expected to be non-fatal per-file.
            self.ctx.logger.debug(f"GHSA PFH validation failed for {path}: {e}")
            return None
    
    def _fetch_advisory(self, ghsa_id: str, *, timeout: int = 7) -> Optional[Dict[str, Any]]:
        """
        Fetch a single GHSA advisory from GitHub REST API.
        
        Args:
            ghsa_id: GHSA identifier (e.g., "GHSA-1234-abcd-efgh")
            timeout: Request timeout in seconds
            
        Returns:
            Dict with advisory data if successful, None otherwise
        """
        # Check cache first
        if ghsa_id in self._advisory_cache:
            return self._advisory_cache[ghsa_id]
        
        try:
            url = f"{self.GHSA_API_BASE}/{ghsa_id}"
            headers = self._build_headers()
            
            resp = requests.get(url, headers=headers, timeout=timeout)
            resp.raise_for_status()
            
            advisory_data = resp.json()
            self._advisory_cache[ghsa_id] = advisory_data
            return advisory_data
        
        except requests.RequestException as e:
            self.ctx.logger.debug(f"GHSA API fetch failed for {ghsa_id}: {e}")
            return None

    def _fetch_advisories_by_cve(self, cve_id: str, *, timeout: int = 7) -> List[Dict[str, Any]]:
        """Fetch GHSA advisories for a CVE via GitHub advisories endpoint."""
        normalized = cve_id.strip().upper()
        if not self._is_valid_cve_id(normalized):
            return []

        if normalized in self._cve_search_cache:
            return self._cve_search_cache[normalized]

        try:
            headers = self._build_headers()
            resp = requests.get(
                self.GHSA_API_BASE,
                params={"cve_id": normalized, "per_page": 20},
                headers=headers,
                timeout=timeout,
            )
            resp.raise_for_status()
            payload = resp.json()
            advisories = payload if isinstance(payload, list) else []
            advisories = [a for a in advisories if isinstance(a, dict)]
            self._cve_search_cache[normalized] = advisories
            return advisories
        except requests.RequestException as e:
            self.ctx.logger.debug(f"GHSA API CVE lookup failed for {normalized}: {e}")
            self._cve_search_cache[normalized] = []
            return []

    def preload_online_for_cves(self, cves: Set[str], *, timeout: int = 7, max_lookups: int = 25) -> Dict[str, int]:
        """Prefetch GHSA advisories online for a bounded set of CVEs."""
        if not cves:
            self._is_loaded = True
            return {"requested": 0, "queried": 0, "hits": 0}

        normalized = sorted({c.strip().upper() for c in cves if self._is_valid_cve_id(c)})
        selected = normalized[: max(0, int(max_lookups))]

        hit_count = 0
        for cve in selected:
            advisories = self._fetch_advisories_by_cve(cve, timeout=timeout)
            if advisories:
                hit_count += 1
                for advisory in advisories:
                    self._index_advisory(advisory)

        self._is_loaded = True
        return {
            "requested": len(normalized),
            "queried": len(selected),
            "hits": hit_count,
        }

    @staticmethod
    def _extract_package_tokens_from_finding(finding: Any) -> Set[str]:
        """Extract normalized package-like tokens from finding text and PURL fields."""
        fields = [
            getattr(finding, "title", "") or "",
            getattr(finding, "description", "") or "",
            getattr(finding, "solution", "") or "",
            getattr(finding, "detection_plugin", "") or "",
            getattr(finding, "plugin_output", "") or "",
        ]
        text = "\n".join(str(x) for x in fields if x)
        tokens = {t.lower() for t in _PKG_TOKEN_RE.findall(text)}
        purl = getattr(finding, "package_purl", None)
        if isinstance(purl, str) and purl.strip():
            _, pkg_name = parse_purl(purl)
            if pkg_name:
                tokens.add(pkg_name)
                if ":" in pkg_name:
                    tokens.add(pkg_name.split(":", 1)[1])
                if "/" in pkg_name:
                    tokens.add(pkg_name.rsplit("/", 1)[1])
        return tokens

    def lookup_by_purl(self, purl: str) -> List[Dict[str, Any]]:
        """Resolve advisories by PURL using in-memory index or warm SQLite ghsa_package_index."""
        eco, pkg_name = parse_purl(purl)
        if not pkg_name:
            return []

        if eco and (eco, pkg_name) in self.ghsa_by_ecosystem_package:
            return list(self.ghsa_by_ecosystem_package[(eco, pkg_name)])

        if self._sqlite_enabled:
            self._sqlite_hydrate_packages(target_purls={purl})
            if eco and (eco, pkg_name) in self.ghsa_by_ecosystem_package:
                return list(self.ghsa_by_ecosystem_package[(eco, pkg_name)])

        matched: List[Dict[str, Any]] = []
        for k, advs in self.ghsa_by_package.items():
            if str(k).strip().lower() == pkg_name:
                matched.extend(advs)
        return matched

    def _lookup_by_package(self, finding: Any) -> List[Dict[str, Any]]:
        matched: List[Dict[str, Any]] = []
        seen_ids: Set[str] = set()

        purl = getattr(finding, "package_purl", None)
        if isinstance(purl, str) and purl.strip():
            for advisory in self.lookup_by_purl(purl):
                aid = self._advisory_id(advisory)
                if aid in seen_ids:
                    continue
                seen_ids.add(aid)
                matched.append(advisory)
            if matched:
                return matched

        tokens = self._extract_package_tokens_from_finding(finding)
        if (not self.ghsa_by_package) and self._sqlite_enabled and tokens:
            self._sqlite_hydrate_packages(target_packages=tokens)

        if not self.ghsa_by_package:
            return matched

        pkg_lookup: Dict[str, List[Dict[str, Any]]] = {}
        for pkg_name, advisories in self.ghsa_by_package.items():
            key = str(pkg_name).strip().lower()
            if key and isinstance(advisories, list):
                pkg_lookup.setdefault(key, []).extend(a for a in advisories if isinstance(a, dict))

        for token in tokens:
            for advisory in pkg_lookup.get(token, []):
                aid = str(advisory.get("id") or advisory.get("ghsa_id") or "")
                if aid and aid in seen_ids:
                    continue
                if aid:
                    seen_ids.add(aid)
                matched.append(advisory)
        return matched
    
    def load_online(self, *, ghsa_ids: Optional[List[str]] = None, timeout: int = 7) -> bool:
        """
        Load GHSA data from GitHub REST API (online mode).
        
        Args:
            ghsa_ids: List of GHSA IDs to fetch (e.g., ["GHSA-1234-abcd-efgh", ...])
                     If None, no advisories are fetched (on-demand mode)
            timeout: Request timeout in seconds per advisory
            
        Returns:
            bool: True if load succeeded (or no IDs provided), False otherwise
            
        Rate limiting: 60 requests/hour unauthenticated, 5000/hour with token.
        Use sparingly for initial load; on-demand lookup preferred for individual enrichments.
        """
        if not ghsa_ids:
            self.ctx.logger.debug("GHSA online mode enabled (on-demand lookup)")
            self._is_loaded = True
            return True
        
        successful = 0
        failed = 0
        
        for ghsa_id in ghsa_ids:
            adv = self._fetch_advisory(ghsa_id, timeout=timeout)
            if adv:
                successful += 1
                self._index_advisory(adv)
            else:
                failed += 1
        
        if successful > 0:
            self.ctx.logger.info(
                f"GHSA online load: {successful} advisories fetched "
                f"({failed} failed, {len(self.ghsa_by_cve)} unique CVEs)"
            )
            self._is_loaded = True
            return True
        
        return False
    
    def load_offline(
        self,
        *,
        db_path: Optional[str] = None,
        target_cves: Optional[Set[str]] = None,
        force_reindex: bool = False,
        target_purls: Optional[Set[str]] = None,
        target_packages: Optional[Set[str]] = None,
    ) -> bool:
        """
        Load GHSA data from local offline database (JSON file or advisory-database directory),
        indexing both CVEs (ghsa_cve_index) and packages/PURLs (ghsa_package_index).
        """
        if not db_path:
            self.ctx.logger.debug("GHSA offline load: no database path provided")
            return False

        try:
            source_path = Path(db_path)
            loaded_count = 0
            target_cve_set = self._normalize_target_cves(target_cves)
            has_pkg_targets = bool(target_purls or target_packages)

            if source_path.is_file():
                advisories = self._load_json_file(source_path, label="ghsa advisory source")
                if advisories is None:
                    return False
                sqlite_rows: List[Tuple[str, str, str, str]] = []
                pkg_rows: List[Tuple[Any, ...]] = []

                if isinstance(advisories, dict):
                    self._index_advisory(advisories)
                    sqlite_rows.extend(self._sqlite_rows_for_advisory(advisories))
                    pkg_rows.extend(self._sqlite_package_rows_for_advisory(advisories))
                    loaded_count = 1
                elif isinstance(advisories, list):
                    for advisory in advisories:
                        if isinstance(advisory, dict):
                            self._index_advisory(advisory)
                            sqlite_rows.extend(self._sqlite_rows_for_advisory(advisory))
                            pkg_rows.extend(self._sqlite_package_rows_for_advisory(advisory))
                            loaded_count += 1
                else:
                    self.ctx.logger.warning(
                        f"GHSA database format error: expected dict/list, got {type(advisories)}"
                    )
                    return False

                if sqlite_rows or pkg_rows:
                    self._sqlite_upsert_rows(sqlite_rows, package_rows=pkg_rows)
            elif source_path.is_dir():
                reviewed_root = source_path / "advisories" / "github-reviewed"
                if not reviewed_root.exists():
                    reviewed_root = source_path

                try:
                    reviewed_root = self.ctx.pfh.ensure_readable_dir(reviewed_root, label="ghsa advisory directory")
                except Exception as e:
                    self.ctx.logger.warning(f"GHSA source directory not readable under PFH policy: {e}")
                    return False

                sqlite_had_rows = self._sqlite_has_rows()
                if force_reindex and self._sqlite_enabled:
                    self._sqlite_clear()
                    sqlite_had_rows = False

                if self._sqlite_enabled and not force_reindex and sqlite_had_rows:
                    if target_cve_set or has_pkg_targets:
                        unresolved = self._sqlite_hydrate_targets(target_cve_set) if target_cve_set else set()
                        pkg_hits = (
                            self._sqlite_hydrate_packages(
                                target_packages=target_packages,
                                target_purls=target_purls,
                            )
                            if has_pkg_targets
                            else 0
                        )
                        self._is_loaded = True
                        self.ctx.logger.info(
                            f"GHSA SQLite warm-hit: cves_resolved={len(target_cve_set) - len(unresolved)}/{len(target_cve_set)}, "
                            f"pkg_rows={pkg_hits}; skipped directory parse."
                        )
                        return True

                candidate_files = list(reviewed_root.glob("*/*/GHSA-*/*.json"))
                if not candidate_files:
                    candidate_files = list(reviewed_root.rglob("GHSA-*.json"))

                max_workers = min(os.cpu_count() or 4, 8)
                sqlite_batch: List[Tuple[str, str, str, str]] = []
                pkg_batch: List[Tuple[Any, ...]] = []

                def _read_one(fp: Path) -> Optional[Dict[str, Any]]:
                    adv = self._load_json_file(fp, label="ghsa advisory file")
                    return adv if isinstance(adv, dict) else None

                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
                    for advisory in pool.map(_read_one, candidate_files):
                        if advisory is None:
                            continue
                        self._index_advisory(advisory)
                        if self._sqlite_enabled:
                            sqlite_batch.extend(self._sqlite_rows_for_advisory(advisory))
                            pkg_batch.extend(self._sqlite_package_rows_for_advisory(advisory))
                            if len(sqlite_batch) >= 2000 or len(pkg_batch) >= 2000:
                                self._sqlite_upsert_rows(sqlite_batch, package_rows=pkg_batch)
                                sqlite_batch.clear()
                                pkg_batch.clear()
                        loaded_count += 1

                if sqlite_batch or pkg_batch:
                    self._sqlite_upsert_rows(sqlite_batch, package_rows=pkg_batch)

                if (target_cve_set or has_pkg_targets) and self._sqlite_enabled:
                    self.ghsa_by_cve = {}
                    self.ghsa_by_package = {}
                    self.ghsa_by_ecosystem_package = {}
                    if target_cve_set:
                        self._sqlite_hydrate_targets(target_cve_set)
                    if has_pkg_targets:
                        self._sqlite_hydrate_packages(
                            target_packages=target_packages,
                            target_purls=target_purls,
                        )
            else:
                self.ctx.logger.warning(f"GHSA source path not found: {db_path}")
                return False

            if loaded_count <= 0 and not self.ghsa_by_cve and not self.ghsa_by_package:
                self.ctx.logger.warning("GHSA offline load completed with 0 advisory files.")
                return False

            self._is_loaded = True
            self.ctx.logger.info(
                f"GHSA database loaded: {loaded_count} advisories, "
                f"{len(self.ghsa_by_cve)} CVE mappings, {len(self.ghsa_by_package)} package mappings"
            )
            return True

        except (IOError, json.JSONDecodeError) as e:
            self.ctx.logger.warning(f"GHSA database load failed: {e}")
            return False
    
    def enrich_finding(self, finding: Any, *, by_cve: bool = True, by_package: bool = False, online: bool = False, timeout: int = 7) -> Optional[Dict[str, Any]]:
        """
        Look up GHSA advisory data for a finding.
        
        Matching strategy:
        1. by_cve: Match on CVE identifier (default, fastest)
        2. by_package: Match on package name and version range (requires more context)
        3. online: Enable REST API lookup for real-time data (requires internet)
        
        Args:
            finding: Finding object to enrich
            by_cve: Enable CVE-based lookup
            by_package: Enable package-based lookup (requires package context in finding)
            online: Enable REST API lookups (one request per CVE)
            timeout: Request timeout for API calls
            
        Returns:
            Dict with advisory data if match found, None otherwise
        """
        if not self._is_loaded and not online:
            return None
        
        # Try CVE lookup first (offline or online)
        if by_cve and hasattr(finding, 'cves') and finding.cves:
            for cve in finding.cves:
                # Check offline cache first
                if cve in self.ghsa_by_cve:
                    advisories = self.ghsa_by_cve[cve]
                    return {
                        "source": "ghsa",
                        "match_type": "cve",
                        "lookup_mode": "offline",
                        "advisories": advisories,
                        "advisory_count": len(advisories),
                    }
                
                # Try online lookup if enabled
                if online and self._is_valid_cve_id(cve):
                    advisories = self._fetch_advisories_by_cve(cve, timeout=timeout)
                    if advisories:
                        for advisory in advisories:
                            self._index_advisory(advisory)
                        return {
                            "source": "ghsa",
                            "match_type": "cve",
                            "lookup_mode": "online",
                            "advisories": advisories,
                            "advisory_count": len(advisories),
                        }
        
        # Package-based lookup scaffolded for v1.2.1+
        if by_package:
            package_advisories = self._lookup_by_package(finding)
            if package_advisories:
                return {
                    "source": "ghsa",
                    "match_type": "package",
                    "lookup_mode": "offline",
                    "advisories": package_advisories,
                    "advisory_count": len(package_advisories),
                }
        
        return None
    
    def enrich_scan(self, scan: ScanResult) -> Dict[str, Dict[str, Any]]:
        """
        Enrich all findings in a scan with GHSA advisory data.
        
        Args:
            scan: ScanResult to enrich
            
        Returns:
            Dict mapping finding_id → enrichment data
        """
        if not self._is_loaded:
            return {}
        
        enrichments: Dict[str, Dict[str, Any]] = {}
        
        for asset in scan.assets:
            for finding in asset.findings:
                adv_data = self.enrich_finding(finding, by_cve=True, by_package=False)
                if adv_data:
                    enrichments[finding.finding_id] = adv_data
        
        return enrichments
