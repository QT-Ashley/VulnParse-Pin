# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

"""
GitHub Security Advisory (GHSA) hybrid enrichment source.

Provides enrichment via GHSA vulnerability advisory data.
Supports both online (GitHub REST API) and offline (local database) modes.
"""

from typing import Dict, Optional, List, Any, Set, Tuple
from pathlib import Path
from datetime import datetime, timezone, timedelta
import concurrent.futures
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
from vulnparse_pin.utils.logger import colorize
from vulnparse_pin import UA

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

    def _init_sqlite_index(self) -> None:
        """Initialize optional GHSA SQLite index for warm-run CVE lookups."""
        try:
            paths = getattr(self.ctx, "paths", None)
            if not paths or not getattr(paths, "cache_dir", None):
                return

            db_path = paths.cache_dir / "ghsa_cache.sqlite3"
            if not db_path.exists():
                db_path = self.ctx.pfh.ensure_writable_file(
                    db_path,
                    label="GHSA SQLite Index",
                    create_parents=True,
                    overwrite=False,
                )
            else:
                self.ctx.pfh.ensure_readable_file(db_path, label="GHSA SQLite Index")
                if not os.access(db_path, os.W_OK):
                    raise PermissionError(
                        f"GHSA SQLite index is not writable: {self.ctx.pfh.format_for_log(db_path)}"
                    )

            with sqlite3.connect(str(db_path)) as conn:
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
                conn.execute("PRAGMA integrity_check")

            self._sqlite_enabled = True
            self._sqlite_path = str(db_path)
            self._sqlite_sig_path = f"{self._sqlite_path}.sig.json"
            self._sqlite_harden_permissions()

            if not self._sqlite_verify_signature():
                self.ctx.logger.warning(
                    "GHSA SQLite signature verification failed; quarantining and rebuilding index."
                )
                self._sqlite_quarantine_and_reset()

            self._sqlite_prune()

            # Re-sign after all schema operations so the sig reflects the
            # post-init file state (schema-DDL no-ops can touch SQLite header bytes).
            self._sqlite_write_signature()

            self.ctx.logger.debug(
                f"GHSA SQLite index enabled at {self.ctx.pfh.format_for_log(db_path)}"
            )
        except (OSError, sqlite3.DatabaseError, ValueError, TypeError) as e:
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
        headers["User-Agent"] = UA or "VulnParse-Pin/1.2"
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
            with sqlite3.connect(self._sqlite_path) as conn:
                before_changes = conn.total_changes
                if max_age_hours > 0:
                    cutoff = (datetime.now(timezone.utc) - timedelta(hours=max_age_hours)).isoformat().replace("+00:00", "Z")
                    conn.execute("DELETE FROM ghsa_cve_index WHERE updated_at < ?", (cutoff,))
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

    def _sqlite_verify_signature(self) -> bool:
        """Return False when tampering or corruption is detected."""
        if not self._sqlite_enabled or not self._sqlite_path:
            return False
        if not self._sqlite_sig_path or not os.path.exists(self._sqlite_sig_path):
            # First run – bootstrap signature.
            self._sqlite_write_signature()
            return True
        try:
            with self.ctx.pfh.open_for_read(self._sqlite_sig_path, mode="r", encoding="utf-8", label="GHSA SQLite Signature", log=False) as f:
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
        with sqlite3.connect(self._sqlite_path) as conn:
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
        self._sqlite_write_signature()

    def _normalize_target_cves(self, target_cves: Optional[Set[str]]) -> Set[str]:
        if not target_cves:
            return set()
        return {
            c.strip().upper()
            for c in target_cves
            if isinstance(c, str) and c.strip().upper().startswith("CVE-")
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
            with sqlite3.connect(self._sqlite_path) as conn:
                row_count = conn.execute("SELECT COUNT(*) FROM ghsa_cve_index").fetchone()[0]
            return row_count > 0
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
            with sqlite3.connect(self._sqlite_path) as conn:
                batch = list(valid_targets)
                chunk_size = 900          # stay under SQLite 999-parameter limit
                for i in range(0, len(batch), chunk_size):
                    chunk = batch[i:i + chunk_size]
                    # Parameterised placeholders — no string interpolation of user data.
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

    def _sqlite_upsert_rows(self, rows: List[Tuple[str, str, str, str]]) -> None:
        if not self._sqlite_enabled or not self._sqlite_path or not rows:
            return
        if not self._sqlite_verify_signature():
            self.ctx.logger.warning(
                "GHSA SQLite signature check failed during upsert; quarantining and rebuilding."
            )
            self._sqlite_quarantine_and_reset()
        try:
            with sqlite3.connect(self._sqlite_path) as conn:
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
            self._sqlite_prune()
            self._sqlite_write_signature()
        except (OSError, sqlite3.DatabaseError) as e:
            self.ctx.logger.warning(f"GHSA SQLite upsert failed; continuing with in-memory index only: {e}")

    def _sqlite_clear(self) -> None:
        if not self._sqlite_enabled or not self._sqlite_path:
            return
        try:
            with sqlite3.connect(self._sqlite_path) as conn:
                conn.execute("DELETE FROM ghsa_cve_index")
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
        """Extract normalized package-like tokens from finding text fields."""
        fields = [
            getattr(finding, "title", "") or "",
            getattr(finding, "description", "") or "",
            getattr(finding, "solution", "") or "",
            getattr(finding, "detection_plugin", "") or "",
            getattr(finding, "plugin_output", "") or "",
        ]
        text = "\n".join(str(x) for x in fields if x)
        tokens = {t.lower() for t in _PKG_TOKEN_RE.findall(text)}
        return tokens

    def _lookup_by_package(self, finding: Any) -> List[Dict[str, Any]]:
        if not self.ghsa_by_package:
            return []
        pkg_lookup: Dict[str, List[Dict[str, Any]]] = {}
        for pkg_name, advisories in self.ghsa_by_package.items():
            key = str(pkg_name).strip().lower()
            if key and isinstance(advisories, list):
                pkg_lookup.setdefault(key, []).extend(a for a in advisories if isinstance(a, dict))

        if not pkg_lookup:
            return []

        matched: List[Dict[str, Any]] = []
        seen_ids: Set[str] = set()
        for token in self._extract_package_tokens_from_finding(finding):
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
    ) -> bool:
        """
        Load GHSA data from local offline database.
        
        Expected file format: JSON array of GHSA advisory objects:
        [
          {
            "ghsa_id": "GHSA-1234-abcd-efgh",
            "cve": "CVE-2023-12345",
            "package_name": "example-lib",
            "affected_versions": ["<1.2.3"],
            "fixed_version": "1.2.3",
            "severity": "HIGH",
            "published_at": "2023-04-01T00:00:00Z",
            "references": [...]
          },
          ...
        ]
        
        Args:
            db_path: Path to GHSA database JSON file
            
        Returns:
            bool: True if load succeeded, False otherwise
        """
        if not db_path:
            self.ctx.logger.debug("GHSA offline load: no database path provided")
            return False

        try:
            source_path = Path(db_path)
            loaded_count = 0
            target_cve_set = self._normalize_target_cves(target_cves)

            if source_path.is_file():
                advisories = self._load_json_file(source_path, label="ghsa advisory source")
                if advisories is None:
                    return False
                sqlite_rows: List[Tuple[str, str, str, str]] = []

                if isinstance(advisories, dict):
                    self._index_advisory(advisories)
                    sqlite_rows.extend(self._sqlite_rows_for_advisory(advisories))
                    loaded_count = 1
                elif isinstance(advisories, list):
                    for advisory in advisories:
                        if isinstance(advisory, dict):
                            self._index_advisory(advisory)
                            sqlite_rows.extend(self._sqlite_rows_for_advisory(advisory))
                            loaded_count += 1
                else:
                    self.ctx.logger.warning(
                        f"GHSA database format error: expected dict/list, got {type(advisories)}"
                    )
                    return False

                if sqlite_rows:
                    self._sqlite_upsert_rows(sqlite_rows)
            elif source_path.is_dir():
                # Supports github/advisory-database layout:
                # advisories/github-reviewed/YYYY/MM/GHSA-XXXX-XXXX-XXXX/*.json
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

                unresolved = set(target_cve_set)
                if target_cve_set and self._sqlite_enabled and not force_reindex:
                    unresolved = self._sqlite_hydrate_targets(target_cve_set)
                    if not unresolved:
                        self._is_loaded = True
                        self.ctx.logger.info(
                            f"GHSA SQLite warm-hit satisfied all {len(target_cve_set)} target CVEs; skipped directory parse."
                        )
                        return True

                    # If SQLite already has historical data, avoid a full repository rescan on every run.
                    if sqlite_had_rows:
                        self._is_loaded = True
                        self.ctx.logger.info(
                            f"GHSA SQLite warm-hit partial: {len(target_cve_set) - len(unresolved)} resolved, "
                            f"{len(unresolved)} unresolved (treated as no GHSA advisory match)."
                        )
                        return True

                candidate_files = list(reviewed_root.glob("*/*/GHSA-*/*.json"))
                if not candidate_files:
                    candidate_files = list(reviewed_root.rglob("GHSA-*.json"))

                # ----------------------------------------------------------
                # Parallel JSON read: IO-bound, so threads scale well here.
                # Workers return (advisory_dict | None) per file.
                # ----------------------------------------------------------
                max_workers = min(os.cpu_count() or 4, 8)
                sqlite_batch: List[Tuple[str, str, str, str]] = []

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
                            if len(sqlite_batch) >= 2000:
                                self._sqlite_upsert_rows(sqlite_batch)
                                sqlite_batch.clear()
                        loaded_count += 1

                if sqlite_batch:
                    self._sqlite_upsert_rows(sqlite_batch)

                # After a cold parse, hydrate only requested CVEs to keep in-memory map compact.
                if target_cve_set and self._sqlite_enabled:
                    self.ghsa_by_cve = {}
                    self.ghsa_by_package = {}
                    self._sqlite_hydrate_targets(target_cve_set)
            else:
                self.ctx.logger.warning(f"GHSA source path not found: {db_path}")
                return False

            if loaded_count <= 0 and not self.ghsa_by_cve:
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
