# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

import contextlib
import hashlib
import hmac
from io import BytesIO
import math
from pathlib import Path
import sqlite3
import stat
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import gzip
import csv
import re
import os
import json
import requests
from vulnparse_pin.utils.logger import SEVERITY_COLOR, EnrichmentMissLogger, colorize
from vulnparse_pin.utils.enrichment_stats import stats
from vulnparse_pin.utils.cve_selector import select_authoritative_cve
from vulnparse_pin.utils.feed_cache import stream_https_get_bytes
from vulnparse_pin.utils.cvss_utils import (
    compute_cvss_base_score,
    detect_cvss_exact_version,
    detect_cvss_version,
    is_valid_cvss_vector,
    parse_cvss_vector,
)
from vulnparse_pin.core.classes.dataclass import Finding, RunContext, ScanResult
from vulnparse_pin import UA

# ------------- Globals -----------------

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
PKG_TOKEN_RE = re.compile(r"[a-zA-Z0-9_.+-]{3,}")
MAX_REMOTE_FEED_BYTES = 200 * 1024 * 1024
MAX_DECOMPRESSED_FEED_BYTES = 2 * 1024 * 1024 * 1024
_SQLITE_CHUNK_SIZE = 900

DEFAULT_ENRICHMENT_CONFIDENCE_POLICY = {
    "model_version": "v1",
    "max_score": 100,
    "base_scanner": 35,
    "weights": {
        "nvd": 25,
        "kev": 15,
        "epss": 10,
        "exploitdb": 10,
        "ghsa": 15,
        "osv": 10,
    },
    "ghsa_signals": {
        "advisory_confidence_bonus": 3,
        "max_advisory_confidence_bonus": 9,
        "exploit_signal_on_high_severity": False,
        "exploit_signal_confidence_bonus": 5,
    },
}

# ----------------------------------------


def _get_stats(ctx: Optional[RunContext]):
    services = getattr(ctx, "services", None) if ctx is not None else None
    run_stats = getattr(services, "enrichment_stats", None) if services is not None else None
    return run_stats if run_stats is not None else stats


def _is_valid_cve_id(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    return CVE_RE.match(value.strip()) is not None


def _filter_valid_cves(cves: Optional[Set[str]]) -> Optional[Set[str]]:
    if cves is None:
        return None
    out: Set[str] = set()
    for raw in cves:
        if isinstance(raw, str):
            cand = raw.strip().upper()
            if _is_valid_cve_id(cand):
                out.add(cand)
    return out

def _is_https_url(url: str) -> bool:
    return str(url).strip().lower().startswith("https://")


def _response_content_length(resp: requests.Response) -> Optional[int]:
    raw = resp.headers.get("Content-Length")
    if not raw:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _assert_response_within_size_limit(resp: requests.Response, *, max_bytes: int, label: str) -> None:
    content_len = _response_content_length(resp)
    if content_len is not None and content_len > max_bytes:
        raise RuntimeError(
            f"{label} response exceeds configured size limit. "
            f"Content-Length={content_len} bytes, limit={max_bytes} bytes."
        )


def _assert_https_redirect_target(resp: requests.Response, *, label: str) -> None:
    final_url = str(getattr(resp, "url", "") or "")
    if final_url and not _is_https_url(final_url):
        raise RuntimeError(f"{label} request redirected to non-HTTPS URL: {final_url}")

#'''TODO: def enrich_with_shodan(ip_address):
#    Query Shodan with API Key
#    parse results: open ports, services, vulns, org
#    return {
#         "open_ports": [22, 80, 443],
#         "services": ["SSH", "HTTP", "HTTPS"],
#         "org": Example.org,
#         "shodan_tag": ["ics", "vpn"]
#    }
#    '''


class _SignedSQLiteFeedCache:
    """
    Shared tamper-evident SQLite cache base enforcing 0o600 permissions,
    world-writable rejection, HMAC/SHA-256 .sig.json verification, and
    quarantine-on-tamper reset.
    """

    def __init__(
        self,
        ctx: Optional[RunContext],
        *,
        db_filename: str,
        label: str,
    ) -> None:
        self.ctx = ctx
        self._label = label
        self._sqlite_enabled = False
        self._sqlite_path: Optional[str] = None
        self._sqlite_sig_path: Optional[str] = None
        self._init_db(db_filename)

    def _sqlite_secret(self) -> Optional[bytes]:
        raw = os.getenv("VP_SQLITE_HMAC_KEY")
        return raw.encode("utf-8") if raw else None

    def _create_schema(self, conn: sqlite3.Connection) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def _harden_permissions(self) -> None:
        if not self._sqlite_path:
            return
        if os.name == "nt":
            self.ctx.pfh.ensure_readable_file(self._sqlite_path, label=self._label)
            if not os.access(self._sqlite_path, os.W_OK):
                raise PermissionError(f"{self._label} is not writable on Windows.")
            return
        try:
            os.chmod(self._sqlite_path, 0o600)
        except OSError:
            pass
        try:
            self.ctx.pfh.ensure_readable_file(self._sqlite_path, label=self._label)
            st = os.stat(self._sqlite_path)
            if bool(st.st_mode & stat.S_IWOTH):
                raise PermissionError(f"{self._label} is world-writable; refusing to continue.")
        except OSError as exc:
            raise PermissionError(f"{self._label} permission check failed: {exc}") from exc

    def _compute_digest(self) -> Optional[str]:
        if not self._sqlite_path:
            return None
        digest = hashlib.sha256()
        with self.ctx.pfh.open_for_read(self._sqlite_path, mode="rb", label=self._label, log=False) as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _write_signature(self) -> None:
        if not self._sqlite_enabled or not self._sqlite_path or not self._sqlite_sig_path:
            return
        digest = self._compute_digest()
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
            label=f"{self._label} Signature",
            create_parents=True,
            overwrite=True,
        )
        with self.ctx.pfh.open_for_write(
            sig_path,
            mode="w",
            encoding="utf-8",
            label=f"{self._label} Signature",
        ) as f:
            json.dump(payload, f, indent=2)
        if os.name != "nt":
            try:
                os.chmod(sig_path, 0o600)
            except OSError:
                pass

    def _verify_signature(self) -> bool:
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
                label=f"{self._label} Signature",
                log=False,
            ) as f:
                payload = json.load(f)
            if not isinstance(payload, dict):
                return False
            mode = str(payload.get("mode", "")).strip()
            expected_sig = str(payload.get("signature", ""))
            expected_digest = str(payload.get("digest", ""))
            current_digest = self._compute_digest()
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

    def _quarantine_and_reset(self) -> None:
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
                self._create_schema(conn)
        self._harden_permissions()
        self._write_signature()

    def _init_db(self, db_filename: str) -> None:
        try:
            paths = getattr(self.ctx, "paths", None)
            cache_dir = getattr(paths, "cache_dir", None) if paths else None
            if not cache_dir or not isinstance(cache_dir, (str, os.PathLike)):
                return
            db_path = Path(cache_dir) / db_filename
            sig_path = f"{db_path}.sig.json"
            db_existed = db_path.exists()

            if not db_existed:
                db_path = Path(
                    self.ctx.pfh.ensure_writable_file(
                        db_path,
                        label=self._label,
                        create_parents=True,
                        overwrite=False,
                    )
                )
            else:
                self.ctx.pfh.ensure_readable_file(db_path, label=self._label)
                if not os.access(db_path, os.W_OK):
                    raise PermissionError(f"{self._label} is not writable: {db_path}")

            self._sqlite_enabled = True
            self._sqlite_path = str(db_path)
            self._sqlite_sig_path = sig_path

            if db_existed:
                self._harden_permissions()
                if not self._verify_signature():
                    if getattr(self.ctx, "logger", None) is not None:
                        self.ctx.logger.warning(f"{self._label} signature failed; quarantining and rebuilding.")
                    self._quarantine_and_reset()
                else:
                    with contextlib.closing(sqlite3.connect(str(db_path))) as conn:
                        with conn:
                            self._create_schema(conn)
                            conn.execute("PRAGMA integrity_check")
            else:
                with contextlib.closing(sqlite3.connect(str(db_path))) as conn:
                    with conn:
                        self._create_schema(conn)
                        conn.execute("PRAGMA integrity_check")

            self._harden_permissions()
            self._write_signature()
        except PermissionError:
            raise
        except (OSError, sqlite3.DatabaseError, ValueError, TypeError, AttributeError) as exc:
            self._sqlite_enabled = False
            self._sqlite_path = None
            self._sqlite_sig_path = None
            if getattr(self.ctx, "logger", None) is not None:
                self.ctx.logger.debug(f"{self._label} disabled: {exc}")


class EPSSLookup(dict):
    """
    Backward-compatible dict[str, float] mapping CVE -> epss_score,
    carrying EPSS v5 percentile and model/date metadata.
    """

    def __init__(
        self,
        scores: Optional[Dict[str, float]] = None,
        *,
        percentiles: Optional[Dict[str, Optional[float]]] = None,
        records: Optional[Dict[str, Dict[str, Any]]] = None,
        model_version: Optional[str] = None,
        score_date: Optional[str] = None,
        source_sha256: Optional[str] = None,
    ) -> None:
        super().__init__(scores or {})
        self.percentiles: Dict[str, Optional[float]] = dict(percentiles or {})
        self.records: Dict[str, Dict[str, Any]] = dict(records or {})
        self.model_version = model_version
        self.score_date = score_date
        self.source_sha256 = source_sha256

    def get_percentile(self, cve_id: str) -> Optional[float]:
        return self.percentiles.get(str(cve_id).strip().upper())

    def get_record(self, cve_id: str) -> Optional[Dict[str, Any]]:
        return self.records.get(str(cve_id).strip().upper())

    @property
    def metadata(self) -> Dict[str, Optional[str]]:
        return {
            "model_version": self.model_version,
            "score_date": self.score_date,
            "source_sha256": self.source_sha256,
        }


class EPSSFeedCache(_SignedSQLiteFeedCache):
    """Signed SQLite-backed cache for EPSS v5 probabilities, percentiles, and model metadata."""

    def __init__(self, ctx: Optional[RunContext]) -> None:
        super().__init__(ctx, db_filename="epss_cache.sqlite3", label="EPSS SQLite Index")

    def _create_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS epss_records (
                cve_id TEXT PRIMARY KEY,
                epss_score REAL,
                epss_percentile REAL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS epss_meta (
                key TEXT PRIMARY KEY,
                value TEXT
            )
            """
        )

    def get_meta(self) -> Dict[str, str]:
        if not self._sqlite_enabled or not self._sqlite_path:
            return {}
        if not self._verify_signature():
            self._quarantine_and_reset()
            return {}
        try:
            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    rows = conn.execute("SELECT key, value FROM epss_meta").fetchall()
            return {str(k): str(v) for k, v in rows if k is not None and v is not None}
        except (OSError, sqlite3.DatabaseError):
            return {}

    def is_warm_for_sha(self, expected_sha256: str) -> bool:
        if not self._sqlite_enabled or not self._sqlite_path or not expected_sha256:
            return False
        if not self._verify_signature():
            self._quarantine_and_reset()
            return False
        meta = self.get_meta()
        if meta.get("source_sha256") != expected_sha256:
            return False
        try:
            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    cnt = conn.execute("SELECT COUNT(*) FROM epss_records").fetchone()[0]
            return cnt > 0
        except (OSError, sqlite3.DatabaseError):
            return False

    def rebuild_from_rows(
        self,
        rows: List[Tuple[str, float, Optional[float]]],
        *,
        model_version: Optional[str],
        score_date: Optional[str],
        source_sha256: Optional[str],
    ) -> None:
        if not self._sqlite_enabled or not self._sqlite_path:
            return
        if not self._verify_signature():
            self._quarantine_and_reset()
        now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        meta_rows = [
            ("model_version", model_version or ""),
            ("score_date", score_date or ""),
            ("source_sha256", source_sha256 or ""),
            ("updated_at", now_utc),
        ]
        try:
            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    conn.execute("DELETE FROM epss_records")
                    conn.execute("DELETE FROM epss_meta")
                    if rows:
                        conn.executemany(
                            "INSERT OR REPLACE INTO epss_records (cve_id, epss_score, epss_percentile) VALUES (?, ?, ?)",
                            rows,
                        )
                    conn.executemany(
                        "INSERT OR REPLACE INTO epss_meta (key, value) VALUES (?, ?)",
                        meta_rows,
                    )
            self._harden_permissions()
            self._write_signature()
        except (OSError, sqlite3.DatabaseError) as exc:
            if getattr(self.ctx, "logger", None) is not None:
                self.ctx.logger.warning(f"EPSS SQLite index write failed: {exc}")

    def query_cves(self, target_cves: Optional[Set[str]] = None) -> EPSSLookup:
        if not self._sqlite_enabled or not self._sqlite_path:
            return EPSSLookup()
        if not self._verify_signature():
            self._quarantine_and_reset()
            return EPSSLookup()

        meta = self.get_meta()
        model_version = meta.get("model_version") or None
        score_date = meta.get("score_date") or None
        source_sha256 = meta.get("source_sha256") or None

        scores: Dict[str, float] = {}
        percentiles: Dict[str, Optional[float]] = {}
        records: Dict[str, Dict[str, Any]] = {}

        try:
            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    if target_cves is None:
                        fetched = conn.execute(
                            "SELECT cve_id, epss_score, epss_percentile FROM epss_records"
                        ).fetchall()
                    else:
                        valid_targets = sorted(_filter_valid_cves(target_cves) or set())
                        fetched = []
                        for i in range(0, len(valid_targets), _SQLITE_CHUNK_SIZE):
                            chunk = valid_targets[i:i + _SQLITE_CHUNK_SIZE]
                            placeholders = ",".join("?" for _ in chunk)
                            sql = (
                                "SELECT cve_id, epss_score, epss_percentile "
                                f"FROM epss_records WHERE cve_id IN ({placeholders})"
                            )
                            fetched.extend(conn.execute(sql, tuple(chunk)).fetchall())

            for cve_id, epss_score, epss_percentile in fetched:
                score_val = _parse_bounded_prob(epss_score, allow_percent=False)
                if score_val is None:
                    continue
                pct_val = _parse_bounded_prob(epss_percentile, allow_percent=True)
                scores[cve_id] = score_val
                percentiles[cve_id] = pct_val
                records[cve_id] = {
                    "cve_id": cve_id,
                    "epss_score": score_val,
                    "epss_percentile": pct_val,
                    "model_version": model_version,
                    "score_date": score_date,
                }
        except (OSError, sqlite3.DatabaseError) as exc:
            if getattr(self.ctx, "logger", None) is not None:
                self.ctx.logger.warning(f"EPSS SQLite query failed: {exc}")

        return EPSSLookup(
            scores,
            percentiles=percentiles,
            records=records,
            model_version=model_version,
            score_date=score_date,
            source_sha256=source_sha256,
        )


def _parse_epss_comment_metadata(line: str) -> Dict[str, str]:
    """Parse FIRST EPSS comment header line like '#model_version:v2025.03.14,score_date:2026-01-01T00:00:00+0000'."""
    meta: Dict[str, str] = {}
    cleaned = line.lstrip("\ufeff").strip()
    if not cleaned.startswith("#"):
        return meta
    body = cleaned[1:].strip()
    for part in re.split(r"[,;]", body):
        token = part.strip()
        if ":" not in token:
            continue
        k, v = token.split(":", 1)
        key_norm = k.strip().lower()
        val_norm = v.strip()
        if key_norm and val_norm:
            meta[key_norm] = val_norm
    return meta


def _parse_bounded_prob(raw: Any, *, allow_percent: bool = False) -> Optional[float]:
    if raw is None or isinstance(raw, bool):
        return None
    text = str(raw).strip()
    if not text:
        return None
    try:
        val = float(text)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(val) or val < 0.0:
        return None
    if val > 1.0:
        if allow_percent and val <= 100.0:
            return val / 100.0
        return None
    return val


def _parse_epss_csv_stream(
    text_stream: Any,
    *,
    target_cves: Optional[Set[str]] = None,
) -> Tuple[EPSSLookup, List[Tuple[str, float, Optional[float]]]]:
    """
    Parse EPSS CSV stream extracting model_version, score_date, epss, and percentile.
    Returns (filtered EPSSLookup, full row list for SQLite indexing).
    """
    model_version: Optional[str] = None
    score_date: Optional[str] = None
    header_line: Optional[str] = None

    for raw_line in text_stream:
        line = raw_line.lstrip("\ufeff")
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            meta = _parse_epss_comment_metadata(stripped)
            model_version = meta.get("model_version") or model_version
            score_date = meta.get("score_date") or score_date
            continue
        header_line = line
        break

    if header_line is None:
        return EPSSLookup(model_version=model_version, score_date=score_date), []

    import itertools
    normalized_header = [col.strip().lower() for col in next(csv.reader([header_line]))]
    reader = csv.DictReader(itertools.chain([",".join(normalized_header)], text_stream))

    valid_targets = _filter_valid_cves(target_cves)
    all_rows: List[Tuple[str, float, Optional[float]]] = []
    scores: Dict[str, float] = {}
    percentiles: Dict[str, Optional[float]] = {}
    records: Dict[str, Dict[str, Any]] = {}

    for row in reader:
        cve = (row.get("cve") or "").strip().upper()
        if not cve:
            continue
        epss_val = _parse_bounded_prob(row.get("epss") or row.get("epss_score") or row.get("score"))
        if epss_val is None:
            continue
        pct_val = _parse_bounded_prob(row.get("percentile") or row.get("epss_percentile"), allow_percent=True)
        all_rows.append((cve, epss_val, pct_val))

        if valid_targets is not None and cve not in valid_targets:
            continue
        scores[cve] = epss_val
        percentiles[cve] = pct_val
        records[cve] = {
            "cve_id": cve,
            "epss_score": epss_val,
            "epss_percentile": pct_val,
            "model_version": model_version,
            "score_date": score_date,
        }

    return (
        EPSSLookup(
            scores,
            percentiles=percentiles,
            records=records,
            model_version=model_version,
            score_date=score_date,
        ),
        all_rows,
    )


def load_epss(
    ctx: RunContext,
    *,
    path_url: str,
    force_refresh: bool,
    allow_regen: bool,
    timeout: int = 7,
    user_agent: Optional[str] = UA,
    target_cves: Optional[Set[str]] = None,
) -> EPSSLookup:
    """
    Load EPSS v5 data (probability + percentile + model_version + score_date)
    from a CSV file or HTTPS URL, backed by a signed 0o600 SQLite cache.
    """
    key = "epss"
    fc = ctx.services.feed_cache
    cache_path, _, _ = fc.resolve(key)
    path_url_str = str(path_url)
    epss_db = EPSSFeedCache(ctx)

    def _parse_and_index(feed_path: Path, source_sha: Optional[str] = None) -> EPSSLookup:
        if source_sha is None:
            try:
                source_sha = fc.compute_checksum(key)
            except Exception:
                source_sha = None
        if (not force_refresh) and source_sha and epss_db.is_warm_for_sha(source_sha):
            return epss_db.query_cves(target_cves)
        with ctx.pfh.open_for_read(feed_path, "r", label="EPSS Cache (.csv)") as f:
            lookup, all_rows = _parse_epss_csv_stream(f, target_cves=target_cves)
        if source_sha is None:
            try:
                source_sha = hashlib.sha256(feed_path.read_bytes()).hexdigest()
            except OSError:
                source_sha = None
        lookup.source_sha256 = source_sha
        epss_db.rebuild_from_rows(
            all_rows,
            model_version=lookup.model_version,
            score_date=lookup.score_date,
            source_sha256=source_sha,
        )
        return lookup

    # ----------------------------
    # Online Mode
    # ----------------------------
    if _is_https_url(path_url_str):
        if (not force_refresh) and cache_path.exists() and fc.is_fresh(key):
            ctx.logger.print_info("Using cached EPSS (TTL valid).", label="EPSS Loader")
            fc.ensure_feed_checksum(key, allow_regen=allow_regen)
            fc.print_cache_metadata(key)
            return _parse_and_index(cache_path)

        ctx.logger.print_info(f"Fetching EPSS from {path_url} (streamed).", label="EPSS Loader")
        headers = {"User-Agent": user_agent}

        try:
            fc.write_atomic_stream_gunzip(
                key,
                source_url=path_url_str,
                mode="Online",
                validated=False,
                checksum_src="Local",
                timeout=timeout,
                headers=headers,
                extra_meta={
                    "content_encoding": "gzip",
                    "stored_as": "csv",
                    "source_type": "url",
                },
                max_response_bytes=MAX_REMOTE_FEED_BYTES,
                enforce_https_redirect=True,
            )

            fc.ensure_feed_checksum(key, allow_regen=True)
            fc.print_cache_metadata(key)
            # Force SQLite rebuild after online refresh
            with ctx.pfh.open_for_read(cache_path, "r", label="EPSS Cache (.csv)") as f:
                lookup, all_rows = _parse_epss_csv_stream(f, target_cves=target_cves)
            source_sha = fc.compute_checksum(key)
            lookup.source_sha256 = source_sha
            epss_db.rebuild_from_rows(
                all_rows,
                model_version=lookup.model_version,
                score_date=lookup.score_date,
                source_sha256=source_sha,
            )
            return lookup
        except RuntimeError:
            raise
        except Exception as e:
            ctx.logger.exception("EPSS update failed %s", e)

            if cache_path.exists():
                ctx.logger.print_warning("Falling back to existing cached EPSS.", label="EPSS Loader")
                fc.ensure_feed_checksum(key, allow_regen=allow_regen)
                return _parse_and_index(cache_path)
            return EPSSLookup()

    # ----------------------------
    # Local/Offline Mode
    # ----------------------------
    src_path = Path(path_url_str)
    if src_path.exists():
        ctx.logger.print_info(f"Importing local EPSS source {ctx.pfh.format_for_log(src_path)}", label="EPSS Loader")

        with ctx.pfh.open_for_read(src_path, mode="rb", label="Local EPSS Source") as r:
            raw = r.read()

        if src_path.suffix.lower().endswith(".gz"):
            try:
                chunks = []
                total_decomp = 0
                with gzip.GzipFile(fileobj=BytesIO(raw), mode="rb") as gz:
                    while True:
                        c = gz.read(1024 * 1024)
                        if not c:
                            break
                        total_decomp += len(c)
                        if total_decomp > MAX_DECOMPRESSED_FEED_BYTES:
                            raise RuntimeError("Local EPSS .gz exceeds 2 GiB safety limit.")
                        chunks.append(c)
                raw_csv = b"".join(chunks)
                content_encoding = "gzip"
            except RuntimeError:
                raise
            except Exception as e:
                raise RuntimeError(f"Failed to decompress local EPSS .gz file: {e}") from e
        else:
            raw_csv = raw
            content_encoding = "none"

        local_digest = hashlib.sha256(raw_csv).hexdigest()
        try:
            if (not force_refresh) and cache_path.exists():
                cache_digest = fc.compute_checksum(key)
                if cache_digest == local_digest and fc.load_meta(key):
                    fc.ensure_feed_checksum(key, allow_regen=allow_regen)
                    if epss_db.is_warm_for_sha(local_digest):
                        ctx.logger.print_info("Local EPSS matches cache & SQLite index; warm-hit.", label="EPSS Loader")
                        return epss_db.query_cves(target_cves)
                    ctx.logger.print_info("Local EPSS matches cache; skipping import.", label="EPSS Loader")
                    return _parse_and_index(cache_path, source_sha=local_digest)
        except RuntimeError:
            raise
        except Exception:
            pass

        fc.write_atomic(
            key,
            raw_csv,
            source_url=f"file://{src_path.as_posix()}",
            mode="Offline-Import",
            validated=False,
            checksum_src="Local",
            extra_meta={
                "content-encoding": content_encoding,
                "stored_as": "csv",
                "source_type": "local",
            },
        )
        fc.ensure_feed_checksum(key, allow_regen=True)
        fc.print_cache_metadata(key)
        with ctx.pfh.open_for_read(cache_path, "r", label="EPSS Cache (.csv)") as f:
            lookup, all_rows = _parse_epss_csv_stream(f, target_cves=target_cves)
        lookup.source_sha256 = local_digest
        epss_db.rebuild_from_rows(
            all_rows,
            model_version=lookup.model_version,
            score_date=lookup.score_date,
            source_sha256=local_digest,
        )
        return lookup

    raise FileNotFoundError(f"EPSS Source not found or invalid: {ctx.pfh.format_for_log(path_url)}")


class KEVLookup(dict):
    """
    Backward-compatible dict[str, bool] mapping CVE -> True,
    carrying full CISA KEV metadata per CVE.
    """

    def __init__(
        self,
        flags: Optional[Dict[str, bool]] = None,
        *,
        records: Optional[Dict[str, Dict[str, Any]]] = None,
        catalog_version: Optional[str] = None,
        date_released: Optional[str] = None,
        source_sha256: Optional[str] = None,
    ) -> None:
        super().__init__(flags or {})
        self.records: Dict[str, Dict[str, Any]] = dict(records or {})
        self.catalog_version = catalog_version
        self.date_released = date_released
        self.source_sha256 = source_sha256

    def get_record(self, cve_id: str) -> Optional[Dict[str, Any]]:
        return self.records.get(str(cve_id).strip().upper())


class KEVFeedCache(_SignedSQLiteFeedCache):
    """Signed SQLite-backed cache for CISA KEV catalog metadata."""

    def __init__(self, ctx: Optional[RunContext]) -> None:
        super().__init__(ctx, db_filename="kev_cache.sqlite3", label="KEV SQLite Index")

    def _create_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS kev_records (
                cve_id TEXT PRIMARY KEY,
                date_added TEXT,
                due_date TEXT,
                known_ransomware INTEGER NOT NULL DEFAULT 0,
                required_action TEXT,
                vulnerability_name TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS kev_meta (
                key TEXT PRIMARY KEY,
                value TEXT
            )
            """
        )

    def get_meta(self) -> Dict[str, str]:
        if not self._sqlite_enabled or not self._sqlite_path:
            return {}
        if not self._verify_signature():
            self._quarantine_and_reset()
            return {}
        try:
            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    rows = conn.execute("SELECT key, value FROM kev_meta").fetchall()
            return {str(k): str(v) for k, v in rows if k is not None and v is not None}
        except (OSError, sqlite3.DatabaseError):
            return {}

    def is_warm_for_sha(self, expected_sha256: str) -> bool:
        if not self._sqlite_enabled or not self._sqlite_path or not expected_sha256:
            return False
        if not self._verify_signature():
            self._quarantine_and_reset()
            return False
        meta = self.get_meta()
        if meta.get("source_sha256") != expected_sha256:
            return False
        try:
            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    cnt = conn.execute("SELECT COUNT(*) FROM kev_records").fetchone()[0]
            return cnt > 0
        except (OSError, sqlite3.DatabaseError):
            return False

    def rebuild_from_records(
        self,
        records_list: List[Dict[str, Any]],
        *,
        catalog_version: Optional[str],
        date_released: Optional[str],
        source_sha256: Optional[str],
    ) -> None:
        if not self._sqlite_enabled or not self._sqlite_path:
            return
        if not self._verify_signature():
            self._quarantine_and_reset()
        now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        payload = [
            (
                rec["cve_id"],
                rec.get("date_added"),
                rec.get("due_date"),
                1 if rec.get("known_ransomware") else 0,
                rec.get("required_action"),
                rec.get("vulnerability_name"),
            )
            for rec in records_list
            if rec.get("cve_id")
        ]
        meta_rows = [
            ("catalog_version", catalog_version or ""),
            ("date_released", date_released or ""),
            ("source_sha256", source_sha256 or ""),
            ("updated_at", now_utc),
        ]
        try:
            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    conn.execute("DELETE FROM kev_records")
                    conn.execute("DELETE FROM kev_meta")
                    if payload:
                        conn.executemany(
                            """
                            INSERT OR REPLACE INTO kev_records (
                                cve_id, date_added, due_date, known_ransomware, required_action, vulnerability_name
                            ) VALUES (?, ?, ?, ?, ?, ?)
                            """,
                            payload,
                        )
                    conn.executemany(
                        "INSERT OR REPLACE INTO kev_meta (key, value) VALUES (?, ?)",
                        meta_rows,
                    )
            self._harden_permissions()
            self._write_signature()
        except (OSError, sqlite3.DatabaseError) as exc:
            if getattr(self.ctx, "logger", None) is not None:
                self.ctx.logger.warning(f"KEV SQLite index write failed: {exc}")

    def query_cves(self, target_cves: Optional[Set[str]] = None) -> KEVLookup:
        if not self._sqlite_enabled or not self._sqlite_path:
            return KEVLookup()
        if not self._verify_signature():
            self._quarantine_and_reset()
            return KEVLookup()

        meta = self.get_meta()
        catalog_version = meta.get("catalog_version") or None
        date_released = meta.get("date_released") or None
        source_sha256 = meta.get("source_sha256") or None

        flags: Dict[str, bool] = {}
        records: Dict[str, Dict[str, Any]] = {}
        try:
            with contextlib.closing(sqlite3.connect(self._sqlite_path)) as conn:
                with conn:
                    if target_cves is None:
                        fetched = conn.execute(
                            "SELECT cve_id, date_added, due_date, known_ransomware, required_action, vulnerability_name FROM kev_records"
                        ).fetchall()
                    else:
                        valid_targets = sorted(_filter_valid_cves(target_cves) or set())
                        fetched = []
                        for i in range(0, len(valid_targets), _SQLITE_CHUNK_SIZE):
                            chunk = valid_targets[i:i + _SQLITE_CHUNK_SIZE]
                            placeholders = ",".join("?" for _ in chunk)
                            sql = (
                                "SELECT cve_id, date_added, due_date, known_ransomware, required_action, vulnerability_name "
                                f"FROM kev_records WHERE cve_id IN ({placeholders})"
                            )
                            fetched.extend(conn.execute(sql, tuple(chunk)).fetchall())

            for cve_id, date_added, due_date, known_ransomware, required_action, vuln_name in fetched:
                flags[cve_id] = True
                records[cve_id] = {
                    "cve_id": cve_id,
                    "date_added": date_added,
                    "due_date": due_date,
                    "known_ransomware": bool(known_ransomware),
                    "required_action": required_action,
                    "vulnerability_name": vuln_name,
                }
        except (OSError, sqlite3.DatabaseError) as exc:
            if getattr(self.ctx, "logger", None) is not None:
                self.ctx.logger.warning(f"KEV SQLite query failed: {exc}")

        return KEVLookup(
            flags,
            records=records,
            catalog_version=catalog_version,
            date_released=date_released,
            source_sha256=source_sha256,
        )


def _normalize_ransomware_flag(raw: Any) -> bool:
    if isinstance(raw, bool):
        return raw
    if raw is None:
        return False
    return str(raw).strip().lower() in {"known", "true", "yes", "1"}


def _parse_kev_payload(
    data: Dict[str, Any],
    *,
    target_cves: Optional[Set[str]] = None,
) -> Tuple[KEVLookup, List[Dict[str, Any]]]:
    catalog_version = str(data.get("catalogVersion") or "").strip() or None
    date_released = str(data.get("dateReleased") or "").strip() or None
    valid_targets = _filter_valid_cves(target_cves)

    flags: Dict[str, bool] = {}
    records: Dict[str, Dict[str, Any]] = {}
    all_records: List[Dict[str, Any]] = []

    for entry in data.get("vulnerabilities", []) or []:
        if not isinstance(entry, dict):
            continue
        raw_cve = entry.get("cveID") or entry.get("CVE") or entry.get("cve_id")
        if not raw_cve:
            continue
        cve_id = str(raw_cve).strip().upper()
        rec = {
            "cve_id": cve_id,
            "date_added": entry.get("dateAdded") or entry.get("date_added"),
            "due_date": entry.get("dueDate") or entry.get("due_date"),
            "known_ransomware": _normalize_ransomware_flag(
                entry.get("knownRansomwareCampaignUse")
                if "knownRansomwareCampaignUse" in entry
                else entry.get("known_ransomware")
            ),
            "required_action": entry.get("requiredAction") or entry.get("required_action"),
            "vulnerability_name": entry.get("vulnerabilityName") or entry.get("vulnerability_name"),
        }
        all_records.append(rec)
        if valid_targets is not None and cve_id not in valid_targets:
            continue
        flags[cve_id] = True
        records[cve_id] = rec

    return (
        KEVLookup(
            flags,
            records=records,
            catalog_version=catalog_version,
            date_released=date_released,
        ),
        all_records,
    )


def load_kev(
    ctx: RunContext,
    path_url: str,
    *,
    force_refresh: bool,
    allow_regen: bool,
    timeout: int = 7,
    user_agent: Optional[str] = UA,
    target_cves: Optional[Set[str]] = None,
) -> KEVLookup:
    """
    Load CISA KEV data (flag + full metadata) from JSON/HTTPS into a
    backward-compatible KEVLookup backed by a signed 0o600 SQLite cache.
    """
    key = "kev"
    fc = ctx.services.feed_cache
    path_url_str = str(path_url)
    kev_db = KEVFeedCache(ctx)

    def _read_json(feed_path: Path) -> Dict[str, Any]:
        if str(feed_path).endswith(".gz"):
            with ctx.pfh.open_for_read(feed_path, mode="rb", label="KEV Feed (.gz)") as rb:
                with gzip.open(rb, "rt", encoding="utf-8") as f:
                    return json.load(f)
        with ctx.pfh.open_for_read(feed_path, mode="r", label="KEV Feed (.json)") as f:
            return json.load(f)

    def _parse_and_index(feed_path: Path, source_sha: Optional[str] = None) -> KEVLookup:
        if source_sha is None:
            try:
                source_sha = fc.compute_checksum(key)
            except Exception:
                source_sha = None
        if (not force_refresh) and source_sha and kev_db.is_warm_for_sha(source_sha):
            return kev_db.query_cves(target_cves)
        data = _read_json(feed_path)
        lookup, all_records = _parse_kev_payload(data, target_cves=target_cves)
        lookup.source_sha256 = source_sha
        kev_db.rebuild_from_records(
            all_records,
            catalog_version=lookup.catalog_version,
            date_released=lookup.date_released,
            source_sha256=source_sha,
        )
        return lookup

    # ----------------------------
    # Online Mode (URL)
    # ----------------------------
    if _is_https_url(path_url_str):
        data_path, _, _ = fc.resolve(key)

        if (not force_refresh) and data_path.exists() and fc.is_fresh(key):
            ctx.logger.print_info("Using cached CISA KEV feed (TTL Valid).", label="KEV Loader")
            fc.ensure_feed_checksum(key, allow_regen=allow_regen)
            fc.print_cache_metadata(key)
            lookup = _parse_and_index(data_path)
            ctx.logger.print_success(f"Loaded KEV data from {ctx.pfh.format_for_log(data_path)}")
            return lookup

        ctx.logger.print_info(f"Downloading CISA KEV feed from {path_url_str}...", label="KEV Loader")
        headers = {"User-Agent": user_agent}

        try:
            raw = stream_https_get_bytes(
                path_url_str,
                max_bytes=MAX_REMOTE_FEED_BYTES,
                timeout=timeout,
                headers=headers,
                label="KEV",
                requests_get=requests.get,
            )
        except RuntimeError:
            raise
        except requests.RequestException as e:
            ctx.logger.exception(f"KEV Loader Failed to retrieve KEV feed: {e}")
            if data_path.exists():
                ctx.logger.print_warning("Upstream fetch failed; attempting fallback to local cache.", label="KEV Loader")
                try:
                    fc.ensure_feed_checksum(key, allow_regen=allow_regen)
                    lookup = _parse_and_index(data_path)
                    ctx.logger.print_warning("Using fallback cached KEV.")
                    return lookup
                except Exception as e2:
                    raise RuntimeError(f"KEV upstream fetch failed and cache fallback failed: {e2}") from e
            return KEVLookup()

        fc.write_atomic(
            key,
            raw,
            source_url=path_url_str,
            mode="Online",
            validated=False,
            checksum_src="Local",
        )
        fc.ensure_feed_checksum(key, allow_regen=True)
        fc.update_cache_meta(key)
        fc.print_cache_metadata(key)

        data_path, _, _ = fc.resolve(key)
        data = _read_json(data_path)
        source_sha = fc.compute_checksum(key)
        lookup, all_records = _parse_kev_payload(data, target_cves=target_cves)
        lookup.source_sha256 = source_sha
        kev_db.rebuild_from_records(
            all_records,
            catalog_version=lookup.catalog_version,
            date_released=lookup.date_released,
            source_sha256=source_sha,
        )
        ctx.logger.print_success(f"Loaded KEV data from {ctx.pfh.format_for_log(data_path)}", label="KEV Loader")
        return lookup

    # -----------------------------
    # Offline / LOCAL
    # -----------------------------
    if os.path.exists(path_url_str):
        try:
            feed_path = ctx.pfh.ensure_readable_file(path_url_str, label="Local KEV Cache")
        except Exception as e:
            raise FileNotFoundError(f"Local KEV file not readable: {ctx.pfh.format_for_log(path_url_str)}") from e

        if feed_path.suffix.lower() == ".gz":
            raise RuntimeError(
                "Local KEV file is .gz, but cache target is kev_cache.json. "
                "Unzip the JSON KEV file or change cache filename to .json.gz."
            )

        with ctx.pfh.open_for_read(feed_path, "rb", label="Local KEV Cache") as r:
            raw = r.read()

        try:
            parsed = json.loads(raw.decode("utf-8"))
        except Exception as e:
            raise RuntimeError(f"Local KEV file is not valid JSON: {ctx.pfh.format_for_log(feed_path)} Trace = {e}") from e

        if not isinstance(parsed, dict):
            raise RuntimeError("Local KEV JSON must be an object at top-level.")

        cache_path, _, _ = fc.resolve("kev")
        local_digest = hashlib.sha256(raw).hexdigest()

        try:
            if (not force_refresh) and cache_path.exists():
                cache_digest = fc.compute_checksum("kev")
                if cache_digest == local_digest and fc.load_meta("kev"):
                    fc.ensure_feed_checksum("kev", allow_regen=allow_regen)
                    if kev_db.is_warm_for_sha(local_digest):
                        ctx.logger.print_info("Local KEV matches cache & SQLite index; warm-hit.")
                        return kev_db.query_cves(target_cves)
                    ctx.logger.print_info("Local KEV matches existing cache; skipping re-import.")
                    return _parse_and_index(cache_path, source_sha=local_digest)
        except RuntimeError:
            raise
        except Exception:
            pass

        fc.write_atomic(
            "kev",
            raw,
            source_url=f"file://{feed_path.as_posix()}",
            mode="Offline-Import",
            validated=False,
            checksum_src="Local",
        )
        fc.ensure_feed_checksum("kev", allow_regen=allow_regen)
        fc.print_cache_metadata("kev")

        data_path, _, _ = fc.resolve("kev")
        data = _read_json(data_path)
        lookup, all_records = _parse_kev_payload(data, target_cves=target_cves)
        lookup.source_sha256 = local_digest
        kev_db.rebuild_from_records(
            all_records,
            catalog_version=lookup.catalog_version,
            date_released=lookup.date_released,
            source_sha256=local_digest,
        )
        ctx.logger.print_success(f"Loaded KEV data from local file {ctx.pfh.format_for_log(data_path)}")
        return lookup

    raise FileNotFoundError(f"File or URL not found: {path_url_str}")
def calculate_risk_score(cvss_score: float, exploit_available: bool, cisa_kev: bool, epss_score: float, score_config: dict):
    weights = score_config["weights"]
    risk_cap = score_config["risk_cap"]

    raw_risk_score = cvss_score

    # Add enrichment weights based on config

    if exploit_available:
        raw_risk_score += weights["exploit_available"]
    if cisa_kev:
        raw_risk_score += weights["cisa_kev"]
    if epss_score >= 0.8:
        raw_risk_score += weights["epss_score_high"]
    elif epss_score >= 0.5:
        raw_risk_score += weights["epss_score_medium"]

    # Cap raw risk at configured max
    if raw_risk_score > risk_cap["max_raw_risk_score"]:
        raw_risk_score = risk_cap["max_raw_risk_score"]

    # Derived capped 0-10 operational risk score
    risk_score = min(raw_risk_score, risk_cap["max_operational_risk_score"])

    # Determine risk band
    risk_band = determine_risk_band(raw_risk_score)

    return raw_risk_score, risk_score, risk_band

def determine_risk_band(raw_risk_score):
    if raw_risk_score >= 10:
        return "Critical+"
    elif raw_risk_score >= 8:
        return "High"
    elif raw_risk_score >= 5:
        return "Medium"
    elif raw_risk_score >= 3:
        return "Low"
    else:
        return "Informational"


def update_enrichment_status(finding):
    extra_sources = set(getattr(finding, "enrichment_sources", []) or []) - {"scanner"}
    if finding.exploit_available or (finding.epss_score is not None) or finding.cisa_kev or bool(extra_sources):
        finding.enriched = True
    else:
        finding.enriched = False


def _normalize_confidence_policy(policy: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    merged = {
        "model_version": DEFAULT_ENRICHMENT_CONFIDENCE_POLICY["model_version"],
        "max_score": int(DEFAULT_ENRICHMENT_CONFIDENCE_POLICY["max_score"]),
        "base_scanner": int(DEFAULT_ENRICHMENT_CONFIDENCE_POLICY["base_scanner"]),
        "weights": dict(DEFAULT_ENRICHMENT_CONFIDENCE_POLICY["weights"]),
        "ghsa_signals": dict(DEFAULT_ENRICHMENT_CONFIDENCE_POLICY["ghsa_signals"]),
    }

    if not isinstance(policy, dict):
        return merged

    model_version = policy.get("model_version")
    if isinstance(model_version, str) and model_version.strip():
        merged["model_version"] = model_version.strip()

    max_score = policy.get("max_score")
    if isinstance(max_score, int):
        merged["max_score"] = max(0, min(100, max_score))

    base_scanner = policy.get("base_scanner")
    if isinstance(base_scanner, int):
        merged["base_scanner"] = max(0, min(100, base_scanner))

    weights = policy.get("weights")
    if isinstance(weights, dict):
        for key in ("nvd", "kev", "epss", "exploitdb", "ghsa", "osv"):
            val = weights.get(key)
            if isinstance(val, int):
                merged["weights"][key] = max(0, min(100, val))

    ghsa_signals = policy.get("ghsa_signals")
    if isinstance(ghsa_signals, dict):
        for key in ("advisory_confidence_bonus", "max_advisory_confidence_bonus", "exploit_signal_confidence_bonus"):
            val = ghsa_signals.get(key)
            if isinstance(val, int):
                merged["ghsa_signals"][key] = max(0, min(100, val))
        exploit_signal = ghsa_signals.get("exploit_signal_on_high_severity")
        if isinstance(exploit_signal, bool):
            merged["ghsa_signals"]["exploit_signal_on_high_severity"] = exploit_signal

    return merged


def _ghsa_high_severity_exploit_signal(advisories: List[Dict[str, Any]]) -> bool:
    for advisory in advisories:
        if not isinstance(advisory, dict):
            continue
        if advisory.get("withdrawn_at"):
            continue
        severity = advisory.get("severity")
        if not isinstance(severity, str):
            database_specific = advisory.get("database_specific")
            if isinstance(database_specific, dict):
                severity = database_specific.get("severity")
        if isinstance(severity, str) and severity.strip().upper() in {"HIGH", "CRITICAL"}:
            return True
    return False


def _ghsa_max_severity(advisories: List[Dict[str, Any]]) -> Optional[str]:
    ranks = {
        "LOW": 1,
        "MODERATE": 2,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }
    best: Optional[str] = None
    best_rank = -1

    for advisory in advisories:
        if not isinstance(advisory, dict):
            continue
        severity = advisory.get("severity")
        if not isinstance(severity, str):
            database_specific = advisory.get("database_specific")
            if isinstance(database_specific, dict):
                severity = database_specific.get("severity")
        if not isinstance(severity, str):
            continue
        normalized = severity.strip().upper()
        rank = ranks.get(normalized, 0)
        if rank > best_rank:
            best_rank = rank
            best = normalized

    return best


def _score_confidence_from_sources(
    sources: List[str],
    policy: Dict[str, Any],
    *,
    ghsa_advisory_count: int = 0,
    ghsa_exploit_signal: bool = False,
) -> tuple[int, Dict[str, int]]:
    evidence: Dict[str, int] = {}
    total = 0

    if "scanner" in sources:
        base = int(policy.get("base_scanner", DEFAULT_ENRICHMENT_CONFIDENCE_POLICY["base_scanner"]))
        evidence["base_scanner"] = base
        total += base

    weights = policy.get("weights", {})
    for src in ("nvd", "kev", "epss", "exploitdb", "ghsa", "osv"):
        if src in sources:
            weight = int(weights.get(src, 0)) if isinstance(weights, dict) else 0
            evidence[src] = weight
            total += weight

    ghsa_signals = policy.get("ghsa_signals", {})
    if "ghsa" in sources and ghsa_advisory_count > 0 and isinstance(ghsa_signals, dict):
        bonus_each = int(ghsa_signals.get("advisory_confidence_bonus", 0))
        bonus_cap = int(ghsa_signals.get("max_advisory_confidence_bonus", 0))
        ghsa_bonus = max(0, min(bonus_cap, ghsa_advisory_count * max(0, bonus_each)))
        if ghsa_bonus > 0:
            evidence["ghsa_bonus"] = ghsa_bonus
            total += ghsa_bonus

    if ghsa_exploit_signal and isinstance(ghsa_signals, dict):
        exploit_bonus = max(0, int(ghsa_signals.get("exploit_signal_confidence_bonus", 0)))
        if exploit_bonus > 0:
            evidence["ghsa_exploit_signal"] = exploit_bonus
            total += exploit_bonus

    max_score = int(policy.get("max_score", 100))
    final_score = min(max_score, max(0, total))
    evidence["max_score"] = max_score
    evidence["final"] = final_score
    return final_score, evidence


def _apply_enrichment_metadata(
    finding: Finding,
    *,
    nvd_hit: bool,
    ghsa_hit: bool,
    ghsa_advisory_count: int,
    ghsa_exploit_signal: bool,
    confidence_policy: Dict[str, Any],
    osv_hit: bool = False,
    verified_exploit: Optional[bool] = None,
) -> None:
    sources: set[str] = set()

    # Scanner is the baseline signal when parser-derived finding context exists.
    if getattr(finding, "vuln_id", None) or getattr(finding, "title", None):
        sources.add("scanner")

    if getattr(finding, "cisa_kev", False):
        sources.add("kev")
    if getattr(finding, "epss_score", None) is not None:
        sources.add("epss")
    is_verified_exploit = (
        bool(verified_exploit)
        if verified_exploit is not None
        else (
            bool(getattr(finding, "verified_exploit", False))
            or bool(getattr(finding, "exploit_references", None))
        )
    )
    if is_verified_exploit:
        sources.add("exploitdb")
    if nvd_hit:
        sources.add("nvd")
    if ghsa_hit:
        sources.add("ghsa")
    if osv_hit:
        sources.add("osv")

    sorted_sources = sorted(sources)
    finding.enrichment_sources = sorted_sources
    score, evidence = _score_confidence_from_sources(
        sorted_sources,
        confidence_policy,
        ghsa_advisory_count=ghsa_advisory_count,
        ghsa_exploit_signal=ghsa_exploit_signal,
    )
    finding.confidence = score
    finding.confidence_evidence = evidence


def _merge_ghsa_references(finding: Finding, advisories: List[Dict[str, Any]]) -> None:
    existing = list(getattr(finding, "references", []) or [])
    out: List[str] = [str(r) for r in existing if isinstance(r, str)]

    for advisory in advisories:
        if not isinstance(advisory, dict):
            continue

        primary_ref = advisory.get("html_url") or advisory.get("url")
        if isinstance(primary_ref, str) and primary_ref:
            out.append(primary_ref)

        for ref in advisory.get("references", []) or []:
            if isinstance(ref, str) and ref:
                out.append(ref)
            elif isinstance(ref, dict):
                ref_url = ref.get("url")
                if isinstance(ref_url, str) and ref_url:
                    out.append(ref_url)

    # Preserve order while deduping.
    finding.references = list(dict.fromkeys(out))


def _extract_package_tokens_for_finding(finding: Finding) -> set[str]:
    fields = [
        finding.title or "",
        finding.description or "",
        finding.solution or "",
        finding.detection_plugin or "",
        finding.plugin_output or "",
        getattr(finding, "package_purl", None) or "",
    ]
    text = "\n".join(fields)
    return {tok.lower() for tok in PKG_TOKEN_RE.findall(text)}

def prefer_vector(vectors):
    order = {"CVSS:3.1": 1, "CVSS:3.0": 2, "CVSS:2.0": 3}
    def rank(v):
        for prefix, score in order.items():
            if v.startswith(prefix):
                return score
        return 99
    return sorted(vectors, key=rank)[0]

def log_finding_summary(logger, finding: Finding):
    severity = finding.risk_band
    sev_label = colorize(severity, SEVERITY_COLOR.get(severity, "white")) # type: ignore
    msg = (
        f"[RiskCalc] "
        f"{sev_label} "
        f"Asset={finding.asset_id}; "
        f"Finding={finding.title}; "
        f"CVE={getattr(finding, 'enrichment_source_cve', None) or 'SENTINEL(No_CVE_Listed)'}; "
        f"Score={(getattr(finding, 'risk_score', None))}; "
        f"Band={getattr(finding, 'risk_band', 'N/A')}; "
        f"Triage={getattr(finding, 'triage_priority', 'N/A')}; "
        f"KEV={bool(getattr(finding, 'cisa_kev', False))}; "
        f"Exploit={bool(getattr(finding, 'exploit_available', False))}"
    )
    logger.debug(msg)

_CVSS_VERSION_RANK = {"4.0": 0, "3.1": 1, "3.0": 2, "2.0": 3}


def _parse_valid_cvss_score(raw: Any) -> Optional[float]:
    if raw is None or isinstance(raw, bool):
        return None
    try:
        val = float(raw)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(val) or val < 0.0 or val > 10.0:
        return None
    return val


def _extract_advisory_cvss(advisories: Optional[List[Dict[str, Any]]]) -> Tuple[Optional[float], Optional[str], Optional[str]]:
    """
    Extract best (score, vector, cvss_version) from GHSA/OSV advisory dicts,
    computing base score via clean-room cvss_utils whenever a vector exists without score.
    """
    if not advisories:
        return None, None, None

    best_rank = (99, 1)
    best: Tuple[Optional[float], Optional[str], Optional[str]] = (None, None, None)

    def _consider(vector: Optional[str], score_raw: Any) -> None:
        nonlocal best_rank, best
        vec = vector.strip() if isinstance(vector, str) and vector.strip() else None
        score: Optional[float] = _parse_valid_cvss_score(score_raw)
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

    for adv in advisories:
        if not isinstance(adv, dict) or adv.get("withdrawn_at"):
            continue
        sev = adv.get("severity")
        if isinstance(sev, list):
            for entry in sev:
                if isinstance(entry, dict):
                    _consider(entry.get("score"), None)
        cvss_sevs = adv.get("cvss_severities")
        if isinstance(cvss_sevs, dict):
            for key in ("cvss_v4", "cvss_v3", "cvss_v2"):
                item = cvss_sevs.get(key)
                if isinstance(item, dict):
                    _consider(item.get("vector_string") or item.get("vectorString"), item.get("score"))
        cvss_obj = adv.get("cvss")
        if isinstance(cvss_obj, dict):
            _consider(cvss_obj.get("vector_string") or cvss_obj.get("vectorString"), cvss_obj.get("score") or cvss_obj.get("baseScore"))
        _consider(adv.get("cvss_vector"), adv.get("cvss_score"))
        db_spec = adv.get("database_specific")
        if isinstance(db_spec, dict) and isinstance(db_spec.get("cvss"), dict):
            db_cvss = db_spec["cvss"]
            _consider(db_cvss.get("vectorString") or db_cvss.get("vector_string"), db_cvss.get("score") or db_cvss.get("baseScore"))

    return best


def _extract_advisory_ids(advisories: Optional[List[Dict[str, Any]]]) -> List[str]:
    out: List[str] = []
    for adv in advisories or []:
        if not isinstance(adv, dict):
            continue
        aid = adv.get("id") or adv.get("ghsa_id") or adv.get("osv_id")
        if isinstance(aid, str) and aid.strip():
            out.append(aid.strip())
    return list(dict.fromkeys(out))


def resolve_cvss_with_provenance(
    ctx: Optional["RunContext"],
    *,
    scanner_vector: Optional[str] = None,
    scanner_score: Optional[float] = None,
    auth_cve: Optional[str] = None,
    nvd_record: Optional[Dict[str, Any]] = None,
    nvd_cache: Optional[Any] = None,
    ghsa_advisories: Optional[List[Dict[str, Any]]] = None,
    osv_advisories: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Unified CVSS resolver enforcing precedence:
    NVD > CNA > GHSA > OSV > Scanner-Supplied > Missing.
    Computes base scores via clean-room cvss_utils whenever a vector exists without a score.
    """
    has_real_cve = bool(auth_cve and not str(auth_cve).startswith("SENTINEL:") and _is_valid_cve_id(str(auth_cve)))

    if nvd_record is None and nvd_cache is not None and has_real_cve:
        nvd_record = nvd_cache.get(str(auth_cve).strip().upper())

    # 1 & 2. NVD vs CNA
    if isinstance(nvd_record, dict) and nvd_record.get("found", True) is not False:
        nvd_vec = nvd_record.get("cvss_vector")
        nvd_score_raw = nvd_record.get("cvss_score")
        raw_prov = str(nvd_record.get("cvss_provenance") or "").strip()
        if raw_prov in ("NVD", "CNA"):
            prov = raw_prov
        else:
            src_id = str(nvd_record.get("source_identifier") or "").lower()
            prov = "CNA" if (src_id and "nvd@nist.gov" not in src_id) else "NVD"

        if isinstance(nvd_vec, str) and is_valid_cvss_vector(nvd_vec.strip()):
            vec_clean = nvd_vec.strip()
            score_val = compute_cvss_base_score(vec_clean)
            if score_val is None:
                score_val = _parse_valid_cvss_score(nvd_score_raw)
            ver = nvd_record.get("cvss_version") or detect_cvss_exact_version(vec_clean)
            return {
                "cvss_vector": vec_clean,
                "resolved_vector": vec_clean,
                "cvss_score": score_val,
                "cvss_provenance": prov,
                "cvss_version": ver,
                "cvss_source": "nvd_vector" if prov == "NVD" else "cna_vector",
            }
        score_val = _parse_valid_cvss_score(nvd_score_raw)
        if score_val is not None:
            return {
                "cvss_vector": f"SENTINEL:ScoreOnly:{score_val}",
                "resolved_vector": None,
                "cvss_score": score_val,
                "cvss_provenance": prov,
                "cvss_version": nvd_record.get("cvss_version"),
                "cvss_source": "nvd_score" if prov == "NVD" else "cna_score",
            }

    # 3. GHSA
    ghsa_score, ghsa_vec, ghsa_ver = _extract_advisory_cvss(ghsa_advisories)
    if ghsa_vec or ghsa_score is not None:
        return {
            "cvss_vector": ghsa_vec or f"SENTINEL:ScoreOnly:{ghsa_score}",
            "resolved_vector": ghsa_vec,
            "cvss_score": ghsa_score,
            "cvss_provenance": "GHSA",
            "cvss_version": ghsa_ver,
            "cvss_source": "ghsa_vector" if ghsa_vec else "ghsa_score",
        }

    # 4. OSV
    osv_score, osv_vec, osv_ver = _extract_advisory_cvss(osv_advisories)
    if osv_vec or osv_score is not None:
        return {
            "cvss_vector": osv_vec or f"SENTINEL:ScoreOnly:{osv_score}",
            "resolved_vector": osv_vec,
            "cvss_score": osv_score,
            "cvss_provenance": "OSV",
            "cvss_version": osv_ver,
            "cvss_source": "osv_vector" if osv_vec else "osv_score",
        }

    # 5. Scanner-Supplied
    if isinstance(scanner_vector, str) and is_valid_cvss_vector(scanner_vector.strip()):
        vec_clean = scanner_vector.strip()
        score_val = compute_cvss_base_score(vec_clean)
        if score_val is None:
            score_val = _parse_valid_cvss_score(scanner_score)
        ver = detect_cvss_exact_version(vec_clean)
        return {
            "cvss_vector": vec_clean,
            "resolved_vector": vec_clean,
            "cvss_score": score_val,
            "cvss_provenance": "Scanner-Supplied",
            "cvss_version": ver,
            "cvss_source": "scanner_vector",
        }
    score_val = _parse_valid_cvss_score(scanner_score)
    if score_val is not None:
        return {
            "cvss_vector": f"SENTINEL:ScoreOnly:{score_val}",
            "resolved_vector": None,
            "cvss_score": score_val,
            "cvss_provenance": "Scanner-Supplied",
            "cvss_version": None,
            "cvss_source": "scanner_score",
        }

    # 6. Missing
    return {
        "cvss_vector": "SENTINEL:Attempted_NotFound" if has_real_cve else "SENTINEL:NoCVE",
        "resolved_vector": None,
        "cvss_score": None,
        "cvss_provenance": "Missing",
        "cvss_version": None,
        "cvss_source": None,
    }


def resolve_cvss_vector(
    ctx: "RunContext",
    scanner_vector: Optional[str],
    auth_cve: Optional[str],
    nvd_cache: Any,
    current_score: float = 0.0,
    *,
    ghsa_advisories: Optional[List[Dict[str, Any]]] = None,
    osv_advisories: Optional[List[Dict[str, Any]]] = None,
    scanner_score: Optional[float] = None,
) -> Tuple[str, float]:
    """
    Resolve a CVSS vector & base score using unified precedence:
    NVD > CNA > GHSA > OSV > Scanner-Supplied > Missing.
    """
    run_stats = _get_stats(ctx)

    if not auth_cve or str(auth_cve).startswith("SENTINEL:"):
        run_stats.cvss_no_cve_skipped += 1
        if run_stats.cvss_no_cve_skipped <= 3 and getattr(ctx, "logger", None) is not None:
            ctx.logger.warning("[CVSSVector] Skipping CVSS resolution because no real CVE is associated with this finding.")
        return "SENTINEL:NoCVE", current_score

    effective_scanner_score = _parse_valid_cvss_score(scanner_score)
    if effective_scanner_score is None:
        parsed_cur = _parse_valid_cvss_score(current_score)
        if parsed_cur is not None and parsed_cur > 0.0:
            effective_scanner_score = parsed_cur

    resolved = resolve_cvss_with_provenance(
        ctx,
        scanner_vector=scanner_vector,
        scanner_score=effective_scanner_score,
        auth_cve=auth_cve,
        nvd_cache=nvd_cache,
        ghsa_advisories=ghsa_advisories,
        osv_advisories=osv_advisories,
    )

    prov = resolved["cvss_provenance"]
    ver = resolved["cvss_version"]
    vec = resolved["cvss_vector"]
    score = resolved["cvss_score"]

    if prov in ("NVD", "CNA"):
        if str(vec).startswith("SENTINEL:ScoreOnly:"):
            run_stats.cvss_score_only += 1
        else:
            run_stats.cvss_nvd_fallback += 1
    elif prov == "Scanner-Supplied":
        if ver in ("3.0", "3.1", "4.0"):
            run_stats.cvss_scanner_v3_used += 1
        elif ver == "2.0":
            run_stats.cvss_scanner_v2_used += 1
        else:
            run_stats.cvss_score_only += 1
    elif prov == "Missing":
        run_stats.cvss_not_found += 1

    return vec, (score if score is not None else current_score)


def enrich_scan_results(
    ctx: "RunContext",
    results: ScanResult,
    kev_data: Optional[Dict[str, Any]] = None,
    epss_data: Optional[Dict[str, Any]] = None,
    ghsa_data: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    ghsa_package_data: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    offline_mode: bool = False,
    nvd_cache: Optional[Any] = None,
    confidence_policy: Optional[Dict[str, Any]] = None,
    osv_data: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    osv_package_data: Optional[Dict[str, List[Dict[str, Any]]]] = None,
) -> None:  # type: ignore
    """
    Enrich the findings in a ScanResult object with EPSS v5 (prob + percentile),
    CISA KEV metadata, NVD/CNA/GHSA/OSV CVSS provenance, and verified Exploit-DB
    availability (strictly decoupled from CISA KEV and heuristic text mentions).
    """
    run_stats = _get_stats(ctx)
    miss_logger = EnrichmentMissLogger(ctx)
    normalized_confidence_policy = _normalize_confidence_policy(confidence_policy)
    ghsa_signal_policy = normalized_confidence_policy.get("ghsa_signals", {})

    baseline_risk_count = 0

    kev_lookup: Dict[str, bool] = {}
    kev_records: Dict[str, Dict[str, Any]] = {}
    raw_kev_records = getattr(kev_data, "records", None)
    if isinstance(raw_kev_records, dict):
        for cve, rec in raw_kev_records.items():
            c_up = str(cve).strip().upper()
            kev_lookup[c_up] = True
            if isinstance(rec, dict):
                kev_records[c_up] = rec
    for cve, val in (kev_data or {}).items():
        c_up = str(cve).strip().upper()
        if isinstance(val, dict):
            kev_lookup[c_up] = True
            kev_records.setdefault(c_up, val)
        else:
            kev_lookup[c_up] = bool(val)

    epss_lookup: Dict[str, float] = {}
    epss_percentiles: Dict[str, Optional[float]] = {}
    epss_records_map: Dict[str, Dict[str, Any]] = {}
    epss_model_version: Optional[str] = getattr(epss_data, "model_version", None)
    epss_date: Optional[str] = getattr(epss_data, "score_date", None)

    raw_epss_pcts = getattr(epss_data, "percentiles", None)
    if isinstance(raw_epss_pcts, dict):
        for cve, pct in raw_epss_pcts.items():
            pct_val = _parse_bounded_prob(pct, allow_percent=True)
            if pct_val is not None:
                epss_percentiles[str(cve).strip().upper()] = pct_val
    raw_epss_recs = getattr(epss_data, "records", None)
    if isinstance(raw_epss_recs, dict):
        for cve, rec in raw_epss_recs.items():
            if isinstance(rec, dict):
                epss_records_map[str(cve).strip().upper()] = rec

    for cve, score in (epss_data or {}).items():
        c_up = str(cve).strip().upper()
        if isinstance(score, dict):
            s_raw = score.get("epss_score") if score.get("epss_score") is not None else score.get("epss")
            s_val = _parse_bounded_prob(s_raw, allow_percent=False)
            if s_val is None:
                continue
            epss_lookup[c_up] = s_val
            pct = score.get("epss_percentile") if score.get("epss_percentile") is not None else score.get("percentile")
            pct_val = _parse_bounded_prob(pct, allow_percent=True)
            if pct_val is not None:
                epss_percentiles[c_up] = pct_val
            epss_records_map.setdefault(c_up, score)
        else:
            s_val = _parse_bounded_prob(score, allow_percent=False)
            if s_val is not None:
                epss_lookup[c_up] = s_val

    nvd_get = getattr(nvd_cache, "get", None) if nvd_cache is not None else None
    ghsa_lookup: Dict[str, List[Dict[str, Any]]] = {}
    for cve, advisories in (ghsa_data or {}).items():
        key = str(cve).upper().strip()
        if key and isinstance(advisories, list):
            ghsa_lookup[key] = advisories

    ghsa_pkg_lookup: Dict[str, List[Dict[str, Any]]] = {}
    for package_name, advisories in (ghsa_package_data or {}).items():
        key = str(package_name).strip().lower()
        if key and isinstance(advisories, list):
            ghsa_pkg_lookup[key] = advisories

    osv_lookup: Dict[str, List[Dict[str, Any]]] = {}
    for cve, advisories in (osv_data or {}).items():
        key = str(cve).upper().strip()
        if key and isinstance(advisories, list):
            osv_lookup[key] = advisories

    osv_pkg_lookup: Dict[str, List[Dict[str, Any]]] = {}
    for package_name, advisories in (osv_package_data or {}).items():
        key = str(package_name).strip().lower()
        if key and isinstance(advisories, list):
            osv_pkg_lookup[key] = advisories

    nvd_record_cache: Dict[str, Any] = {}
    no_record = object()

    finding_counter = 0

    for asset in results.assets:
        for finding in asset.findings:
            finding_counter += 1
            scanner_cvss_score = getattr(finding, "cvss_score", None)
            scanner_cvss_vector = getattr(finding, "cvss_vector", None)
            heuristic_mention = bool(getattr(finding, "heuristic_exploit_mention", False))
            preexisting_verified = bool(getattr(finding, "verified_exploit", False)) or (
                bool(getattr(finding, "exploit_available", False)) and not heuristic_mention
            )

            enrichment_attempted = False
            any_kev_hit = False
            any_epss_hit = False
            any_nvd_hit = False
            any_ghsa_hit = False
            any_osv_hit = False
            ghsa_advisory_count = 0
            ghsa_exploit_signal = False
            enrichment_map: Dict[str, Dict[str, Any]] = {}
            cve_analysis: List[Dict[str, Any]] = []

            cves: List[str] = []
            for raw_cve in getattr(finding, "cves", []) or []:
                cve_upper = str(raw_cve).upper().strip()
                if CVE_RE.match(cve_upper):
                    cves.append(cve_upper)

            if cves:
                enrichment_attempted = True
                run_stats.total_cves += len(cves)

                for cve in cves:
                    exploit_refs = [
                        ref
                        for ref in (getattr(finding, "exploit_references", []) or [])
                        if isinstance(ref, dict) and str(ref.get("cve", "")).upper().strip() == cve
                    ]
                    cve_verified_exploit = bool(exploit_refs) or preexisting_verified

                    kev_hit = kev_lookup.get(cve, False)
                    kev_rec = kev_records.get(cve, {}) if kev_hit else {}
                    if kev_hit:
                        run_stats.kev_hits += 1
                        any_kev_hit = True
                    else:
                        miss_logger.log_miss(cve, cisa_kev=False, epss_score=None)

                    epss_score = epss_lookup.get(cve)
                    epss_pct = epss_percentiles.get(cve)
                    epss_rec = epss_records_map.get(cve, {})
                    cve_epss_mv = epss_rec.get("model_version") or epss_model_version
                    cve_epss_dt = epss_rec.get("score_date") or epss_date
                    if epss_score is None:
                        run_stats.epss_misses += 1
                        miss_logger.log_miss(cve, cisa_kev=kev_hit, epss_score=None)
                    else:
                        any_epss_hit = True

                    ghsa_advisories = ghsa_lookup.get(cve, [])
                    ghsa_hit = len(ghsa_advisories) > 0
                    if ghsa_hit:
                        any_ghsa_hit = True
                        ghsa_advisory_count += len(ghsa_advisories)
                        ghsa_exploit_signal = ghsa_exploit_signal or _ghsa_high_severity_exploit_signal(ghsa_advisories)

                    osv_advisories = osv_lookup.get(cve, [])
                    osv_hit = len(osv_advisories) > 0
                    if osv_hit:
                        any_osv_hit = True

                    record = None
                    if nvd_get is not None:
                        record = nvd_record_cache.get(cve, no_record)
                        if record is no_record:
                            record = nvd_get(cve)
                            nvd_record_cache[cve] = record
                        if isinstance(record, dict) and record.get("found", True) is not False and (
                            record.get("cvss_vector") or _parse_valid_cvss_score(record.get("cvss_score")) is not None
                        ):
                            any_nvd_hit = True

                    resolved_cvss = resolve_cvss_with_provenance(
                        ctx,
                        scanner_vector=scanner_cvss_vector,
                        scanner_score=scanner_cvss_score,
                        auth_cve=cve,
                        nvd_record=record if (record and record is not no_record) else None,
                        ghsa_advisories=ghsa_advisories,
                        osv_advisories=osv_advisories,
                    )

                    nvd_summary = None
                    nvd_published = None
                    nvd_last_modified = None
                    if record and record is not no_record and record.get("found", True) is not False:
                        nvd_summary = record.get("description")
                        nvd_published = record.get("published")
                        nvd_last_modified = record.get("last_modified")

                    cve_analysis.append({
                        "cve_id": cve,
                        "scanner_cvss_score": scanner_cvss_score,
                        "scanner_cvss_vector": scanner_cvss_vector,
                        "resolved_cvss_score": resolved_cvss["cvss_score"],
                        "resolved_cvss_vector": resolved_cvss["resolved_vector"],
                        "cvss_version": resolved_cvss["cvss_version"],
                        "cvss_provenance": resolved_cvss["cvss_provenance"],
                        "cvss_source": resolved_cvss["cvss_source"],
                        "summary": nvd_summary,
                        "published": nvd_published,
                        "last_modified": nvd_last_modified,
                        "epss_score": epss_score,
                        "epss_percentile": epss_pct,
                        "epss_model_version": cve_epss_mv,
                        "epss_date": cve_epss_dt,
                        "cisa_kev": kev_hit,
                        "kev_date_added": kev_rec.get("date_added") if kev_hit else None,
                        "kev_due_date": kev_rec.get("due_date") if kev_hit else None,
                        "kev_ransomware": bool(kev_rec.get("known_ransomware", False)) if kev_hit else False,
                        "kev_required_action": kev_rec.get("required_action") if kev_hit else None,
                        "kev_vulnerability_name": kev_rec.get("vulnerability_name") if kev_hit else None,
                        "exploit_available": cve_verified_exploit,
                        "verified_exploit": cve_verified_exploit,
                        "heuristic_exploit_mention": heuristic_mention,
                        "exploit_reference_count": len(exploit_refs),
                        "ghsa_advisory_count": len(ghsa_advisories),
                        "ghsa_max_severity": _ghsa_max_severity(ghsa_advisories),
                        "ghsa_match_type": "cve" if ghsa_hit else None,
                        "ghsa_ids": _extract_advisory_ids(ghsa_advisories),
                        "osv_advisory_count": len(osv_advisories),
                        "osv_ids": _extract_advisory_ids(osv_advisories),
                        "selected_for_display": False,
                    })

                    enrichment_map[cve] = {
                        "epss_score": epss_score,
                        "epss_percentile": epss_pct,
                        "cisa_kev": kev_hit,
                        "exploit_available": cve_verified_exploit,
                        "cvss_score": resolved_cvss["cvss_score"],
                        "cvss_vector": resolved_cvss["resolved_vector"],
                        "cvss_provenance": resolved_cvss["cvss_provenance"],
                        "cvss_version": resolved_cvss["cvss_version"],
                        "ghsa_advisories": ghsa_advisories,
                        "osv_advisories": osv_advisories,
                        "resolved_cvss": resolved_cvss,
                    }

                finding.cve_analysis = cve_analysis
                authoritative_cve = select_authoritative_cve(cves, enrichment_map)
                if authoritative_cve:
                    for entry in finding.cve_analysis:
                        if isinstance(entry, dict) and entry.get("cve_id") == authoritative_cve:
                            entry["selected_for_display"] = True
                    best = enrichment_map[authoritative_cve]
                    epss_c = best.get("epss_score")
                    finding.epss_score = epss_c if epss_c is not None else None
                    finding.epss_percentile = best.get("epss_percentile")
                    finding.cisa_kev = bool(best.get("cisa_kev", False) or any(v.get("cisa_kev", False) for v in enrichment_map.values()))

                    auth_ghsa = best.get("ghsa_advisories", []) or []
                    auth_osv = best.get("osv_advisories", []) or []
                    finding.cvss_vector, resolved_score = resolve_cvss_vector(
                        ctx,
                        scanner_vector=scanner_cvss_vector,
                        auth_cve=authoritative_cve,
                        nvd_cache=nvd_cache,
                        current_score=scanner_cvss_score if scanner_cvss_score is not None else 0.0,
                        ghsa_advisories=auth_ghsa,
                        osv_advisories=auth_osv,
                        scanner_score=scanner_cvss_score,
                    )
                    auth_cvss = best.get("resolved_cvss", {})
                    finding.cvss_score = auth_cvss.get("cvss_score") if auth_cvss.get("cvss_score") is not None else (
                        resolved_score if auth_cvss.get("cvss_provenance") != "Missing" else scanner_cvss_score
                    )
                    finding.cvss_provenance = auth_cvss.get("cvss_provenance", "Missing")
                    finding.cvss_version = auth_cvss.get("cvss_version")

                    # Keep CISA KEV, Exploit-DB verified exploits, and heuristic text mentions strictly independent.
                    exploit_flag = any(v.get("exploit_available", False) for v in enrichment_map.values())
                    finding.verified_exploit = bool(getattr(finding, "exploit_references", None)) or exploit_flag
                    finding.exploit_available = finding.verified_exploit
                    finding.enrichment_source_cve = authoritative_cve

                    if auth_ghsa:
                        _merge_ghsa_references(finding, auth_ghsa)
                        if (
                            bool(ghsa_signal_policy.get("exploit_signal_on_high_severity", False))
                            and ghsa_exploit_signal
                        ):
                            finding.exploit_available = True
                    if auth_osv:
                        _merge_ghsa_references(finding, auth_osv)
            else:
                non_cve_cvss = resolve_cvss_with_provenance(
                    ctx,
                    scanner_vector=scanner_cvss_vector,
                    scanner_score=scanner_cvss_score,
                    auth_cve=None,
                )
                finding.cvss_provenance = non_cve_cvss["cvss_provenance"]
                finding.cvss_version = non_cve_cvss["cvss_version"]
                finding.verified_exploit = preexisting_verified
                finding.exploit_available = preexisting_verified

            if (not any_ghsa_hit) and ghsa_pkg_lookup:
                matched: List[Dict[str, Any]] = []
                seen_ids: set[str] = set()
                for token in _extract_package_tokens_for_finding(finding):
                    for advisory in ghsa_pkg_lookup.get(token, []):
                        aid = str(advisory.get("id") or advisory.get("ghsa_id") or "")
                        if aid and aid in seen_ids:
                            continue
                        if aid:
                            seen_ids.add(aid)
                        matched.append(advisory)

                if matched:
                    any_ghsa_hit = True
                    ghsa_advisory_count += len(matched)
                    ghsa_exploit_signal = ghsa_exploit_signal or _ghsa_high_severity_exploit_signal(matched)
                    _merge_ghsa_references(finding, matched)
                    if (
                        bool(ghsa_signal_policy.get("exploit_signal_on_high_severity", False))
                        and ghsa_exploit_signal
                    ):
                        finding.exploit_available = True

            if (not any_osv_hit) and osv_pkg_lookup:
                osv_matched: List[Dict[str, Any]] = []
                seen_osv_ids: set[str] = set()
                for token in _extract_package_tokens_for_finding(finding):
                    for advisory in osv_pkg_lookup.get(token, []):
                        aid = str(advisory.get("id") or "")
                        if aid and aid in seen_osv_ids:
                            continue
                        if aid:
                            seen_osv_ids.add(aid)
                        osv_matched.append(advisory)
                if osv_matched:
                    any_osv_hit = True
                    _merge_ghsa_references(finding, osv_matched)

            if finding.cvss_vector and not str(finding.cvss_vector).startswith("SENTINEL:"):
                run_stats.cvss_vectors_assigned += 1
                run_stats.cvss_vectors_validated += 1

            cvss = finding.cvss_score or -1.0
            if cvss == 0.0 and (finding.exploit_available or finding.severity in ["Critical", "High"]):
                baseline_risk_count += 1

            finding.raw_risk_score = None
            finding.risk_score = None
            finding.risk_band = None

            finding.enriched = enrichment_attempted and (
                any_kev_hit or
                any_epss_hit or
                any_ghsa_hit or
                any_osv_hit or
                bool(getattr(finding, "verified_exploit", False)) or
                bool(finding.exploit_available)
            )

            _apply_enrichment_metadata(
                finding,
                nvd_hit=any_nvd_hit,
                ghsa_hit=any_ghsa_hit,
                ghsa_advisory_count=ghsa_advisory_count,
                ghsa_exploit_signal=ghsa_exploit_signal,
                confidence_policy=normalized_confidence_policy,
                osv_hit=any_osv_hit,
                verified_exploit=bool(getattr(finding, "verified_exploit", False)),
            )

            if finding_counter <= 20 or finding_counter % 100000 == 0:
                log_finding_summary(ctx.logger, finding)

        asset.avg_risk_score = None

    print("="*25 + "[Enrichment Summary]" + "="*25)
    ctx.logger.print_info(f"   Total CVEs Processed : {run_stats.total_cves:,}")
    ctx.logger.print_info(f"   Total CISA KEV Hits : {run_stats.kev_hits:,}")
    ctx.logger.print_info(f"   Total CVSS Vectors Assigned : {run_stats.cvss_vectors_assigned:,}")
    ctx.logger.print_info(f"   Total CVSS Vectors Validated : {run_stats.cvss_vectors_validated:,}")
    ctx.logger.print_info(f"   Total EPSS Misses : {run_stats.epss_misses:,}")
    ctx.logger.print_info(f"   Total Findings Rx Baseline Risk Adjustment: {baseline_risk_count:,}")

    total_cvss_resolutions = (
        run_stats.cvss_scanner_v3_used + run_stats.cvss_scanner_v2_used +
        run_stats.cvss_nvd_fallback + run_stats.cvss_score_only +
        run_stats.cvss_not_found + run_stats.cvss_no_cve_skipped
    )
    if total_cvss_resolutions > 0:
        ctx.logger.print_info("   CVSSVector Resolution Summary:")
        ctx.logger.print_info(f"      Scanner V3: {run_stats.cvss_scanner_v3_used:,} | Scanner V2: {run_stats.cvss_scanner_v2_used:,}")
        ctx.logger.print_info(f"      NVD Fallback: {run_stats.cvss_nvd_fallback:,} | Score Only: {run_stats.cvss_score_only:,}")
        ctx.logger.print_info(f"      Not Found: {run_stats.cvss_not_found:,} | No CVE: {run_stats.cvss_no_cve_skipped:,}")
        if run_stats.cvss_parse_errors > 0:
            ctx.logger.print_info(f"      Parse Errors: {run_stats.cvss_parse_errors:,} (check ERROR logs)")

    print("="*25 + "[Enrichment Summary End]" + "="*25)

    miss_logger.write_log()
