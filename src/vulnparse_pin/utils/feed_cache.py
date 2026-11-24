# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations
import contextlib
from typing import TYPE_CHECKING, Dict, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import gzip
from pathlib import Path
import json
import hashlib
import hmac
import os
import stat
from urllib.parse import urljoin, urlsplit

import requests
from vulnparse_pin import UA

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext
    from vulnparse_pin.core.classes.dataclass import FeedCachePolicy
    from vulnparse_pin.core.classes.dataclass import FeedSpec

MAX_REMOTE_FEED_BYTES = 200 * 1024 * 1024
MAX_DECOMPRESSED_FEED_BYTES = 2 * 1024 * 1024 * 1024
MAX_NVD_META_BYTES = 1024 * 1024


class FeedChecksumError(RuntimeError):
    """Raised when feed checksum or integrity validation fails closed."""


class _BoundedReadStream:
    """Stream wrapper enforcing an upper bound on compressed network bytes read."""

    def __init__(self, raw_stream: Any, max_bytes: Optional[int], label: str) -> None:
        self._raw = raw_stream
        self._max_bytes = max_bytes
        self._label = label
        self._bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        data = self._raw.read(size)
        if data:
            self._bytes_read += len(data)
            if self._max_bytes is not None and self._bytes_read > self._max_bytes:
                raise RuntimeError(
                    f"{self._label} response exceeds configured size limit. "
                    f"Read={self._bytes_read} bytes, limit={self._max_bytes} bytes."
                )
        return data


def _validate_https_url(url: str, *, label: str) -> str:
    """Validate that a remote feed URL uses HTTPS and includes a network host."""
    cur_url = str(url or "").strip()
    parts = urlsplit(cur_url)
    if parts.scheme.lower() != "https" or not parts.netloc:
        raise RuntimeError(f"{label} request requires HTTPS URL: {cur_url}")
    return cur_url


@contextlib.contextmanager
def _open_https_stream(
    url: str,
    *,
    timeout: int,
    headers: Optional[Dict[str, str]],
    label: str,
    requests_get: Any = None,
    max_redirects: int = 5,
):
    """
    Open an HTTPS streaming response with allow_redirects=False and strict
    per-hop HTTPS validation across redirect hops.
    """
    getter = requests.get if requests_get is None else requests_get
    cur_url = _validate_https_url(url, label=label)
    for _ in range(max_redirects + 1):
        _validate_https_url(cur_url, label=label)
        req_cm = getter(
            cur_url,
            allow_redirects=False,
            stream=True,
            timeout=timeout,
            headers=headers,
        )
        cm = req_cm if hasattr(req_cm, "__enter__") else contextlib.closing(req_cm)
        with cm as resp:
            status_code = getattr(resp, "status_code", None)
            if status_code in (301, 302, 303, 307, 308):
                resp_headers = getattr(resp, "headers", None) or {}
                loc = resp_headers.get("Location") or resp_headers.get("location")
                if not loc:
                    raise RuntimeError(f"{label} redirect missing Location header.")
                next_url = urljoin(cur_url, str(loc).strip())
                parts = urlsplit(next_url)
                if parts.scheme.lower() != "https" or not parts.netloc:
                    raise RuntimeError(f"{label} request redirected to non-HTTPS URL: {next_url}")
                cur_url = next_url
                continue

            resp.raise_for_status()
            final_url = str(getattr(resp, "url", "") or "")
            if final_url:
                final_parts = urlsplit(final_url)
                if final_parts.scheme.lower() != "https" or not final_parts.netloc:
                    raise RuntimeError(f"{label} request redirected to non-HTTPS URL: {final_url}")

            yield resp
            return

    raise RuntimeError(f"{label} exceeded maximum HTTPS redirects ({max_redirects}).")


def stream_https_get_bytes(
    url: str,
    *,
    max_bytes: int,
    timeout: int,
    headers: Optional[Dict[str, str]],
    label: str,
    requests_get: Any = None,
    max_redirects: int = 5,
    chunk_size: int = 1024 * 1024,
) -> bytes:
    """
    Fetch an HTTPS URL using allow_redirects=False (per-hop HTTPS validation)
    and stream=True with bounded byte reads.
    """
    with _open_https_stream(
        url,
        timeout=timeout,
        headers=headers,
        label=label,
        requests_get=requests_get,
        max_redirects=max_redirects,
    ) as resp:
        resp_headers = getattr(resp, "headers", None) or {}
        raw_len = resp_headers.get("Content-Length")
        if raw_len:
            try:
                content_len = int(raw_len)
            except (TypeError, ValueError):
                content_len = None
            if content_len is not None and content_len > max_bytes:
                raise RuntimeError(
                    f"{label} response exceeds configured size limit. "
                    f"Content-Length={content_len} bytes, limit={max_bytes} bytes."
                )

        chunks: list[bytes] = []
        total_read = 0
        iter_content = getattr(resp, "iter_content", None)
        if callable(iter_content):
            for chunk in iter_content(chunk_size=chunk_size):
                if not chunk:
                    continue
                total_read += len(chunk)
                if total_read > max_bytes:
                    raise RuntimeError(
                        f"{label} response exceeds configured size limit. "
                        f"Read={total_read} bytes, limit={max_bytes} bytes."
                    )
                chunks.append(chunk)
            return b"".join(chunks)

        raw_stream = getattr(resp, "raw", None)
        if raw_stream is not None and callable(getattr(raw_stream, "read", None)):
            bounded = _BoundedReadStream(raw_stream, max_bytes, label)
            while True:
                chunk = bounded.read(chunk_size)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)

        raw_bytes = getattr(resp, "content", b"") or b""
        if len(raw_bytes) > max_bytes:
            raise RuntimeError(
                f"{label} response exceeds configured size limit. "
                f"Received={len(raw_bytes)} bytes, limit={max_bytes} bytes."
            )
        return raw_bytes

@dataclass
class FeedCacheManager:
    """
    Centralized class object that handles feed cache integrity and checksum validations.
    - Resolves canonical cache paths under ctx.paths.cache_dir
    - Enforces TTL
    - Supports checksum/meta sidecars
    - Performs atomic writes via PFH
    """
    cache_dir: Path
    pfh: Any
    logger: Any
    specs: Dict[str, FeedSpec]
    policy: FeedCachePolicy
    nvd_feeds_dir: Path

    @classmethod
    def from_ctx(cls, ctx: "RunContext", specs: Dict[str, "FeedSpec"], policy: "FeedCachePolicy") -> "FeedCacheManager":
        cache_dir = ctx.paths.cache_dir
        cache_dir.mkdir(parents = True, exist_ok = True)
        return cls(cache_dir = cache_dir, pfh = ctx.pfh, logger = ctx.logger, specs = specs, policy = policy, nvd_feeds_dir = ctx.paths.nvd_feeds_dir)


    # ---------------- Resolving Paths ----------------

    def resolve(self, key: str) -> Tuple[Path, Optional[Path], Optional[Path]]:
        """
        Returns (data_path, sha256_path, meta_path) for a feed key.
        """
        # NVD Branch
        if key.startswith("nvd."):
            return self._resolve_nvd_key(key)
        spec = self.specs[key]
        data_path = self.cache_dir / spec.key / spec.filename
        sha_path = Path(str(data_path) + spec.sha256_suffix) if spec.sha256_suffix else None
        meta_path = Path(str(data_path) + spec.meta_suffix) if spec.meta_suffix else None

        return data_path, sha_path, meta_path

    def _spec(self, key: str) -> "FeedSpec":
        """
        Returns FeedSpec details for specified key.
        """
        if key not in self.specs:
            raise KeyError(f"Unknown feed key: {key}")
        return self.specs[key]

    # ----------------- Meta Handling -----------------

    def load_meta(self, key: str) -> Optional[dict]:
        _, _, meta_path = self.resolve(key)

        if not meta_path.exists():
            return None
        try:
            with self.pfh.open_for_read(meta_path, mode = "r", label = f"{key} Meta") as r:
                return json.load(r)
        except Exception as e:
            self.logger.print_warning(
                f"Meta file for {key} is corrupted; ignoring. "
                f"Path={self.pfh.format_for_log(meta_path)} Trace={e}",
                label = "Cache Manager"
            )
            return None

    def save_metadata_file(self,
                           key: str,
                           *,
                           source_url: str,
                           mode: str,
                           validated: bool,
                           checksum_src: str,
                           fetched_by: str = UA,) -> None:
        """
        Handles saving .meta files for feed caches.

        :param key: Key name - e.g, "kev", "epss", "exploitdb", "nvd"
        :type key: str
        :param source_url: From where the data feed was fetched.
        :type source_url: str
        :param mode: Online/Offline mode
        :type mode: str
        :param validated: Validated against upstream
        :type validated: bool
        :param checksum_src: From where checksum was generated
        :type checksum_src: str
        :param fetched_by: Fetched by metadata
        :type fetched_by: str
        """
        spec = self._spec(key)
        data_path, _, meta_path = self.resolve(key)

        now = datetime.now(timezone.utc).isoformat()

        meta = self.load_meta(key) or {}


        meta["feed"] = key
        meta.setdefault("created_at", now)
        meta["mode"] = mode
        meta["checksum_source"] = checksum_src
        meta["source_url"] = source_url
        meta["fetched_by"] = fetched_by
        meta["validated_against_remote"] = validated
        meta["filename"] = data_path.name
        meta["label"] = spec.label

        # Write File
        meta_path = self.pfh.ensure_writable_file(meta_path, label = f"{key} Meta", create_parents = True, overwrite = True)
        with self.pfh.open_for_write(meta_path, mode = "w", label = f"{key} Meta") as w:
            w.write(json.dumps(meta, indent=2))
        self._harden_file_mode(meta_path)

        self.logger.print_success(f"Metadata written: {self.pfh.format_for_log(meta_path)}", label = "Cache Manager")

    def update_cache_meta(self, key: str) -> None:
        """
        Updates cache metadata when new data is cached.
        """
        _, _, meta_path = self.resolve(key)

        now = datetime.now(timezone.utc).isoformat()

        meta = self.load_meta(key) or {}

        # Ensure created_at exists. If not, create it.
        meta.setdefault("created_at", now)

        # Always refresh 'last_updated'
        meta["last_updated"] = now

        meta_path = self.pfh.ensure_writable_file(meta_path, label = f"{key} Meta", create_parents = True, overwrite = True)

        with self.pfh.open_for_write(meta_path, mode = "w", label = f"{key} Meta") as w:
            w.write(json.dumps(meta, indent=2))
        self._harden_file_mode(meta_path)

        self.logger.print_success(f"Metadata update written: {self.pfh.format_for_log(meta_path)}", label = "Cache Manager")

    def print_cache_metadata(self, key: str) -> None:
        """
        Prints cache_metadata information for user awareness.
        """
        _, _, meta_path = self.resolve(key)
        meta = self.load_meta(key)
        if not meta:
            self.logger.print_warning(f"No meta found for '{key}' at {self.pfh.format_for_log(meta_path)}", label = "Cache Manager")
            return

        # Safely extract fields to report
        last_updated = meta.get("last_updated")
        created_at = meta.get("created_at")

        if last_updated:
            self.logger.print_info(f"{meta_path.name} last updated (UTC): {meta['last_updated']}", label = "Cache Manager")
        elif created_at:
            self.logger.print_info(f"{meta_path.name} created at: {meta['created_at']} (No 'last_updated' yet)", label = "Cache Manager")
        else:
            # Log warning about feed's meta file
            self.logger.print_warning(f"Meta file for '{key}' exists, but contains no timestamp fields.", label = "Cache Manager")

    # ----------------- TTL Logic -----------------
    def is_fresh(self, key: str) -> bool:
        """
        Check FeedSpec for ttl_hours to determine if feed cache is fresh based from config.
        """
        spec = self._spec(key)
        data_path, _, _ = self.resolve(key)
        ttl = self._ttl_hours(key)

        if ttl == 0:
            self.logger.debug('TTL is less than or equal to 0 : "%s"', ttl)
            return False

        meta = self.load_meta(key)
        if not meta:
            self.logger.debug('.meta file cannot be found : "%s"', f"Check {self.pfh.format_for_log(data_path)} for the existence of .meta")
            return False

        last_raw = meta.get("last_updated") or meta.get("created_at")
        if not last_raw:
            self.logger.debug('No last raw timestamp : "%s"', "No timestamp available to determine TTL.")
            return False


        try:
            dt = datetime.fromisoformat(last_raw.replace("Z", "+00:00"))
        except Exception as e:
            self.logger.debug('Invalid last_updated timestamp in meta for "%s", Timestamp: "%s", Error Trace: "%s".', key, last_raw, e)
            return False

        now = datetime.now(timezone.utc)
        age = now - dt

        if ttl < 0:
            self.logger.debug('TTL is "%s" which is set to never expire. This is typically set in Offline only environments.', ttl)
            return True

        age_hours = age.total_seconds() / 3600.0
        self.logger.debug("'%s' cache age=%sh, ttl=%sh", key, f"{age_hours:.2f}", ttl)
        return age_hours <= float(ttl)

    # ----------------- Permission & Quarantine Helpers -----------------
    @staticmethod
    def _harden_file_mode(path: Optional[Path]) -> None:
        if path is None or os.name == "nt":
            return
        try:
            if path.exists():
                os.chmod(path, 0o600)
        except OSError:
            pass

    @staticmethod
    def _assert_not_world_writable(path: Optional[Path], *, label: str = "Cache file") -> None:
        if path is None or os.name == "nt" or not path.exists():
            return
        try:
            st = os.stat(path)
        except OSError as exc:
            raise PermissionError(f"{label} permission check failed: {exc}") from exc
        if bool(st.st_mode & stat.S_IWOTH):
            raise PermissionError(f"{label} is world-writable; refusing to continue: {path.name}")

    @staticmethod
    def _quarantine_tampered_paths(*paths: Optional[Path]) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        for path in paths:
            if path is None:
                continue
            try:
                if path.exists():
                    os.replace(path, Path(f"{path}.tampered.{ts}"))
            except OSError:
                pass

    # ----------------- Checksum Logic -----------------
    def compute_checksum(self, key: str) -> str:
        data_path, _, _ = self.resolve(key)
        self._assert_not_world_writable(data_path, label=f"{key} Cache")
        h = hashlib.sha256()
        with self.pfh.open_for_read(data_path, mode = 'rb', label = f"{key} Cache") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def _feed_integrity_secret(self) -> Optional[bytes]:
        raw = os.getenv("VP_FEED_CACHE_HMAC_KEY")
        if not raw:
            return None
        return raw.encode("utf-8")

    def _feed_integrity_path(self, data_path: Path) -> Path:
        return Path(str(data_path) + ".integrity.json")

    def _write_feed_integrity(self, key: str, data_path: Path, digest: str) -> None:
        integrity_path = self._feed_integrity_path(data_path)
        secret = self._feed_integrity_secret()
        mode = "sha256"
        signature = digest
        if secret is not None:
            mode = "hmac-sha256"
            signature = hmac.new(secret, digest.encode("utf-8"), hashlib.sha256).hexdigest()

        payload = {
            "feed": key,
            "filename": data_path.name,
            "mode": mode,
            "digest": digest,
            "signature": signature,
            "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }

        integrity_path = self.pfh.ensure_writable_file(
            integrity_path,
            label=f"{key} Integrity Sidecar",
            create_parents=True,
            overwrite=True,
        )
        with self.pfh.open_for_write(integrity_path, mode="w", label=f"{key} Integrity Sidecar") as w:
            w.write(json.dumps(payload, indent=2))
        self._harden_file_mode(integrity_path)

    def _verify_feed_integrity(self, key: str, data_path: Path, digest: str, *, allow_regen: bool) -> bool:
        integrity_path = self._feed_integrity_path(data_path)

        if not integrity_path.exists():
            if allow_regen:
                self._write_feed_integrity(key, data_path, digest)
            return False

        try:
            self._assert_not_world_writable(integrity_path, label=f"{key} Integrity Sidecar")
            with self.pfh.open_for_read(integrity_path, mode="r", label=f"{key} Integrity Sidecar") as r:
                payload = json.load(r)
            if not isinstance(payload, dict):
                raise ValueError("Invalid integrity payload")

            mode = str(payload.get("mode", "")).strip()
            expected_digest = str(payload.get("digest", ""))
            expected_signature = str(payload.get("signature", ""))

            if not hmac.compare_digest(expected_digest, digest):
                if allow_regen:
                    self._write_feed_integrity(key, data_path, digest)
                    return False
                return False

            secret = self._feed_integrity_secret()
            if secret is not None and mode != "hmac-sha256":
                if allow_regen:
                    self._write_feed_integrity(key, data_path, digest)
                    return False
                return False

            if mode == "hmac-sha256":
                if secret is None:
                    if allow_regen:
                        self._write_feed_integrity(key, data_path, digest)
                        return False
                    return False
                computed_sig = hmac.new(secret, digest.encode("utf-8"), hashlib.sha256).hexdigest()
            elif mode == "sha256":
                computed_sig = digest
            else:
                if allow_regen:
                    self._write_feed_integrity(key, data_path, digest)
                    return False
                return False

            if not hmac.compare_digest(expected_signature, computed_sig):
                if allow_regen:
                    self._write_feed_integrity(key, data_path, digest)
                    return False
                return False
            return True
        except PermissionError:
            raise
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            if allow_regen:
                self._write_feed_integrity(key, data_path, digest)
                return False
            return False

    def ensure_feed_checksum(self, key: str, *, allow_regen: bool) -> bool:
        """
        Ensure checksum + meta exist and are consistent with the feed.

        Returns:
            True -> checksum verified and valid
            False -> checksum/state regenerated when allow_regen=True
        Raises:
            FeedChecksumError (subclass of RuntimeError) when allow_regen=False and
            checksum or integrity sidecar is missing or tampered.
        """
        spec = self._spec(key)
        data_path, sha_path, _ = self.resolve(key)

        if not data_path.exists():
            raise FileNotFoundError(f"Feed '{key}' not found: {self.pfh.format_for_log(data_path)}")

        self._assert_not_world_writable(data_path, label=f"{key} Cache")
        if sha_path is not None and sha_path.exists():
            self._assert_not_world_writable(sha_path, label=f"{key} SHA256")

        # If checksum file exists, validate the checksum
        if sha_path is not None and sha_path.exists():
            with self.pfh.open_for_read(sha_path, mode = "r", label = f"{key} SHA256") as r:
                raw_sha = r.read().strip().split()
            expected = raw_sha[0] if raw_sha else ""
            actual = self.compute_checksum(key)

            # Diff Check
            if not hmac.compare_digest(expected, actual):
                if not allow_regen:
                    self.logger.print_error(f"Checksum mismatch for {data_path.name}", label = "Cache Manager")
                    self._quarantine_tampered_paths(
                        data_path,
                        sha_path,
                        self._feed_integrity_path(data_path),
                    )
                    raise FeedChecksumError(
                        f"Checksum mismatch for {data_path.name}; tampered cache quarantined. "
                        f"Re-download with --refresh-cache or configure allow_regen=True."
                    )
                # Allow_regen = True: non-interactive offline / recovery mode
                self.logger.print_warning(
                    f"Checksum mismatch for {data_path.name}. "
                    f"Regenerating checksum from file contents (allow_regen=True). "
                    f"Integrity vs upstream mirror CANNOT be verified — best-effort cache.",
                    label = "Cache Manager",
                )
                self._create_cs(key, actual)
                self._write_feed_integrity(key, data_path, actual)
                self.update_cache_meta(key)
                return False

            # Checksum matches; verify HMAC/SHA-256 integrity sidecar
            integrity_ok = self._verify_feed_integrity(key, data_path, actual, allow_regen=allow_regen)
            if not integrity_ok and not allow_regen:
                self._quarantine_tampered_paths(
                    data_path,
                    sha_path,
                    self._feed_integrity_path(data_path),
                )
                raise FeedChecksumError(
                    f"Integrity sidecar mismatch for {data_path.name}; quarantined cache. "
                    f"Refusing to trust cache without tamper-safe metadata."
                )
            if not integrity_ok:
                self.logger.print_warning(
                    f"Integrity sidecar refreshed for {data_path.name}; continuing in best-effort mode.",
                    label="Cache Manager"
                )
                return False
            self.logger.print_success(f"Checksum valid for {spec.label}: {data_path.name}", label = "Cache Manager")
            return True

        # No .sha256 file present
        if not allow_regen:
            raise FeedChecksumError(
                f"Missing checksum for {data_path.name}. "
                f"Refusing to trust cache without integrity metadata. "
                f"Use --refresh-cache to re-download a verified feed or set allow_regen=True."
            )

        # Missing checksum with explicit allow_regen=True
        actual = self.compute_checksum(key)
        self._create_cs(key, actual)
        self._write_feed_integrity(key, data_path, actual)
        self.update_cache_meta(key)

        self.logger.print_warning(
            f"No checksum file found for {data_path.name}. "
            f"Generated LOCAL checksum {actual} (allow_regen=True). "
            f"Integrity vs upstream mirror CANNOT be verified — using best-effort offline cache.",
            label = "Cache Manager",
        )
        return False

    def _create_cs(self, key: str, digest: str) -> None:
        """
        Creates checksum and writes to file.
        """
        data_path, sha_path, _ = self.resolve(key)
        sha_path = self.pfh.ensure_writable_file(sha_path, label = f"{key} SHA256", create_parents = True, overwrite = True)
        with self.pfh.open_for_write(sha_path, mode = "w", label = f"{key} SHA256") as w:
            w.write(f"{digest} {data_path.name}\n")
        self._harden_file_mode(sha_path)

    # ----------------- Decision Helpers -----------------
    def should_use_cached(self, key: str, *, force_refresh: bool) -> bool:
        if force_refresh:
            return False

        data_path, _, meta_path = self.resolve(key)

        if not data_path.exists() or not meta_path.exists():
            return False

        if not self.is_fresh(key):
            return False

        self.logger.debug("should_use_Cached is : '%s'", True)
        return True

    # ----------------- Helpers -----------------
    def _ttl_hours(self, key: str) -> float:
        return self.policy.ttl_for(key)

    def write_atomic(
        self,
        key: str,
        data: bytes,
        *,
        source_url: str,
        mode: str,
        validated: bool,
        checksum_src: str,
        overwrite: bool = True,
        extra_meta: Optional[dict] = None
    ) -> Path:
        """
        Atomically write feed bytes to cache (data + sha + meta).

        - Uses PFH for all I/O ops
        - Writes to temp file then replaces
        - Writes sha sidecar and meta JSON

        :param key: Feed Key Name
        :type key: str
        :param data: Feed data
        :type data: bytes
        :param source_url: URL of cache feed(Online)
        :type source_url: str
        :param mode: Online/Offline
        :type mode: str
        :param validated: Whether feed has been validated against upstream
        :type validated: bool
        :param checksum_src: From what source has checksum been generated.
        :type checksum_src: str
        :param overwrite: If True, overwrite pre-existing data with new. (Default True)
        :type overwrite: bool
        :returns: Final Data Path
        """

        # NVD Branching
        if key.startswith("nvd."):
            data_path, sha_path, meta_path = self.resolve(key)
            return self._write_atomic_paths_resolved(
                key=key,
                data_path=data_path,
                sha_path=sha_path,
                meta_path=meta_path,
                data=data,
                source_url=source_url,
                mode=mode,
                validated=validated,
                checksum_src=checksum_src,
                overwrite=overwrite,
                extra_meta=extra_meta
            )

        spec = self._spec(key)
        data_path, sha_path, meta_path = self.resolve(key)

        # Ensure parent exists
        self.cache_dir.mkdir(parents = True, exist_ok = True)

        # Temp file
        tmp_path = data_path.with_suffix(data_path.suffix + ".tmp")

        tmp_path = self.pfh.ensure_writable_file(
            tmp_path,
            label = f"{spec.label} Temp Cache File",
            create_parents = True,
            overwrite = True,
        )
        with self.pfh.open_for_write(tmp_path, mode = "wb", label = f"{spec.label} Temp Cache File") as w:
            w.write(data)

        # Promote temp -> Final file
        data_path = self.pfh.ensure_writable_file(
            data_path,
            label = f"{spec.label} Cache File",
            create_parents = True,
            overwrite = overwrite
        )
        tmp_path.replace(data_path)
        self._harden_file_mode(data_path)

        # Write sha256
        digest = hashlib.sha256(data).hexdigest()
        sha_path = self.pfh.ensure_writable_file(
            sha_path,
            label = f"{spec.label} SHA256",
            create_parents = True,
            overwrite = True
        )
        with self.pfh.open_for_write(sha_path, mode = "w", label = f"{spec.label} SHA256") as w:
            w.write(f"{digest} {data_path.name}\n")
        self._harden_file_mode(sha_path)
        self._write_feed_integrity(key, data_path, digest)

        # Write/update meta
        now = datetime.now(timezone.utc).isoformat()
        meta = self.load_meta(key) or {}
        meta["feed"] = key
        meta.setdefault("created_at", now)
        meta["last_updated"] = now
        meta["mode"] = mode
        meta["checksum_source"] = checksum_src
        meta["source_url"] = source_url
        meta["fetched_by"] = UA
        meta["validated_against_remote"] = validated
        meta["filename"] = data_path.name
        meta["label"] = spec.label
        meta["bytes"] = len(data)
        if extra_meta:
            meta.update(extra_meta)

        meta_path = self.pfh.ensure_writable_file(
            meta_path,
            label = f"{spec.label} Meta",
            create_parents = True,
            overwrite = True
        )
        with self.pfh.open_for_write(meta_path, mode = "w", label = f"{spec.label} Meta") as w:
            w.write(json.dumps(meta, indent=2))
        self._harden_file_mode(meta_path)

        self.logger.print_success(f"Cached {spec.label} at {self.pfh.format_for_log(data_path)}", label = "CacheManager")
        return data_path

    def write_atomic_stream_gunzip(
        self,
        key: str,
        *,
        source_url: str,
        mode: str,
        validated: bool,
        checksum_src: str,
        timeout: int = 15,
        headers: Optional[Dict[str, str]] = None,
        extra_meta: Optional[Dict[str, Any]] = None,
        chunk_size: int = 1024 * 1024,
        max_decompressed_bytes: int = MAX_DECOMPRESSED_FEED_BYTES,
        max_response_bytes: Optional[int] = MAX_REMOTE_FEED_BYTES,
        enforce_https_redirect: bool = False,
    ) -> Path:
        """
        Stream-download a gzip feed and atomically cache its *decompressed* bytes.

        - Downloads with requests stream=True
        - Decompresses on the fly (gzip)
        - Writes decompressed bytes to temp file
        - Computes sha256 over decompressed bytes
        - Atomically replaces final cache file
        - Writes sha+meta files

        :returns: final data_path
        """
        spec = self._spec(key)
        data_path, sha_path, meta_path = self.resolve(key)

        tmp_path = data_path.with_suffix(data_path.suffix + ".tmp")

        # Prep tmp file
        tmp_path = self.pfh.ensure_writable_file(
            tmp_path,
            label = f"{spec.label} Temp Cache File",
            create_parents = True,
            overwrite = True
        )

        h = hashlib.sha256()
        total_bytes = 0

        # Stream download with allow_redirects=False and per-hop HTTPS validation
        with _open_https_stream(
            source_url,
            timeout=timeout,
            headers=headers,
            label=spec.label,
        ) as resp:
            resp_headers = getattr(resp, "headers", None) or {}
            if max_response_bytes is not None:
                content_length = resp_headers.get("Content-Length")
                if content_length:
                    try:
                        length = int(content_length)
                    except (TypeError, ValueError):
                        length = None
                    if length is not None and length > max_response_bytes:
                        raise RuntimeError(
                            f"{spec.label} response exceeds configured size limit. "
                            f"Reported={length} bytes, limit={max_response_bytes} bytes."
                        )

            raw_stream = getattr(resp, "raw", None)
            if raw_stream is not None and callable(getattr(raw_stream, "read", None)):
                raw_stream.decode_content = False
                gz_source: Any = _BoundedReadStream(raw_stream, max_response_bytes, spec.label)
            else:
                import io as _io

                chunks: list[bytes] = []
                total_compressed = 0
                iter_content = getattr(resp, "iter_content", None)
                if callable(iter_content):
                    for chunk in iter_content(chunk_size=chunk_size):
                        if not chunk:
                            continue
                        total_compressed += len(chunk)
                        if max_response_bytes is not None and total_compressed > max_response_bytes:
                            raise RuntimeError(
                                f"{spec.label} response exceeds configured size limit. "
                                f"Read={total_compressed} bytes, limit={max_response_bytes} bytes."
                            )
                        chunks.append(chunk)
                    gz_source = _io.BytesIO(b"".join(chunks))
                else:
                    raw_bytes = getattr(resp, "content", b"") or b""
                    if max_response_bytes is not None and len(raw_bytes) > max_response_bytes:
                        raise RuntimeError(
                            f"{spec.label} response exceeds configured size limit. "
                            f"Received={len(raw_bytes)} bytes, limit={max_response_bytes} bytes."
                        )
                    gz_source = _io.BytesIO(raw_bytes)

            # Gunzip stream
            with gzip.GzipFile(fileobj=gz_source, mode="rb") as gz:
                with self.pfh.open_for_write(tmp_path, mode="wb", label=f"{spec.label} Temp Cache File") as w:
                    while True:
                        chunk = gz.read(chunk_size)
                        if not chunk:
                            break
                        if total_bytes + len(chunk) > max_decompressed_bytes:
                            raise RuntimeError(
                                f"Decompressed feed exceeds safety limit for {spec.label}. "
                                f"Limit={max_decompressed_bytes} bytes"
                            )
                        w.write(chunk)
                        h.update(chunk)
                        total_bytes += len(chunk)

        # Promote tmp -> final file
        data_path = self.pfh.ensure_writable_file(
            data_path,
            label = f"{spec.label} Cache File",
            create_parents = True,
            overwrite = True
        )
        tmp_path.replace(data_path)
        self._harden_file_mode(data_path)

        # Write sha file
        digest = h.hexdigest()
        sha_path = self.pfh.ensure_writable_file(
            sha_path,
            label = f"{spec.label} SHA256",
            create_parents = True,
            overwrite = True,
        )
        with self.pfh.open_for_write(sha_path, mode = "w", label = f"{spec.label} SHA256") as w:
            w.write(f"{digest} {data_path.name}\n")
        self._harden_file_mode(sha_path)
        self._write_feed_integrity(key, data_path, digest)

        # Write meta file
        now = datetime.now(timezone.utc).isoformat()
        meta = self.load_meta(key) or {}

        meta["feed"] = key
        meta.setdefault("created_at", now)
        meta["last_updated"] = now
        meta["mode"] = mode
        meta["checksum_source"] = checksum_src
        meta["source_url"] = source_url
        meta["fetched_by"] = UA
        meta["validated_against_remote"] = validated
        meta["filename"] = data_path.name
        meta["label"] = spec.label
        meta["bytes"] = total_bytes
        meta["sha256"] = digest

        if extra_meta:
            meta.update(extra_meta)

        meta_path = self.pfh.ensure_writable_file(
            meta_path,
            label = f"{spec.label} Meta",
            create_parents = True,
            overwrite = True
        )
        with self.pfh.open_for_write(meta_path, mode = "w", label = f"{spec.label} Meta") as w:
            w.write(json.dumps(meta, indent=2))
        self._harden_file_mode(meta_path)

        self.logger.print_success(
            f"Cached {spec.label} (decompressed) at {self.pfh.format_for_log(data_path)}",
            label = "CacheManager"
        )
        return data_path

    # -----------------------------------------------------
    #   NVD Cache-Specific
    # -----------------------------------------------------
    NVD_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-"
    NVD_TIMEOUT_SEC = 15
    NVD_UA = UA

    def resolve_nvd_feed(
        self,
        *,
        key: str,
        ttl_hours: int,
        refresh_cache: bool,
        offline: bool,
    ) -> Path:
        """
        Resolves the NVD feed path:
        - Uses local cache if fresh
        - Otherwise validate via NVD remote .meta and refresh if needed
        - Always commit atomically and write local .sha256 + meta.json

        :param key: FeedSpec key name
        :type key: str
        :param ttl_hours: TTL threshold for refreshing cache
        :type ttl_hours: int
        :param refresh_cache: If True, refreshes cache with an online feed pull.
        :type refresh_cache: bool
        :param offline: If True, uses only local cache.
        :type offline: bool
        :return: NVD Cache
        :rtype: Path
        """
        data_path, sha_path, meta_path = self.resolve(key)

        if offline:
            if data_path.exists():
                self._assert_not_world_writable(data_path, label=f"NVD Feed Cache ({key})")
                return self.pfh.ensure_readable_file(data_path, label = f"NVD Feed Cache ({key})")
            raise FileNotFoundError(f"Offline mode: missing cached NVD feed for {key}")

        # Soft TTL: if fresh, skip remote meta
        if not refresh_cache and data_path.exists():
            try:
                self._assert_not_world_writable(data_path, label=f"NVD Feed Cache ({key})")
                mtime = datetime.fromtimestamp(data_path.stat().st_mtime, tz=timezone.utc)
                if datetime.now(timezone.utc) - mtime <= timedelta(hours=max(ttl_hours, 0)):
                    return self.pfh.ensure_readable_file(data_path, label = f"NVD Feed Cache ({key})")
            except PermissionError:
                raise
            except Exception:
                pass

        # Determine fname from resolved data_path
        fname = data_path.name
        meta_url = self.NVD_BASE_URL + fname.replace(".json.gz", ".meta")
        feed_url = self.NVD_BASE_URL + fname
        headers = {
            "User-Agent": self.NVD_UA,
            "Accept-Encoding": "identity",
        }

        # Fetch remote metadata with allow_redirects=False, per-hop HTTPS validation, and 1 MiB cap
        try:
            meta_bytes = stream_https_get_bytes(
                meta_url,
                max_bytes=MAX_NVD_META_BYTES,
                timeout=self.NVD_TIMEOUT_SEC,
                headers=headers,
                label=f"NVD Meta ({fname})",
            )
            remote_meta = self._parse_nvd_remote_meta(meta_bytes.decode("utf-8", errors="replace"))
        except RuntimeError:
            raise
        except Exception as e:
            if data_path.exists():
                self._assert_not_world_writable(data_path, label=f"NVD Feed Cache ({key})")
                self.logger.print_warning(f"Meta fetched failed for {fname}. Using local. Trace={e}", label = "FeedCacheManager-NVD")
                return self.pfh.ensure_readable_file(data_path, label = f"NVD Feed Cache ({key})")
            raise

        remote_last = self._iso_to_dt(remote_meta.get("lastModifiedDate"))
        remote_sha = (remote_meta.get("sha256") or "").strip().lower()

        # If local meta exists but remote isn't newer, keep local meta
        if not refresh_cache and data_path.exists() and meta_path.exists() and remote_last:
            try:
                self._assert_not_world_writable(data_path, label=f"NVD Feed Cache ({key})")
                with self.pfh.open_for_read(meta_path, mode = "r", label = "NVD Feed Meta Sidecar") as f:
                    local_meta = json.load(f)
                local_remote_last = self._iso_to_dt(local_meta.get("remote_lastModifiedDate"))
                if local_remote_last and remote_last <= local_remote_last:
                    return self.pfh.ensure_readable_file(data_path, label = f"NVD Feed Cache ({key})")
            except PermissionError:
                raise
            except Exception:
                pass

        # Download feed with allow_redirects=False, per-hop HTTPS redirect validation, 200 MB response limit, and 2 GiB gunzip limit
        self.logger.info(f"Downloading {fname}")
        with _open_https_stream(
            feed_url,
            timeout=self.NVD_TIMEOUT_SEC,
            headers=headers,
            label=f"NVD Feed ({fname})",
        ) as r:
            r_headers = getattr(r, "headers", None) or {}
            content_length = r_headers.get("Content-Length")
            if content_length:
                try:
                    if int(content_length) > MAX_REMOTE_FEED_BYTES:
                        raise RuntimeError(
                            f"NVD feed response exceeds size limit ({content_length} > {MAX_REMOTE_FEED_BYTES} bytes)."
                        )
                except (TypeError, ValueError):
                    pass

            chunks = []
            total_compressed = 0
            raw_stream = getattr(r, "raw", None)
            if raw_stream is not None and callable(getattr(raw_stream, "read", None)):
                raw_stream.decode_content = False
                bounded_raw = _BoundedReadStream(raw_stream, MAX_REMOTE_FEED_BYTES, f"NVD Feed ({fname})")
                while True:
                    chunk = bounded_raw.read(1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
            elif callable(getattr(r, "iter_content", None)):
                for chunk in r.iter_content(chunk_size=1024 * 1024):
                    if not chunk:
                        continue
                    total_compressed += len(chunk)
                    if total_compressed > MAX_REMOTE_FEED_BYTES:
                        raise RuntimeError(
                            f"NVD feed download exceeds safety limit ({total_compressed} > {MAX_REMOTE_FEED_BYTES} bytes)."
                        )
                    chunks.append(chunk)
            else:
                raw_bytes = getattr(r, "content", b"") or b""
                if len(raw_bytes) > MAX_REMOTE_FEED_BYTES:
                    raise RuntimeError(
                        f"NVD feed download exceeds safety limit ({len(raw_bytes)} > {MAX_REMOTE_FEED_BYTES} bytes)."
                    )
                chunks.append(raw_bytes)
            content = b"".join(chunks)
            gz_bytes = content

            # Sanity check gzip magic
            if gz_bytes[:2] != b"\x1f\x8b":
                raise ValueError(f"Expected gzip bytes for {fname}, got magic={gz_bytes[:2].hex()}")

            # Decompress incrementally with 2 GiB cap - NVD meta sha is for uncompressed file.
            try:
                import io as _io
                decomp_hash = hashlib.sha256()
                decomp_total = 0
                with gzip.GzipFile(fileobj=_io.BytesIO(gz_bytes), mode="rb") as gz_in:
                    while True:
                        decomp_chunk = gz_in.read(1024 * 1024)
                        if not decomp_chunk:
                            break
                        decomp_total += len(decomp_chunk)
                        if decomp_total > MAX_DECOMPRESSED_FEED_BYTES:
                            raise RuntimeError(
                                f"Decompressed NVD feed exceeds 2 GiB safety limit for {fname}."
                            )
                        decomp_hash.update(decomp_chunk)
                sha_local_decomp = decomp_hash.hexdigest().lower()
            except OSError as e:
                raise ValueError(f"Failed to gunzip {fname}: {e}") from e

            self.logger.debug(
                f"Content-Encoding={r_headers.get('Content-Encoding')} "
                f"Content-Type={r_headers.get('Content-Type')} "
                f"Content-Length={r_headers.get('Content-Length')} "
                f"User-Agent={r_headers.get('User-Agent')}"
            )

        validated = False
        checksum_src = "local"
        if remote_sha:
            validated = (sha_local_decomp == remote_sha)
            checksum_src = "nvd.meta.sha256"
            if not validated:
                raise ValueError(
                    f"SHA256 mismatch for {fname}: local={sha_local_decomp}, remote={remote_sha}"
                )
        extra_meta = {
            "feed_name(fname)": fname,
            "meta_url": meta_url,
            "remote_lastModifiedDate": remote_meta.get("lastModifiedDate"),
            "remote_sha256": remote_meta.get("sha256"),
            "remote_size": (remote_meta.get("size") or "Missing Size Key"),
        }

        # Final Path
        final_path = self.write_atomic(
            key,
            content,
            source_url=feed_url,
            mode="Online",
            validated=validated,
            checksum_src=checksum_src,
            overwrite=True,
            extra_meta=extra_meta,
        )

        return final_path





    def _parse_nvd_remote_meta(self, text: str) -> Dict[str, str]:
        meta: Dict[str, str] = {}
        for line in (text or "").splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip()
        return meta

    def _iso_to_dt(self, s: Optional[str]) -> Optional[datetime]:
        if not s:
            return None
        return datetime.fromisoformat(s.replace("Z", "+00:00"))

    def _read_local_meta(self, ctx, meta_path: Path) -> Dict[str, str]:
        meta_path = ctx.pfh.ensure_readable_file(meta_path, label = "Feed meta sidecar (.meta.json)")
        with ctx.pfh.open_for_read(meta_path, mode = "r", label = "Feed meta sidecar (.meta.json)") as f:
            return json.load(f)

    def _write_local_sha(self, ctx, sha_path: Path, sha_hex: str):
        with ctx.pfh.open_for_write(sha_path, mode = "w", label = "Feed sha256 sidecar (.sha256)") as f:
            f.write(sha_hex)

    def _write_local_meta(self, ctx, meta_path: Path, payload: Dict):
        with ctx.pfh.open_for_write(meta_path, mode = "w", label = "Feed meta sidecar (.meta.json)") as f:
            json.dump(payload, f, indent=2, sort_keys=True)

    def _resolve_nvd_key(self, key: str) -> Tuple[Path, Optional[Path], Optional[Path]]:
        """
        Returns nvd feed name
        """
        if key == "nvd.modified":
            fname = "modified.json.gz"
        # key can be either nvd.modified or nvd.year.####
        elif key.startswith("nvd.year."):
            year = key.split(".", 2)[2]
            if not year.isdigit() or len(year) != 4:
                raise ValueError(f"Invalid NVD year key: {key}")
            fname = f"{year}.json.gz"
        else:
            raise ValueError(f"Unknown NVD feed key: {key}")

        data_path = self.nvd_feeds_dir / fname
        sha_path = Path(str(data_path) + ".sha256")
        meta_path = Path(str(data_path) + ".meta.json")
        return data_path, sha_path, meta_path

    def _write_atomic_paths_resolved(
        self,
        *,
        key: str,
        data_path: Path,
        sha_path: Optional[Path],
        meta_path: Optional[Path],
        data: bytes,
        source_url: str,
        mode: str,
        validated: bool,
        checksum_src: str,
        overwrite: bool = True,
        extra_meta: Optional[dict] = None
    ) -> Path:
        """
        Atomically write feed bytes to cache (data + sha + meta).

        - Uses PFH for all I/O ops
        - Writes to temp file then replaces
        - Writes sha sidecar and meta JSON

        :param key: Feed Key Name
        :type key: str
        :param data: Feed data
        :type data: bytes
        :param source_url: URL of cache feed(Online)
        :type source_url: str
        :param mode: Online/Offline
        :type mode: str
        :param validated: Whether feed has been validated against upstream
        :type validated: bool
        :param checksum_src: From what source has checksum been generated.
        :type checksum_src: str
        :param overwrite: If True, overwrite pre-existing data with new. (Default True)
        :type overwrite: bool
        :returns: Final Data Path
        """

        # Ensure parent exists
        self.cache_dir.mkdir(parents = True, exist_ok = True)

        # Temp file
        tmp_path = data_path.with_suffix(data_path.suffix + ".tmp")

        tmp_path = self.pfh.ensure_writable_file(
            tmp_path,
            label = f"{data_path.name} Temp Cache File",
            create_parents = True,
            overwrite = True,
        )
        with self.pfh.open_for_write(tmp_path, mode = "wb", label = f"{data_path.name} Temp Cache File") as w:
            w.write(data)

        # Promote temp -> Final file
        data_path = self.pfh.ensure_writable_file(
            data_path,
            label = f"{data_path.name} Cache File",
            create_parents = True,
            overwrite = overwrite
        )
        tmp_path.replace(data_path)
        self._harden_file_mode(data_path)

        # Write sha256
        digest = hashlib.sha256(data).hexdigest()
        sha_path = self.pfh.ensure_writable_file(
            sha_path,
            label = f"{data_path.name} SHA256",
            create_parents = True,
            overwrite = True
        )
        with self.pfh.open_for_write(sha_path, mode = "w", label = f"{data_path.name} SHA256") as w:
            w.write(f"{digest} {data_path.name}\n")
        self._harden_file_mode(sha_path)
        self._write_feed_integrity(key, data_path, digest)

        # Write/update meta
        now = datetime.now(timezone.utc).isoformat()
        meta = self.load_meta(key) or {}
        meta["feed"] = key
        meta.setdefault("created_at", now)
        meta["last_updated"] = now
        meta["mode"] = mode
        meta["checksum_source"] = checksum_src
        meta["source_url"] = source_url
        meta["fetched_by"] = UA
        meta["validated_against_remote"] = validated
        meta["filename"] = data_path.name
        meta["label"] = data_path.name
        meta["bytes"] = len(data)
        if extra_meta:
            meta.update(extra_meta)

        meta_path = self.pfh.ensure_writable_file(
            meta_path,
            label = f"{data_path.name} Meta",
            create_parents = True,
            overwrite = True
        )
        with self.pfh.open_for_write(meta_path, mode = "w", label = f"{data_path.name} Meta") as w:
            w.write(json.dumps(meta, indent=2))
        self._harden_file_mode(meta_path)

        log_fn = getattr(self.logger, "print_success", None) or getattr(self.logger, "success", None)
        if callable(log_fn):
            log_fn(f"Cached {data_path.name} at {self.pfh.format_for_log(data_path)}")
        return data_path