# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from contextlib import contextmanager
import errno
from importlib import resources
import os
from pathlib import Path
import stat
import tempfile
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple, Union

import duckdb

from vulnparse_pin.io.pfhandler import _UMASK_LOCK


def _check_no_symlinks_or_loops(target: Path, *, label: str) -> None:
    """Fail closed if any path segment or the target path is a symlink/loop."""
    raw = target.expanduser()
    if not raw.is_absolute():
        raw = Path(os.getcwd()) / raw

    anchor = Path(raw.anchor) if raw.anchor else Path("/")
    parts = raw.parts[1:] if raw.anchor else raw.parts
    cur = anchor
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            cur = cur.parent
            continue
        cur = cur / part
        try:
            st = os.lstat(cur)
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise ValueError(f"Refusing symlink loop in {label}: {cur}") from exc
            raise ValueError(f"Could not inspect {label} for symlinks: {cur}") from exc
        if stat.S_ISLNK(st.st_mode):
            raise ValueError(f"Refusing symlink {label}: {cur}")


def _validate_duckdb_paths(path: Path) -> None:
    """Validate DuckDB workspace path, ancestors, and WAL/temp sidecars against symlinks."""
    _check_no_symlinks_or_loops(path, label="DuckDB workspace path")
    for suffix, label in ((".wal", "DuckDB WAL sidecar"), (".tmp", "DuckDB temp sidecar")):
        sidecar = Path(f"{path}{suffix}")
        try:
            st = os.lstat(sidecar)
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise ValueError(f"Refusing symlink loop in {label}: {sidecar}") from exc
            raise ValueError(f"Could not inspect {label}: {sidecar}") from exc
        if stat.S_ISLNK(st.st_mode):
            raise ValueError(f"Refusing symlink {label}: {sidecar}")


def _chmod_0600_if_exists(path: Path) -> None:
    """Enforce owner-only 0o600 POSIX permissions on an existing regular DB/WAL file."""
    if os.name != "posix":
        return
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"Refusing symlink DuckDB artifact: {path}")
    if stat.S_ISREG(st.st_mode):
        os.chmod(path, 0o600)


def ensure_safe_dir_non_pfh(
    dir_path: Union[Path, str],
    *,
    label: str = "output directory",
    dir_mode: int = 0o700,
) -> Path:
    """Validate all ancestors for symlinks/loops and create a directory with restricted POSIX perms."""
    target = Path(dir_path).expanduser()
    _check_no_symlinks_or_loops(target, label=label)
    if target.exists() and not target.is_dir():
        raise ValueError(f"Expected directory for {label}, found non-directory: {target}")
    if not target.exists():
        if os.name == "posix":
            dmode = int(dir_mode)
            with _UMASK_LOCK:
                old_umask = os.umask(0o777 & ~dmode)
                try:
                    target.mkdir(mode=dmode, parents=True, exist_ok=True)
                finally:
                    os.umask(old_umask)
        else:
            target.mkdir(parents=True, exist_ok=True)
    _check_no_symlinks_or_loops(target, label=label)
    if not target.is_dir():
        raise ValueError(f"Expected directory for {label}, found non-directory: {target}")
    return target


@contextmanager
def open_for_write_non_pfh(
    target_path: Union[Path, str],
    *,
    label: str = "output file",
    encoding: str = "utf-8",
    newline: Optional[str] = None,
    file_mode: int = 0o600,
    dir_mode: int = 0o700,
) -> Iterator[Any]:
    """
    Safely write a file without PFH: validate all ancestors against symlinks/loops,
    create missing parents under restricted dir umask, create a staging temp file
    with owner-only POSIX perms under `_UMASK_LOCK`, and atomically replace target.
    """
    target = Path(target_path).expanduser()
    _check_no_symlinks_or_loops(target, label=label)
    ensure_safe_dir_non_pfh(target.parent, label=f"{label} parent directory", dir_mode=dir_mode)
    _check_no_symlinks_or_loops(target, label=label)

    if target.exists():
        try:
            st = os.lstat(target)
        except OSError as exc:
            raise ValueError(f"Could not inspect {label}: {target}") from exc
        if stat.S_ISLNK(st.st_mode):
            raise ValueError(f"Refusing symlink {label}: {target}")
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"Refusing non-regular file for {label}: {target}")

    tmp_path: Optional[Path] = None
    fh: Any = None
    fmode = int(file_mode)
    try:
        if os.name == "posix":
            with _UMASK_LOCK:
                old_umask = os.umask(0o777 & ~fmode)
                try:
                    fh = tempfile.NamedTemporaryFile(
                        mode="w",
                        encoding=encoding,
                        newline=newline,
                        dir=str(target.parent),
                        prefix=f".{target.name}.",
                        suffix=".tmp",
                        delete=False,
                    )
                finally:
                    os.umask(old_umask)
        else:
            fh = tempfile.NamedTemporaryFile(
                mode="w",
                encoding=encoding,
                newline=newline,
                dir=str(target.parent),
                prefix=f".{target.name}.",
                suffix=".tmp",
                delete=False,
            )
        tmp_path = Path(fh.name)
        yield fh
        fh.flush()
        fh.close()
        fh = None
        if os.name == "posix":
            if fmode == 0o600:
                _chmod_0600_if_exists(tmp_path)
            else:
                os.chmod(tmp_path, fmode)
        _check_no_symlinks_or_loops(target, label=label)
        os.replace(tmp_path, target)
        tmp_path = None
        if os.name == "posix":
            if fmode == 0o600:
                _chmod_0600_if_exists(target)
            else:
                os.chmod(target, fmode)
    finally:
        if fh is not None:
            try:
                fh.close()
            except Exception:
                pass
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass


def _load_schema_sql() -> str:
    return resources.files("vulnparse_pin.storage").joinpath("schema.sql").read_text(encoding="utf-8")


class VppDatabase:
    """
    DuckDB-backed local workspace (.vpp.db) for VulnParse-Pin v2.0.0.
    Supports context-manager lifecycle, explicit .close(), POSIX 0o600 creation perms,
    and fast columnar bulk operations.
    """

    def __init__(self, db_path: Union[Path, str], *, read_only: bool = False) -> None:
        self.read_only = bool(read_only)
        self._closed = False

        if isinstance(db_path, str) and db_path == ":memory:":
            self.db_path: Union[Path, str] = ":memory:"
            self._conn = duckdb.connect(":memory:")
            self.initialize_schema()
            return

        path = Path(db_path)
        _validate_duckdb_paths(path)
        if not self.read_only:
            ensure_safe_dir_non_pfh(path.parent, label="DuckDB workspace parent directory")
            _validate_duckdb_paths(path)

        try:
            st = os.lstat(path)
            is_new = False
            if stat.S_ISLNK(st.st_mode):
                raise ValueError(f"Refusing symlink DuckDB workspace path: {path}")
        except FileNotFoundError:
            is_new = True

        if self.read_only and is_new:
            raise FileNotFoundError(f"DuckDB workspace does not exist: {path}")

        self.db_path = path
        if os.name == "posix" and not self.read_only:
            # Restrict umask during connect so new .db/.wal files are born 0o600 without a race window.
            with _UMASK_LOCK:
                prev_umask = os.umask(0o177)
                try:
                    self._conn = duckdb.connect(str(path), read_only=self.read_only)
                finally:
                    os.umask(prev_umask)
        else:
            self._conn = duckdb.connect(str(path), read_only=self.read_only)

        if not self.read_only:
            _chmod_0600_if_exists(path)
            _chmod_0600_if_exists(Path(f"{path}.wal"))
            self.initialize_schema()
            _chmod_0600_if_exists(path)
            _chmod_0600_if_exists(Path(f"{path}.wal"))

    @property
    def conn(self) -> duckdb.DuckDBPyConnection:
        if self._closed:
            raise RuntimeError("VppDatabase connection is already closed.")
        return self._conn

    @property
    def is_closed(self) -> bool:
        return self._closed

    def initialize_schema(self) -> None:
        ddl = _load_schema_sql()
        self.conn.execute(ddl)

    def execute(self, query: str, parameters: Optional[Sequence[Any]] = None) -> duckdb.DuckDBPyConnection:
        if parameters is None:
            return self.conn.execute(query)
        return self.conn.execute(query, parameters)

    @contextmanager
    def transaction(self) -> Iterator[duckdb.DuckDBPyConnection]:
        conn = self.conn
        if isinstance(self.db_path, Path) and not self.read_only:
            with _UMASK_LOCK:
                prev_umask = os.umask(0o177)
                try:
                    conn.execute("BEGIN TRANSACTION")
                finally:
                    os.umask(prev_umask)
        else:
            conn.execute("BEGIN TRANSACTION")
        try:
            yield conn
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise
        else:
            conn.execute("COMMIT")
            if isinstance(self.db_path, Path) and not self.read_only:
                _chmod_0600_if_exists(self.db_path)
                _chmod_0600_if_exists(Path(f"{self.db_path}.wal"))

    def close(self) -> None:
        if not self._closed:
            try:
                self._conn.close()
            finally:
                self._closed = True
                if isinstance(self.db_path, Path) and not self.read_only:
                    try:
                        _chmod_0600_if_exists(self.db_path)
                        _chmod_0600_if_exists(Path(f"{self.db_path}.wal"))
                    except OSError:
                        pass

    def __enter__(self) -> "VppDatabase":
        if self._closed:
            raise RuntimeError("Cannot enter closed VppDatabase.")
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Convenience wrappers delegating to storage.repositories
    # ------------------------------------------------------------------

    def ensure_run(self, run_id: str, **kwargs: Any) -> None:
        from vulnparse_pin.storage.repositories import ensure_run

        ensure_run(self, run_id, **kwargs)

    def ingest_normalized_batches(
        self,
        run_id: str,
        batches: Iterable[Sequence[Dict[str, Any]]] | Sequence[Dict[str, Any]],
        asset_matcher: Optional[Any] = None,
    ) -> Dict[str, Any]:
        from vulnparse_pin.storage.repositories import ingest_normalized_batches

        return ingest_normalized_batches(self, run_id, batches, asset_matcher=asset_matcher)

    def query_findings_page(
        self,
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
        from vulnparse_pin.storage.repositories import query_findings_page

        return query_findings_page(
            self,
            run_id,
            priority_tier=priority_tier,
            sla_bucket=sla_bucket,
            scoring_track=scoring_track,
            in_kev=in_kev,
            inventory_status=inventory_status,
            search=search,
            limit=limit,
            offset=offset,
        )

    def get_finding_detail(self, run_id: str, finding_id: str) -> Optional[Dict[str, Any]]:
        from vulnparse_pin.storage.repositories import get_finding_detail

        return get_finding_detail(self, run_id, finding_id)

    def get_run_summary_counts(self, run_id: str) -> Dict[str, Any]:
        from vulnparse_pin.storage.repositories import get_run_summary_counts

        return get_run_summary_counts(self, run_id)

    def get_shadow_assets(self, run_id: str) -> List[Dict[str, Any]]:
        from vulnparse_pin.storage.repositories import get_shadow_assets

        return get_shadow_assets(self, run_id)

    def list_runs(self) -> List[Dict[str, Any]]:
        from vulnparse_pin.storage.repositories import list_runs

        return list_runs(self)
