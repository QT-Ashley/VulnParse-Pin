# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from __future__ import annotations

import os
from pathlib import Path
from typing import IO, Literal, Optional, Any, Union

class FilePathError(RuntimeError):
    """Raised when a path is invalid, missing, or structurally unsafe."""

class FilePermissionError(RuntimeError):
    """Raised when a path exists but is not accessible with the request perms."""

PathLike = Union[str, Path]

class PermFileHandler:
    """
    Centralized, secure-by-default path + file handler.

    Responsibilities:
        - Normalize and sanitize paths
        - Produce log-safe path strings
        - Validate read/write perms
    """

    def __init__(
        self,
        logger: Any,
        *,
        root_dir: Optional[PathLike] = None,
        allowed_roots: Optional[list[PathLike]] = None,
        max_log_path_chars: int = 80,
        hide_home: bool = True,
        forbid_symlinks_read: bool = False,
        forbid_symlinks_write: bool = True,
        enforce_roots_on_read: bool = False,
        enforce_roots_on_write: bool = True,
        file_mode: Optional[int] = None,
        dir_mode: Optional[int] = None,
    ) -> None:
        """
        :param logger: Logging instance
        :param root_dir: Optional 'anchor' dir to relativize paths for logging.
        :param allowed_roots: Optional, List of acceptable roots to allow read/write operations.
        :param hide_name: If True, replaces user's home dir with '~' in log strings.
        :param forbid_symlinks: IF True, rejects paths that are symlinks.
        :param enforce_roots_on_read: If True, enforces read operations to occur only within acceptable roots.
        :param enforce_roots_on_dir: If True, enforces write operations to occur only within acceptable roots.
        :param file_mode: *POSIX* Applies file level permissions to file path.
        :param dir_mode: *POSIX* Applies directory level permissions to file path.
        """
        self.logger = logger
        self.root_dir = Path(root_dir).resolve() if root_dir is not None else None
        self.allowed_roots: list[Path] = []

        if self.root_dir is not None:
            self.allowed_roots.append(self.root_dir)

        if allowed_roots:
            for r in allowed_roots:
                self.allowed_roots.append(Path(r).resolve())

        self.max_log_path_chars = max_log_path_chars
        self.hide_home = hide_home
        self.forbid_symlinks_read = forbid_symlinks_read
        self.forbid_symlinks_write = forbid_symlinks_write
        self.enforce_roots_on_read = enforce_roots_on_read
        self.enforce_roots_on_write = enforce_roots_on_write

        # For POSIX System only
        self.file_mode = file_mode
        self.dir_mode = dir_mode

        try:
            self._home = Path.home().resolve()
        except Exception as e:
            self._home = None
            self.logger.exception(f"[PermFileHandler] Unable to resolve home path. Reason: {e}")

    # -------------------------
    # Public Formatting helpers
    # -------------------------

    def normalize(self, path: PathLike) -> Path:
        """
        Normalize any input into a resolved Path.
        """
        if isinstance(path, Path):
            p = path
        else:
            p = Path(path)

        try:
            return p.expanduser().resolve()
        except Exception:
            # Fallback
            return p.expanduser()

    def relativize(self, path: Path) -> Path:
        """
        Relativize to root_dir if possible, otherwise return as-is.
        """
        if self.root_dir is None:
            return path

        try:
            return path.relative_to(self.root_dir)
        except ValueError:
            return path

    def format_for_log(self, path: PathLike, *, relativize: bool = True) -> str:
        """
        Produce a log-safe representation of a path:
            - Optionally relativized to root_dir
            - Optionally home-masked
            - Trucated to max_log_path_chars
        """

        p = self.normalize(path)

        if relativize:
            p = self.relativize(p)

        path_str = str(p)

        if self.hide_home and self._home is not None:
            home_str = str(self._home)
            if path_str.startswith(home_str):
                path_str = "~" + path_str[len(home_str) :]

        return self._truncate_middle(path_str, self.max_log_path_chars)

    def add_allowed_root(self, path: PathLike) -> None:
        """Dynamically extend the jail with another allowed root."""
        p = self.normalize(path)
        if p not in self.allowed_roots:
            self.allowed_roots.append(p)
            self.logger.debug(
                "Added allowed root: %s",
                self.format_for_log(p, relativize=False)
            )
        return p

    def describe_policy(self) -> str:
        """
        Return human-readable desc of the current path policy.
        Used when --debug-path-policy flag is set.
        """
        roots = ", ".join(str(r) for r in self.allowed_roots) or "<none>"
        return (
            "Path policy:\n"
            f"  Allowed roots               : {roots}\n"
            f"  Enforce on read             : {self.enforce_roots_on_read}\n"
            f"  Enforce on write            : {self.enforce_roots_on_write}\n"
            f"  Forbid symlinks on Read     : {self.forbid_symlinks_read}\n"
            f"  Forbid symlinks on Write    : {self.forbid_symlinks_write}\n"
            f"  POSIX file mode             : {oct(self.file_mode) if self.file_mode is not None else "None"}\n"
            f"  POSIX dir mode              : {oct(self.dir_mode) if self.dir_mode is not None else "None"}\n"
        )

    # -------------------------
    # Permission Checks
    # -------------------------

    def ensure_readable_file(self, path: PathLike, *, label: str = "file", log: bool = True) -> Path:
        """
        Ensure path points to a readable regular file.
        """
        p = self.normalize(path)

        if self.enforce_roots_on_read:
            self._assert_within_roots(p, label)
            self._assert_parent_within_roots(p, label)

        self._assert_not_forbidden_symlink(p, label, op = "read")

        if not p.exists():
            raise FilePathError(f"{label.capitalize()} does not exists: {self.format_for_log(p)}")

        if self.forbid_symlinks_read and p.is_symlink():
            raise FilePathError(f"{label.capitalize()} is a forbidden symlink: {self.format_for_log(p)}")

        if not p.is_file():
            raise FilePathError(f"{label.capitalize()} is not a file: {self.format_for_log(p)}")

        if not os.access(p, os.R_OK):
            raise FilePermissionError(f"{label.capitalize()} is not readable: {self.format_for_log(p)}")

        if log:
            self.logger.debug(
                "Validated readable %s: %s",
                label,
                self.format_for_log(p),
            )

        return p

    def ensure_readable_dir(self, path: PathLike, *, label: str = "directory", log: bool = True) -> Path:
        """
        Ensure path points to a readable directory.
        """
        p = self.normalize(path)

        if self.enforce_roots_on_read:
            self._assert_within_roots(p, label)

        self._assert_not_forbidden_symlink(p, label, op = "read")

        if not p.exists():
            raise FilePathError(f"{label.capitalize()} does not exist: {self.format_for_log(p)}")

        if self.forbid_symlinks_read and p.is_symlink():
            raise FilePathError(f"{label.capitalize()} is a forbidden symlink: {self.format_for_log(p)}")

        if not p.is_dir():
            raise FilePathError(f"{label.capitalize()} is not a directory: {self.format_for_log(p)}")

        if not os.access(p, os.R_OK | os.X_OK):
            raise FilePermissionError(f"{label.capitalize()} is not accessible: {self.format_for_log(p)}")

        if log:
            self.logger.debug(
                "Validated readable %s: %s",
                label,
                self.format_for_log(p),
            )

        return p

    def ensure_writable_file(self,
                             path: PathLike,
                             *,
                             label: str = "output file",
                             create_parents: bool = True,
                             overwrite: bool = True,
                             log: bool = True) -> Path:
        """
        Ensure safe write to given file path.
            - Validates parent dir exists (or create)
            - Validates dir is writable
            - Optionally blocks overwriting existing files
        """
        p = self.normalize(path)

        if self.enforce_roots_on_write:
            self._assert_within_roots(p, label)
            self._assert_parent_within_roots(p, label)

        parent = p.parent

        self._assert_not_forbidden_symlink(parent, f"{label} parent directory", op = "write")


        if not parent.exists():
            if create_parents:
                try:
                    parent.mkdir(parents=True, exist_ok=True)
                    self._apply_dir_mode(parent)
                except Exception as exc:
                    raise FilePathError(
                        f"Failed to create parent directory for {label}: "
                        f"{self.format_for_log(parent)} ({exc})"
                    ) from exc
            else:
                raise FilePathError(f"Parent directory does not exist for {label}: {self.format_for_log(parent)}")

        if self.forbid_symlinks_write and parent.is_symlink():
            raise FilePathError(f"Parent directory is a forbidden symlink for {label}: {self.format_for_log(parent)}")

        if not os.access(parent, os.W_OK | os.X_OK):
            raise FilePermissionError(f"Parent directory is not writable for {label}: {self.format_for_log(parent)}")

        if p.exists() and not overwrite:
            raise FilePathError(f"{label.capitalize()} already exists and overwrite=False: {self.format_for_log(p)}")

        if self.forbid_symlinks_write and p.exists() and p.is_symlink():
            raise FilePathError(f"{label.capitalize()} is a forbidden symlink: {self.format_for_log(p)}")

        if log:
            self.logger.debug("Validated writable %s: %s",
                                   label,
                                   self.format_for_log(p))

        return p

    # -------------------------
    # Safe open managers
    # -------------------------

    def open_for_read(self, path: PathLike, mode: str = "r", encoding: Optional[str] = "utf-8", *, label: str = "file", log: bool = True) -> IO[Any]:
        """
        Safe wrapper around open() for reading.
        """
        if any(c in mode for c in ("w", "a", "+")):
            raise ValueError("open_for_read() must not be used with write/append mode.")

        p = self.ensure_readable_file(path, label=label, log=log)

        try:
            if 'b' in mode:
                return p.open(mode)
            return p.open(mode, encoding=encoding)
        except Exception as e:
            raise FilePermissionError(f"Failed to open {label} for reading: {self.format_for_log(p)} ({e})\n"
                                      f" Resolved path: {p}\n"
                                      f" Underlying error:") from e

    def open_for_write(self, path: PathLike, mode: str = 'w', encoding: Optional[str] = "utf-8", *, label: str = "output file", create_parents: bool = True, overwrite: bool = True) -> IO[Any]:
        """
        Safe wrapper around open() writing.
        """
        if "r" in mode and "+" not in mode:
            raise ValueError("open_for_write() must not be used with pure read modes.")

        p = self.ensure_writable_file(path, label=label, create_parents=create_parents, overwrite=overwrite, log=True)

        try:
            if "b" in mode:
                fh = p.open(mode)
            else:
                fh = p.open(mode, encoding=encoding)
        except Exception as e:
            raise FilePermissionError(
                f"Failed to open {label} for writing: {self.format_for_log(p)} ({e})"
            ) from e

        self._apply_file_mode(p)
        return fh

    # -------------------------
    # Helpers
    # -------------------------

    @staticmethod
    def _truncate_middle(s: str, max_len: int) -> str:
        """
        Truncate a string in the middle, preserving start + end.

        Ex:
            "/very/long/path/to/file.json" -> "/very/lo...file.json"
        """

        if max_len <= 0 or len(s) <= max_len:
            return s

        # Roughly split
        head_len = max(0, max_len // 3)
        tail_len = max(0, max_len - head_len - 3)
        if head_len + tail_len + 3 > max_len:
            tail_len = max_len - head_len - 3

        return f"{s[:head_len]}...{s[-tail_len:]}"

    def _assert_within_roots(self, p: Path, label: str) -> None:
        """
        Ensure path is under one of the allowed roots; raise if not.
        """
        if not self.allowed_roots:
            return

        for root in self.allowed_roots:
            try:
                p.relative_to(root)
                return
            except ValueError:
                continue

        roots_str = ", ".join(str(r) for r in self.allowed_roots) or "<none>"

        # Raise if it's outside all allowed roots
        raise FilePathError(
            f"{label.capitalize()} is outside allowed directories: "
            f"{self.format_for_log(p, relativize=False)}"
            f"  Resolved Path : {p}\n"
            f"  Allowed roots : {roots_str}"
        )

    def _assert_parent_within_roots(self, p: Path, label: str) -> None:
        """
       Ensure parent dir of p is also within allowed_roots.
        """
        parent = p.parent
        self._assert_within_roots(parent, f"{label} parent directory")

    def _assert_not_forbidden_symlink(self, p: Path, label: str, op: Literal["read", "write"]) -> None:
        forbid = self.forbid_symlinks_read if op == "read" else self.forbid_symlinks_write
        if not forbid:
            return

        parts = list(reversed(p.parents)) + [p]
        for x in parts:
            try:
                if x.is_symlink():
                    raise FilePathError(
                        f"{label} contains a forbidden symlink for {op}.\n"
                        f" Component           : {x}\n"
                        f" Forbidden component : {x.resolve(strict=False)}"
                    )
            except OSError as exc:
                if op == "write":
                    raise FilePathError(f"{label} could not be validated for symlinks: {x}") from exc
                self.logger.debug("Could not validate symlink status for %s (%s): %s", x, label, exc)

    def _apply_file_mode(self, p: Path) -> None:
        if self.file_mode is None:
            return
        if os.name != "posix":
            return

        try:
            os.chmod(p, self.file_mode)
        except PermissionError:
            self.logger.warning(
                "Failed to apply file mode %o to %s",
                self.file_mode,
                self.format_for_log(p),
            )

    def _apply_dir_mode(self, p: Path) -> None:
        if self.dir_mode is None:
            return
        if os.name != "posix":
            return

        try:
            os.chmod(p, self.dir_mode)
        except PermissionError:
            self.logger.warning(
                "Failed to apply dir mode %o to %s",
                self.dir_mode,
                self.format_for_log(p),
            )
