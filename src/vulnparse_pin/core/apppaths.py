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
import stat
from typing import TYPE_CHECKING, Tuple
from dataclasses import dataclass
from pathlib import Path
from vulnparse_pin import __version__
from vulnparse_pin.core.config_source import ConfigSource
from vulnparse_pin.core.config_validator import ConfigValidator
from vulnparse_pin.core.config_projector import ConfigProjector

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext


try:
    from platformdirs import user_data_dir
except ImportError as e:
    raise RuntimeError(
        "Missing dependency: platformdirs. Install with pip install platformdirs"
    ) from e

APP_NAME = "VulnParse-Pin"
APP_AUTHOR = False

def _truthy_env(name: str) -> bool:
    v = os.getenv(name, "").strip().lower()
    return v in {"1", "true", "yes", "y", "on"}

def _portable_base() -> Path:
    """
    Decide where portable 'data/' lives.
    - If frozen (Pyinstaller), use directory of executable.
    - Else use current working directory or script dir.
    """
    # PyInstaller
    if getattr(os, "frozen", False):
        import sys
        return Path(sys.executable).resolve().parent

    # Run from source/venv/etc
    return Path.cwd().resolve()

@dataclass
class AppPaths:
    portable: bool
    base_dir: Path          # OS-native base or portable base
    config_dir: Path
    data_dir: Path
    cache_dir: Path
    log_dir: Path
    output_dir: Path
    nvd_dir: Path
    nvd_feeds_dir: Path
    kev_dir: Path
    epss_dir: Path
    exploitdb_dir: Path

    @classmethod
    def resolve(cls, *, portable: bool | None = None, version: str | None = None) -> "AppPaths":
        if version is None:
            version = __version__

        if portable is None:
            portable = _truthy_env("VULNPARSE_PIN_PORTABLE")

        if portable:
            base = _portable_base()
            data_root = base / "data"
            version_root = data_root / "versions" / version
            config_dir = version_root / "config"
            data_dir = data_root
            cache_dir = data_root / "cache"
            log_dir = data_root / "logs"
            output_dir = version_root / "outputs"
            nvd_dir = cache_dir / "nvd"
            nvd_feeds_dir = nvd_dir / "feeds"
            kev_dir = cache_dir / "kev"
            epss_dir = cache_dir / "epss"
            exploitdb_dir = cache_dir / "exploit_db"
        else:
            data_dir = Path(user_data_dir(APP_NAME, APP_AUTHOR))
            version_root = data_dir / "versions" / version
            config_dir = version_root / "config"
            cache_dir = data_dir / "cache"
            log_dir = data_dir / "logs"
            output_dir = version_root / "outputs"
            base = data_dir
            nvd_dir = cache_dir / "nvd"
            nvd_feeds_dir = nvd_dir / "feeds"
            kev_dir = cache_dir / "kev"
            epss_dir = cache_dir / "epss"
            exploitdb_dir = cache_dir / "exploit_db"

        return cls(
            portable = portable,
            base_dir = base,
            config_dir = config_dir,
            data_dir = data_dir,
            cache_dir = cache_dir,
            log_dir = log_dir,
            output_dir = output_dir,
            nvd_dir = nvd_dir,
            nvd_feeds_dir = nvd_feeds_dir,
            kev_dir = kev_dir,
            epss_dir = epss_dir,
            exploitdb_dir = exploitdb_dir,
        )

    def ensure_dirs(self) -> None:
        """
        Create req'd application directories and apply best-effort permission hardening.
        """
        dirs = {
            self.config_dir: 0o700,     # Sensitive - Keep this to power users.
            self.cache_dir: 0o700,      # Sensitive - No one really needs to dig in here other than the owner(power user).
            self.log_dir: 0o700,        # Senstive, but Users of same group can read(e.g., Sysadmins).
            self.output_dir: 0o750,     # Self explainable
            self.nvd_dir: 0o700,
            self.nvd_feeds_dir: 0o700,
            self.kev_dir: 0o700,
            self.epss_dir: 0o700,
            self.exploitdb_dir: 0o700,
        }

        for path, mode in dirs.items():
            path.mkdir(parents=True, exist_ok=True)
            _harden_dir(path, mode)

    def config_path_yaml(self) -> Path:
        return self.config_dir / "config.yaml"

    def config_path_scoring(self) -> Path:
        return self.config_dir / "scoring.json"

    def config_path_topn(self) -> Path:
        return self.config_dir / "tn_triage.json"


def ensure_user_configs(paths: AppPaths) -> Tuple[Path, Path, Path]:
    """
    Backward-compatible wrapper: ensure config files exist.
    Delegates to ConfigSource for file provisioning.
    """
    file_set = ConfigSource.ensure_files(paths)
    return file_set.global_yaml, file_set.scoring_json, file_set.topn_json

def load_config(ctx: "RunContext") -> Tuple[dict, dict, dict]:
    """
    Loads config files for VulnParse-Pin.
    - Global Config: config.yaml
    - Scoring Config: scoring.json
    - TopN Config: tn_triage.json

    :param ctx: RunContext with paths and PFH handler.
    :type ctx: RunContext
    :return: Returns tuple of (global_config, scoring_config, topn_config) dicts.
    :rtype: Tuple[dict, dict, dict]
    """
    files = ConfigSource.ensure_files(ctx.paths)
    payloads = ConfigSource.read_payloads(ctx, files)
    validation = ConfigValidator.validate(ctx, payloads)
    bundle = ConfigProjector.project(validation)
    return bundle.global_config, bundle.scoring_config, bundle.topn_config

def _harden_dir(path: Path, mode: int) -> None:
    """
    Best effort POSIX perm hardening.
    No-op on windows.
    """
    if os.name == "nt":
        return

    try:
        current = stat.S_IMODE(path.stat().st_mode)
        if current != mode:
            path.chmod(mode)
    except (PermissionError, NameError, ImportError) as e:
        raise PermissionError("Invalid permissions. Unable to set permission mode on path.") from e