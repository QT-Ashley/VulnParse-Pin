# VulnParse-Pin – Vulnerability Parsing and Triage Engine
# Copyright (C) 2025 Shade216
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.
from __future__ import annotations
from importlib import resources
import os
import json
from typing import TYPE_CHECKING, Tuple
from dataclasses import dataclass
from pathlib import Path
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError
from vulnparse_pin import __version__

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext


try:
    from platformdirs import user_config_dir, user_data_dir, user_cache_dir, user_log_dir
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
    Ensure config.yaml and/or scoring.json exists in the writable config dir.
    If missing, copy from package resource default.
    """
    paths.ensure_dirs()
    dst_yaml = paths.config_path_yaml() # e.g., .../config/config.yaml
    dst_scoring = paths.config_path_scoring() # e.g., .../config/scoring.json
    dst_topn = paths.config_path_topn() # e.g., .../config/tn_triage.json

    #   Create missing Global config YAML
    if not dst_yaml.exists():
        default_bytes_yaml = resources.files("vulnparse_pin.resources").joinpath("config.yaml").read_bytes()
        dst_yaml.write_bytes(default_bytes_yaml)

    #   Create missing Scoring config JSON
    if not dst_scoring.exists():
        default_bytes_scoring = resources.files("vulnparse_pin.resources").joinpath("scoring.json").read_bytes()
        dst_scoring.write_bytes(default_bytes_scoring)

    if not dst_topn.exists():
        default_bytes_topn = resources.files("vulnparse_pin.resources").joinpath("tn_triage.json").read_bytes()
        dst_topn.write_bytes(default_bytes_topn)


    return dst_yaml, dst_scoring, dst_topn

def load_config(ctx: "RunContext") -> Tuple[dict, dict, dict]:
    """
    Loads config files for VulnParse-Pin.
    - Global Config: config.yaml
    - Scoring Config: scoring.json
    - TopN Config: tn_triage.json

    :param paths: Various attributes available from AppPaths dataclass.
    :type paths: AppPaths
    :return: Returns dict objects with config data.
    :rtype: Tuple[dict, dict, dict]
    """
    cfg_path_yaml, cfg_path_scoring, cfg_path_topn = ensure_user_configs(ctx.paths)

    # Enforce PFH policy

    # YAML INIT
    yaml=YAML(typ = "safe", pure = True)
    try:
        with ctx.pfh.open_for_read(cfg_path_yaml, mode = "r", label = "Global Config (YAML)") as r:
            cfg_yaml = yaml.load(r)
    except (TypeError, ValueError, YAMLError) as e:
        raise RuntimeError("Could not parse yaml file.") from e

    if not isinstance(cfg_yaml, dict):
        raise RuntimeError("Global config must be an object/mapping at top-level.")

    try:
        with ctx.pfh.open_for_read(cfg_path_scoring, mode = "r", label = "Scoring Config (JSON)") as r:
            cfg_json = json.load(r)
    except (json.JSONDecodeError, TypeError, ValueError) as e:
        raise RuntimeError("Could not load json config file.") from e

    if not isinstance(cfg_json, dict):
        raise RuntimeError("Scoring config must be an object at top-level.")

    try:
        with ctx.pfh.open_for_read(cfg_path_topn, mode = "r", label = "TopN Config (JSON)") as r:
            cfg_topn = json.load(r)
    except (json.JSONDecodeError, TypeError, ValueError) as e:
        raise RuntimeError("Could not load json config file.") from e

    if not isinstance(cfg_topn, dict):
        raise RuntimeError("TopN config must be an object at top-level.")

    return cfg_yaml, cfg_json, cfg_topn

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
    except Exception as e:
        raise PermissionError("Invalid permissions. Unable to set permission mode on path.") from e