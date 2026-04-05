# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext
    from vulnparse_pin.core.apppaths import AppPaths


@dataclass(frozen=True)
class ConfigFileSet:
    """
    Represents discovered and provisioned config file locations.
    """
    global_yaml: Path
    scoring_json: Path
    topn_json: Path


@dataclass(frozen=True)
class RawConfigPayloads:
    """
    Represents raw parsed config payloads before validation.
    """
    global_config: dict
    scoring_config: dict
    topn_config: dict


class ConfigSource:
    """
    Config source adapter: handles file discovery, provisioning, and reading.
    """

    @staticmethod
    def ensure_files(paths: "AppPaths") -> ConfigFileSet:
        """
        Ensure config files exist in the writable config dir.
        If missing, copy from package resource defaults.
        Returns ConfigFileSet with file paths.
        """
        paths.ensure_dirs()
        dst_yaml = paths.config_path_yaml()
        dst_scoring = paths.config_path_scoring()
        dst_topn = paths.config_path_topn()

        if not dst_yaml.exists():
            default_bytes_yaml = resources.files("vulnparse_pin.resources").joinpath("config.yaml").read_bytes()
            dst_yaml.write_bytes(default_bytes_yaml)

        if not dst_scoring.exists():
            default_bytes_scoring = resources.files("vulnparse_pin.resources").joinpath("scoring.json").read_bytes()
            dst_scoring.write_bytes(default_bytes_scoring)

        if not dst_topn.exists():
            default_bytes_topn = resources.files("vulnparse_pin.resources").joinpath("tn_triage.json").read_bytes()
            dst_topn.write_bytes(default_bytes_topn)

        return ConfigFileSet(
            global_yaml=dst_yaml,
            scoring_json=dst_scoring,
            topn_json=dst_topn,
        )

    @staticmethod
    def read_payloads(ctx: "RunContext", files: ConfigFileSet) -> RawConfigPayloads:
        """
        Read and parse config payloads from files.
        Returns RawConfigPayloads with parsed dicts.
        Raises RuntimeError on parse failures or invalid top-level types.
        """
        yaml = YAML(typ="safe", pure=True)
        try:
            with ctx.pfh.open_for_read(files.global_yaml, mode="r", label="Global Config (YAML)") as r:
                cfg_yaml = yaml.load(r)
        except (TypeError, ValueError, YAMLError) as e:
            raise RuntimeError("Could not parse yaml file.") from e

        if not isinstance(cfg_yaml, dict):
            raise RuntimeError("Global config must be an object/mapping at top-level.")

        try:
            with ctx.pfh.open_for_read(files.scoring_json, mode="r", label="Scoring Config (JSON)") as r:
                cfg_json = json.load(r)
        except (json.JSONDecodeError, TypeError, ValueError) as e:
            raise RuntimeError("Could not load json config file.") from e

        if not isinstance(cfg_json, dict):
            raise RuntimeError("Scoring config must be an object at top-level.")

        try:
            with ctx.pfh.open_for_read(files.topn_json, mode="r", label="TopN Config (JSON)") as r:
                cfg_topn = json.load(r)
        except (json.JSONDecodeError, TypeError, ValueError) as e:
            raise RuntimeError("Could not load json config file.") from e

        if not isinstance(cfg_topn, dict):
            raise RuntimeError("TopN config must be an object at top-level.")

        return RawConfigPayloads(
            global_config=cfg_yaml,
            scoring_config=cfg_json,
            topn_config=cfg_topn,
        )
