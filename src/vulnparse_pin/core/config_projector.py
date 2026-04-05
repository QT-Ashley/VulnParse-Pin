# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vulnparse_pin.core.config_validator import ConfigValidationResult


@dataclass(frozen=True)
class RuntimeConfigBundle:
    """
    Represents final typed runtime configuration bundle ready for use.
    """
    global_config: dict
    scoring_config: dict
    topn_config: dict


class ConfigProjector:
    """
    Config projector: converts validated payloads into typed runtime bundles.
    """

    @staticmethod
    def project(validation: "ConfigValidationResult") -> RuntimeConfigBundle:
        """
        Project validated payloads into RuntimeConfigBundle.
        Returns bundle with typed config dicts ready for policy construction.
        """
        return RuntimeConfigBundle(
            global_config=validation.normalized.global_config,
            scoring_config=validation.normalized.scoring_config,
            topn_config=validation.normalized.topn_config,
        )
