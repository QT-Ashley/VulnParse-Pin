# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations


class VppError(Exception):
    """Typed CLI and application error carrying an intended process exit code."""

    def __init__(self, message: str, *, exit_code: int = 1) -> None:
        super().__init__(message)
        self.message = str(message)
        self.exit_code = int(exit_code)
