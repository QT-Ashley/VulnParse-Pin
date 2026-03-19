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
from pathlib import Path
import sys

from vulnparse_pin.core.classes.dataclass import ScanResult
from vulnparse_pin.utils.schema_validate import validate_scan_result_schema
from vulnparse_pin.utils.validations import FileInputValidator


@dataclass(frozen=True)
class NormalizationState:
    input_file: Path
    scan_result: ScanResult


def normalize_input(ctx, detector, scanner_input: Path, allow_large: bool) -> NormalizationState:
    logger = ctx.logger

    logger.print_info(f"Loading file: {scanner_input.name}", label="Target File")

    input_file = scanner_input

    validator = FileInputValidator(ctx, input_file, allow_large=allow_large)
    try:
        input_file = validator.validate()
    except (ValueError, TypeError, OSError, RuntimeError):
        sys.exit(1)

    logger.phase("Normalization")
    logger.print_info("Scanning structure to determine the type of parser to use...", label="Normalization")

    scan_result = None
    try:
        det = detector.select(ctx, input_file)
        parser = det.parser_cls(ctx, input_file)
        scan_result = parser.parse()
        try:
            assert isinstance(scan_result, ScanResult)
        except (ValueError, TypeError) as exc:
            raise TypeError(f"Scan Object does is not of valid type(ScanResult), Trace: {exc}") from exc
        validate_scan_result_schema(scan_result)
    except (ValueError, TypeError, OSError, RuntimeError) as e:
        logger.print_error(f"Error occured while trying to determine parser to use. Msg: {e}", label="Normalization")
        return sys.exit(1)

    logger.print_success(
        f"Parsed {len(scan_result.assets)} assets, {sum(len(a.findings) for a in scan_result.assets)} findings",
        label="Normalization",
    )

    return NormalizationState(input_file=input_file, scan_result=scan_result)
