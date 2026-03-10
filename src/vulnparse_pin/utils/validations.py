# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 QTShade
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

import os
import sys

import json


def max_depth(obj, depth=0):
    """
    Checks depth of json structures. Used to prevent super deeply nested structures from resource exhaustion.
    """
    if isinstance(obj, dict):
        return max([max_depth(v, depth + 1) for v in obj.values()] + [depth])
    elif isinstance(obj, list):
        return max([max_depth(i, depth + 1) for i in obj] + [depth])
    return depth

def is_valid_cve_api_response(data):
    """Check and see if the api response has valid cve data in it.
    """
    # At a minimum
    return isinstance(data, dict) and "cve" in data

class FileInputValidator:
    def __init__(self, ctx, file_path, max_size_mb=200, max_nesting=12, allow_large: bool = False):
        """Validate a JSON input file.

        The validator may use ``ctx.pfh`` for every open to ensure path-policy
        enforcement; ``ctx`` is required to keep callers honest.
        """
        self.ctx = ctx
        self.pfh = getattr(ctx, "pfh", None)
        self.file_path = file_path
        self.allow_large = allow_large
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.max_large_size_bytes = 50 * 1024 * 1024 * 1024
        self.max_nesting = max_nesting
        self.report_json = None

    def is_valid_extension_structure(self):
        fstr = str(self.file_path)
        if not fstr.lower().endswith((".json", ".xml", ".nessus")):
            return False
        try:
            if self.pfh:
                with self.pfh.open_for_read(self.file_path, mode='r', label="File Validator") as f:
                    return f.read(1).strip() in ['{', '[', '<']
            else:
                with open(self.file_path, 'r', encoding='utf-8') as f:
                    return f.read(1).strip() in ['{', '[', '<']
        except Exception:
            return False

    def validate(self):
        if not os.path.exists(self.file_path):
            self.ctx.logger.print_error(f"File does not exist: {self.file_path}")
            sys.exit(1)

        if not os.access(self.file_path, os.R_OK):
            self.ctx.logger.print_error(f"File is not readable: {self.file_path}")
            sys.exit(1)

        if not self.is_valid_extension_structure():
            self.ctx.logger.print_error("File extention or initial structure invalid.")
            sys.exit(1)

        size_bytes = os.path.getsize(self.file_path)
        limit = self.max_large_size_bytes if self.allow_large else self.max_size_bytes

        if size_bytes > limit:
            self.ctx.logger.print_error(f"File exceeds size limit. Size: {size_bytes/1024/1024:.2f} MB exceeds limit" f"({limit/1024/1024:.0f} MB). Use --allow-large for enterprise-size reports.")
            sys.exit(1)

        if self.allow_large and size_bytes > self.max_size_bytes:
            self.ctx.logger.print_warning(f"⚠️ Large file mode enabled. File size = {size_bytes/1024/1024:.2f} MB. "
        f"Parsing may be slow or memory intensive.")

        # Load and validate JSON structure only for .json files
        # XML and .nessus files will be validated by their respective parsers
        fstr = str(self.file_path).lower()
        is_json_file = fstr.endswith(".json")

        if is_json_file:
            try:
                if self.pfh:
                    with self.pfh.open_for_read(self.file_path, mode='r', label="File Validator") as f:
                        self.report_json = json.load(f)
                else:
                    with open(self.file_path, 'r', encoding='utf-8') as f:
                        self.report_json = json.load(f)
                self.ctx.logger.print_success(f"File loaded: {self.file_path}")
            except json.JSONDecodeError as e:
                self.ctx.logger.print_error(f"Invalid JSON format: {e}")
                sys.exit(1)
            except Exception as e:
                self.ctx.logger.print_error(f"Error reading file: {e}")
                sys.exit(1)

            # Check nest depth for JSON files
            if max_depth(self.report_json) > self.max_nesting:
                self.ctx.logger.print_error("Nesting depth exceeds safe limit.")
                sys.exit(1)

            # Last sanity check for JSON files
            if not isinstance(self.report_json, dict):
                self.ctx.logger.print_error("Top-level JSON structure is not an object.")
                sys.exit(1)
        else:
            # For XML and .nessus files, just confirm file is readable
            self.ctx.logger.print_success(f"File validated: {self.file_path}")

        return self.file_path