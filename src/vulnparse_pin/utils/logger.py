# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 QTShade
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from pathlib import Path
import re
from typing import Optional
from colorama import init, Fore, Style
import logging
import os
import json

init(autoreset=True)
SEVERITY_COLOR = {
    "Critical+": "light_red",
    "Critical": "light_red",
    "High": "red",
    "Medium": "yellow",
    "Low": "blue",
    "Informational": "cyan"
}
COLOR_MAP = {
    "red": Fore.RED,
    "yellow": Fore.YELLOW,
    "green": Fore.GREEN,
    "blue": Fore.BLUE,
    "cyan": Fore.CYAN,
    "magenta": Fore.MAGENTA,
    "white": Fore.WHITE,
    "light_red": Fore.LIGHTRED_EX,
    "light_green": Fore.LIGHTGREEN_EX,
    "light_yellow": Fore.LIGHTYELLOW_EX,
}
def colorize(text: str, color: str) -> str:
    code = COLOR_MAP.get(color.lower())
    if not code:
        return text
    return f"{code}[{text}]{Style.RESET_ALL}"

ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")

# -------------------------------------
#       Custom Log Level: Success
# -------------------------------------

SUCCESS_LEVEL = 25
logging.addLevelName(SUCCESS_LEVEL, "SUCCESS")

def success(self, msg, *args, **kwargs) -> None:
    if self.isEnabledFor(SUCCESS_LEVEL):
        self._log(SUCCESS_LEVEL, msg, args, **kwargs)

logging.Logger.success = success

# -------------------------------------
#               Formatters
# -------------------------------------
class ConsoleFormatter(logging.Formatter):
    """
    Console formatter with colors and custom bracket style.
    [INFO] [*] "[Label]" message
    [SUCCESS] [+] ...
    [WARNING] [!]
    [ERROR] [-]
    """

    LEVEL_STYLE = {
        "INFO": (Fore.LIGHTCYAN_EX, "[INFO]", "[*]"),
        "SUCCESS": (Fore.LIGHTGREEN_EX, "[SUCCESS]", "[+]"),
        "WARNING": (Fore.YELLOW, "[WARNING]", "[!]"),
        "ERROR": (Fore.RED, "[ERROR]", "[-]"),
        "CRITICAL": (Fore.LIGHTRED_EX, "[CRITICAL]", "[!!!]"),
        "DEBUG": (Fore.LIGHTMAGENTA_EX, "[DEBUG]", "[~]"),
    }

    LABEL_COLOR = Fore.CYAN

    def format(self, record: logging.LogRecord) -> str:
        levelname = record.levelname.upper()
        color, level_tag, icon = self.LEVEL_STYLE.get(
            levelname, (Style.RESET_ALL, f"[{levelname}]", "[?]")
        )

        raw_label = getattr(record, "label", None)
        label_str = ""
        if raw_label:
            label_str = f'{self.LABEL_COLOR}[{raw_label}]{Style.RESET_ALL} '

        msg = record.getMessage()
        return f"{color}{level_tag} {icon}{Style.RESET_ALL} {label_str}{msg}".strip()

class FileFormatter(logging.Formatter):
    """
    Plain file formatter (no ANSI):
        2025-12-11T12:00:00Z - INFO - [INFO] "[Label]" message
    """

    def format(self, record: logging.LogRecord) -> str:
        raw_label = getattr(record, "label", None)
        label_str = f'[{raw_label}] ' if raw_label else ""

        msg = record.getMessage()
        msg = ANSI_RE.sub("", msg)

        created = self.formatTime(record, datefmt="%Y-%m-%d %H:%M:%S")
        return f"{created} - {record.levelname} - {label_str}{msg}".strip()

# -------------------------------------
#               Filter
# -------------------------------------
class VulnParseRecordFilter(logging.Filter):
    """
    - Ensure record has req'd fields.
    - Allow call sites to pass vp_label.
    - Maps vp_label to label if label isn't set.
    """
    def __init__(self, default_label: str = ""):
        super().__init__()
        self.default_label = default_label

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "label"):
            record.label = self.default_label

        vp_label = getattr(record, "vp_label", None)
        if vp_label:
            # Override only if it's empty/default
            if not record.label:
                record.label = vp_label

        return True

# -------------------------------------
#               LoggerWrapper
# -------------------------------------

class LoggerWrapper:
    """
    Provides robust logging for Vulnparse-Pin.
        Includes:
        - Console Handler
        - File Handler
        - Convenience methods
    """
    def __init__(self, log_file: str, log_level: str = "INFO"):
        self.logall = logging.getLogger("vulnparse")
        self.log_file = logging.getLogger("vulnparse.fileonly")
        self.logall.handlers.clear()
        self.log_file.handlers.clear()

        level = getattr(logging, log_level.upper(), logging.INFO)
        self.logall.setLevel(level)
        self.logall.propagate = False  # don't bubble to root logger
        self.log_file.setLevel(logging.DEBUG)
        self.log_file.propagate = False

        log_path = Path(log_file)
        if log_path.parent:
            os.makedirs(log_path.parent, exist_ok=True)

        # ------ File Handler ------
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(FileFormatter())

        self.log_file.addHandler(file_handler)

        # ------ Console Handler ------
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(ConsoleFormatter())
        self.logall.addHandler(file_handler)
        self.logall.addHandler(console_handler)

        # ------ Filter -------
        filt = VulnParseRecordFilter(default_label="")
        file_handler.addFilter(filt)
        console_handler.addFilter(filt)


    # ------------- File Only methods -------------

    def debug(self, msg: str, *args, **kwargs) -> None:
        self.log_file.debug(msg, *args, **kwargs)

    def info(self, msg: str, *args, **kwargs) -> None:
        self.log_file.info(msg, *args, **kwargs)

    def warning(self, msg: str, *args, **kwargs) -> None:
        self.log_file.warning(msg, *args, **kwargs)

    def error(self, msg: str, *args, **kwargs) -> None:
        self.log_file.error(msg, *args, **kwargs)

    def exception(self, msg: str, *args, **kwargs) -> None:
        self.log_file.exception(msg, *args, **kwargs)

    def success(self, msg: str, *args, **kwargs) -> None:
        self.log_file.success(msg, *args, **kwargs)

    def phase(self, phase: str) -> None:
        pstr = f'======= {phase.upper()} ======='
        self.logall.info(pstr, extra={"label": "PHASE"})
        self.log_file.debug(pstr, extra=None)

    # ------------- Public log methods (console + file) -------------

    def print_info(self, msg: str, label: Optional[str] = None) -> None:
        self.logall.info(msg, extra={"label": label} if label else {})

    def print_success(self, msg: str, label: Optional[str] = None) -> None:
        self.logall.success(msg, extra={"label": label} if label else {})

    def print_warning(self, msg: str, label: Optional[str] = None) -> None:
        self.logall.warning(msg, extra={"label": label} if label else {})

    def print_error(self, msg: str, label: Optional[str] = None) -> None:
        self.logall.error(msg, extra={"label": label} if label else {})

    def print_debug(self, msg: str, label: Optional[str] = None) -> None:
        self.logall.debug(msg, extra={"label": label} if label else {})

class EnrichmentMissLogger:
    """
    Track CVEs that were attempted during enrichment but had no data.
    """

    def __init__(self, ctx=None, log_file: str | None = None):
        # default destination lives under the runtime log directory if we have
        # a context, otherwise fall back to a relative path.
        if ctx is not None and log_file is None:
            try:
                log_file = str(ctx.paths.log_dir / "missed_enrichments.json")
            except Exception:
                log_file = "logs/missed_enrichments.json"
        self.log_file = log_file or "logs/missed_enrichments.json"
        self.misses = {}
        self.pfh = getattr(ctx, "pfh", None) if ctx is not None else None

        # Create parent directory; PFH will handle this if available.
        if self.pfh:
            # ensure the directory exists via PFH helpers
            self.pfh.ensure_writable_file(self.log_file, create_parents=True, overwrite=True, label="Missed Enrichments")
        else:
            os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

    def log_miss(self, cve_id, cisa_kev=False, epss_score=None):
        if cve_id not in self.misses:
            self.misses[cve_id] = {
                "cisa_kev": cisa_kev,
                "epss_score": epss_score
            }

    def write_log(self):
        if self.pfh:
            with self.pfh.open_for_write(self.log_file, mode="w", encoding="utf-8", label="Missed Enrichments") as f:
                json.dump(self.misses, f, indent=4)
        else:
            with open(self.log_file, "w", encoding="utf-8") as f:
                json.dump(self.misses, f, indent=4)
