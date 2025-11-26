from email import message
from logging.handlers import RotatingFileHandler
import re
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

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

class LoggerWrapper:
    def __init__(self, log_file: str, log_level: str = "INFO"):
        self.logger = logging.getLogger("vulnparse")

        # Avoid adding handlers multiple times if LoggerWrapper is constructed more than once
        if self.logger.handlers:
            return

        level = getattr(logging, log_level.upper(), logging.INFO)
        self.logger.setLevel(level)
        self.logger.propagate = False  # don't bubble to root logger

        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(file_formatter)

        self.logger.addHandler(file_handler)

    @staticmethod
    def _strip_ansi(text: str) -> str:
        return ANSI_RE.sub("", text)

    # ---------------- Label formatter ----------------
    def _format_label(self, label: str, color: str) -> str:
        """
        Return a colored label for console, uncolored for file log.
        """
        if not label:
            return "", ""
        
        console = f'{color}{label}{Style.RESET_ALL}'
        file = f'"{label}"'
        return console, file
    
    # ------------- Public log methods (console + file) -------------

    def print_info(self, msg: str, label: str = None):
        label_console, label_file = self._format_label(label, Fore.CYAN)
        console_msg = f"{Fore.LIGHTCYAN_EX}[INFO] [*]{Style.RESET_ALL} {label_console} {msg}".strip()
        print(console_msg)

        file_msg = f"[INFO] {label_file} {msg}".strip()
        self.logger.info(self._strip_ansi(file_msg))

    def print_success(self, msg: str, label: str = None):
        label_console, label_file = self._format_label(label, Fore.LIGHTGREEN_EX)
        console_msg = f"{Fore.LIGHTGREEN_EX}[SUCCESS] [+]{Style.RESET_ALL} {label_console} {msg}".strip()
        print(console_msg)

        file_msg = f"[SUCCESS] {label_file} {msg}".strip()
        self.logger.info(self._strip_ansi(file_msg))

    def print_warning(self, msg: str, label: str = None):
        label_console, label_file = self._format_label(label, Fore.YELLOW)
        console_msg = f"{Fore.YELLOW}[WARNING] [!]{Style.RESET_ALL} {label_console} {msg}".strip()
        print(console_msg)

        file_msg = f"[WARNING] {label_file} {msg}".strip()
        self.logger.warning(self._strip_ansi(file_msg))

    def print_error(self, msg: str, label: str = None):
        label_console, label_file = self._format_label(label, Fore.RED)
        console_msg = f"{Fore.RED}[ERROR] [-]{Style.RESET_ALL} {label_console} {msg}".strip()
        print(console_msg)

        file_msg = f"[ERROR] {label_file} {msg}".strip()
        self.logger.error(self._strip_ansi(file_msg))

    # ------------- .logger.exception -------------

    def exception(self, msg: str, *args, **kwargs):
        self.logger.exception(self._strip_ansi(msg), *args, **kwargs)
        
class EnrichmentMissLogger:
    def __init__(self, log_file="logs/missed_enrichments.json"):
        self.log_file = log_file
        self.misses = {}
        
        # Create log directory if it doesn't exist.
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        
    def log_miss(self, cve_id, cisa_kev=False, epss_score=None):
        if cve_id not in self.misses:
            self.misses[cve_id] = {
                "cisa_kev": cisa_kev,
                "epss_score": epss_score
            }
    
    def write_log(self):
        with open(self.log_file, "w") as f:
            json.dump(self.misses, f, indent=4)


