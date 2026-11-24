# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os

from colorama import Fore, Style

from vulnparse_pin.app.bootstrap import RuntimeBootstrapState
from vulnparse_pin.app.runtime_helpers import authorize_output_path
from vulnparse_pin.cli.errors import VppError


@dataclass(frozen=True)
class ResolvedIOState:
    scanner_input: Path
    json_output: Path | None
    csv_output: Path | None
    md_output: Path | None
    md_tech_output: Path | None
    runmanifest_output: Path | None
    exploit_db: Path | None
    csv_sanitization_enabled: bool
    kev_source: str | Path | None
    epss_source: str | Path | None
    html_output: Path | None = None
    dossier_output: Path | None = None


def resolve_io_paths_and_modes(args, runtime: RuntimeBootstrapState, kev_feed: str, epss_feed: str) -> ResolvedIOState:
    paths = runtime.paths
    pfh = runtime.pfh
    ctx = runtime.ctx
    logger = runtime.logger

    scanner_input = pfh.ensure_readable_file(args.file, label="Scanner Input")

    kev_path, _, _ = ctx.services.feed_cache.resolve("kev")
    epss_path, _, _ = ctx.services.feed_cache.resolve("epss")

    json_output = None
    if getattr(args, "output", None):
        json_output = authorize_output_path(pfh, args.output, label="JSON Output File")

    csv_output = None
    if getattr(args, "output_csv", None):
        csv_output = authorize_output_path(pfh, args.output_csv, label="CSV Output File")

    md_output = None
    if getattr(args, "output_md", None):
        md_output = authorize_output_path(pfh, args.output_md, label="Markdown Executive Report")

    md_tech_output = None
    if getattr(args, "output_md_technical", None):
        md_tech_output = authorize_output_path(pfh, args.output_md_technical, label="Markdown Technical Report")

    html_output = None
    if getattr(args, "output_html", None):
        html_output = authorize_output_path(pfh, args.output_html, label="HTML Dossier Report")

    dossier_output = None
    if getattr(args, "output_dossier", None):
        raw_dos = str(args.output_dossier)
        # Validate parent & symlinks without creating file prematurely if directory/stem
        if hasattr(pfh, "_to_unresolved_abs_path"):
            dos_abs = pfh._to_unresolved_abs_path(raw_dos)
        else:
            dos_abs = Path(raw_dos).expanduser().resolve()
        if getattr(pfh, "forbid_symlinks_write", True) and hasattr(pfh, "_inspect_raw_symlinks"):
            pfh._inspect_raw_symlinks(dos_abs, label="Dossier Output", op="write", raise_on_error=True)
        if dos_abs.exists() and dos_abs.is_dir():
            if hasattr(pfh, "allow_workspace_root"):
                pfh.allow_workspace_root(dos_abs)
            dossier_output = dos_abs
        else:
            authorize_output_path(pfh, dos_abs.with_suffix(".md"), label="Dossier Markdown Output")
            authorize_output_path(pfh, dos_abs.with_suffix(".html"), label="Dossier HTML Output")
            dossier_output = dos_abs

    runmanifest_output = None
    if getattr(args, "output_runmanifest", None):
        runmanifest_output = authorize_output_path(pfh, args.output_runmanifest, label="RunManifest Output File")

    exploit_db = None
    offline_flag = bool(getattr(args, "offline", False))
    exploit_mode = "offline" if offline_flag and getattr(args, "exploit_db", None) else getattr(args, "exploit_source", "online")
    if (not getattr(args, "no_exploit", False)) and (exploit_mode == "offline" or getattr(args, "exploit_db", None)):
        raw_edb = getattr(args, "exploit_db", None)
        if raw_edb is not None and Path(raw_edb).suffix.lower() == ".csv":
            src = pfh.ensure_readable_file(raw_edb, label="Exploit-DB Input File")
            dst = pfh.ensure_writable_file(
                paths.cache_dir / "exploit_db" / "files_exploit.csv",
                label="Exploit-DB Cache File",
                create_parents=True,
                overwrite=True,
            )
            with pfh.open_for_read(src, mode="rb", label="Exploit-DB Input File") as r, pfh.open_for_write(
                dst, mode="wb", label="Exploit-DB Cached File"
            ) as w:
                w.write(r.read())
            exploit_db = dst
        elif not offline_flag:
            logger.print_error(
                "Exploit enrichment flag + Offline mode set, but no proper local exploit database file passed. "
                "Supply the exploit-db with a proper file path and try again."
            )
            raise RuntimeError(
                "Enrich-exploit and Offline mode set without specifying Exploit-DB argument. "
                "Please supply file path to --exploit-db and try again."
            )

    logger.debug('Scanner input: "%s"', pfh.format_for_log(scanner_input))
    if json_output:
        logger.debug('JSON output: "%s"', pfh.format_for_log(json_output))
    if csv_output:
        logger.debug('CSV output: "%s"', pfh.format_for_log(csv_output))

    csv_sanitization_enabled = not bool(getattr(args, "no_csv_sanitize", False))
    if not csv_sanitization_enabled:
        if not bool(getattr(args, "confirm_unsafe_csv", False)):
            msg = (
                "Refusing to disable CSV cell sanitization without explicit --confirm-unsafe-csv "
                "(spreadsheet formula injection protection)."
            )
            logger.print_error(msg, label="CSV-DANGEROUS_ACTION")
            raise VppError(msg, exit_code=2)
        logger.print_warning(
            f"Running with CSV cell sanitization {Fore.LIGHTRED_EX}OFF{Style.RESET_ALL} (--confirm-unsafe-csv). This action will be logged.",
            label="CSV-DANGEROUS_ACTION",
        )
    else:
        logger.print_info(
            "Sanitization is enabled: dangerous prefixes (=, +, -, @) will be escaped to prevent CSV formula injection.",
            label="CSV-Sanitization",
        )

    def _is_http_url(value: str) -> bool:
        v = str(value).strip().lower()
        return v.startswith("http://") or v.startswith("https://")

    def _is_https_url(value: str) -> bool:
        return str(value).strip().lower().startswith("https://")

    kev_source: str | Path | None = None
    eff_kev_mode: Optional[str] = None
    if not getattr(args, "no_kev", False):
        kev_override = getattr(args, "kev_feed", None)
        eff_kev_mode = "offline" if (offline_flag or (kev_override and not _is_http_url(str(kev_override)))) else getattr(args, "kev_source", "online")
        if kev_override:
            if eff_kev_mode == "offline" and _is_http_url(str(kev_override)):
                raise ValueError("--kev-source offline does not allow HTTP/HTTPS KEV overrides.")
            if eff_kev_mode == "online" and (not _is_https_url(str(kev_override))):
                raise ValueError("--kev-source online requires an HTTPS URL override.")
            kev_source = (
                pfh.ensure_readable_file(kev_override, label="KEV Local Cache File")
                if eff_kev_mode == "offline"
                else kev_override
            )
        else:
            kev_source = kev_path if eff_kev_mode == "offline" else kev_feed

    epss_source: str | Path | None = None
    eff_epss_mode: Optional[str] = None
    if not getattr(args, "no_epss", False):
        epss_override = getattr(args, "epss_feed", None)
        eff_epss_mode = "offline" if (offline_flag or (epss_override and not _is_http_url(str(epss_override)))) else getattr(args, "epss_source", "online")
        if epss_override:
            if eff_epss_mode == "offline" and _is_http_url(str(epss_override)):
                raise ValueError("--epss-source offline does not allow HTTP/HTTPS EPSS overrides.")
            if eff_epss_mode == "online" and (not _is_https_url(str(epss_override))):
                raise ValueError("--epss-source online requires an HTTPS URL override.")
            epss_source = (
                pfh.ensure_readable_file(epss_override, label="EPSS Local Cache File")
                if eff_epss_mode == "offline"
                else epss_override
            )
        else:
            epss_source = epss_path if eff_epss_mode == "offline" else epss_feed

    if (not getattr(args, "no_kev", False)) and eff_kev_mode == "offline":
        logger.print_info("[*] KEV offline mode enabled. Using local cache/file.", label="Mode-Offline")
        if os.path.lexists(str(kev_source)):
            kev_source = pfh.ensure_readable_file(kev_source, label="KEV Local Cache File")
        if not os.path.exists(str(kev_source)):
            logger.print_error(f"[OFFLINE] KEV cache not found: {kev_source}", label="Mode-Offline")
            raise FileNotFoundError("Missing KEV cache.")

    if (not getattr(args, "no_epss", False)) and eff_epss_mode == "offline":
        logger.print_info("[*] EPSS offline mode enabled. Using local cache/file.", label="Mode-Offline")
        if os.path.lexists(str(epss_source)):
            epss_source = pfh.ensure_readable_file(epss_source, label="EPSS Local Cache File")
        if not os.path.exists(str(epss_source)):
            logger.print_error(f"[OFFLINE] EPSS cache not found: {epss_source}", label="Mode-Offline")
            raise FileNotFoundError("Missing EPSS cache.")

    return ResolvedIOState(
        scanner_input=scanner_input,
        json_output=json_output,
        csv_output=csv_output,
        md_output=md_output,
        md_tech_output=md_tech_output,
        runmanifest_output=runmanifest_output,
        exploit_db=exploit_db,
        csv_sanitization_enabled=csv_sanitization_enabled,
        kev_source=kev_source,
        epss_source=epss_source,
        html_output=html_output,
        dossier_output=dossier_output,
    )
