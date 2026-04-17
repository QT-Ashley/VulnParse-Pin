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
import os
import sys

from colorama import Fore, Style

from vulnparse_pin.app.bootstrap import RuntimeBootstrapState
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
    kev_source: str | Path
    epss_source: str | Path


def resolve_io_paths_and_modes(args, runtime: RuntimeBootstrapState, kev_feed: str, epss_feed: str) -> ResolvedIOState:
    paths = runtime.paths
    pfh = runtime.pfh
    ctx = runtime.ctx
    logger = runtime.logger

    scanner_input = pfh.ensure_readable_file(args.file, label="Scanner Input")

    kev_path = None
    kev_path, _, _ = ctx.services.feed_cache.resolve("kev")

    epss_path = None
    epss_path, _, _ = ctx.services.feed_cache.resolve("epss")

    json_output = None
    if getattr(args, "output", None):
        json_output = pfh.ensure_writable_file(
            paths.output_dir / Path(args.output).name,
            label="JSON Output File",
            create_parents=True,
            overwrite=True,
        )

    csv_output = None
    if getattr(args, "output_csv", None):
        csv_output = pfh.ensure_writable_file(
            paths.output_dir / Path(args.output_csv).name,
            label="CSV Output File",
            create_parents=True,
            overwrite=True,
        )

    md_output = None
    if getattr(args, "output_md", None):
        md_output = pfh.ensure_writable_file(
            paths.output_dir / Path(args.output_md).name,
            label="Markdown Executive Report",
            create_parents=True,
            overwrite=True,
        )

    md_tech_output = None
    if getattr(args, "output_md_technical", None):
        md_tech_output = pfh.ensure_writable_file(
            paths.output_dir / Path(args.output_md_technical).name,
            label="Markdown Technical Report",
            create_parents=True,
            overwrite=True,
        )

    runmanifest_output = None
    if getattr(args, "output_runmanifest", None):
        runmanifest_output = pfh.ensure_writable_file(
            paths.output_dir / Path(args.output_runmanifest).name,
            label="RunManifest Output File",
            create_parents=True,
            overwrite=True,
        )

    src = None
    dst = None
    exploit_db = None
    if (not args.no_exploit) and args.exploit_source == "offline":
        if args.exploit_db is not None and Path(args.exploit_db).suffix == ".csv":
            src = pfh.ensure_readable_file(args.exploit_db, label="Exploit-DB Input File")
            dst = pfh.ensure_writable_file(paths.cache_dir / "exploit_db" / "files_exploit.csv", label="Exploit-DB Cache File", create_parents=True, overwrite=True)

            with pfh.open_for_read(src, mode="rb", label="Exploit-DB Input File") as r, pfh.open_for_write(dst, mode="wb", label="Exploit-DB Cached File") as w:
                w.write(r.read())

            exploit_db = dst
        else:
            logger.print_error("Exploit enrichment flag + Offline mode set, but no proper local exploit database file passed. Supply the exploit-db with a proper file path and try again.")
            raise RuntimeError("Enrich-exploit and Offline mode set without specifying Exploit-DB argument. Please supply file path to --exploit-db and try again.")

    logger.debug('Scanner input: "%s"', pfh.format_for_log(scanner_input))
    if json_output:
        logger.debug('JSON output: "%s"', pfh.format_for_log(json_output))
    if csv_output:
        logger.debug('CSV output: "%s"', pfh.format_for_log(csv_output))

    csv_sanitization_enabled = not args.no_csv_sanitize
    if not csv_sanitization_enabled:
        while True:
            logger.print_warning(
                f"CSV Cell Sanitization has been disabled. This presents a {Fore.LIGHTRED_EX}MAJOR injection vulnerability in spreadsheet tools when opening this CSV.{Style.RESET_ALL}",
                label="CSV-DANGEROUS_ACTION",
            )
            warn = input("Are you sure you want to proceed? Yes/No: ").strip().lower()

            if warn in ("yes", "y"):
                logger.print_warning(
                    f"Running with CSV cell sanitization {Fore.LIGHTRED_EX}OFF{Style.RESET_ALL}. This action will be logged.",
                    label="CSV-DANGEROUS_ACTION",
                )
                break
            elif warn in ("no", "n"):
                logger.print_info("Aborting at user request.", label="CSV-DANGEROUS_ACTION")
                sys.exit(0)
            else:
                logger.print_warning("Please answer 'yes' or 'no'.", label="CSV-DANGEROUS_ACTION")
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

    kev_source = None
    if not args.no_kev:
        kev_override = getattr(args, "kev_feed", None)
        if kev_override:
            if args.kev_source == "offline" and _is_http_url(str(kev_override)):
                raise ValueError("--kev-source offline does not allow HTTP/HTTPS KEV overrides.")
            if args.kev_source == "online" and (not _is_https_url(str(kev_override))):
                raise ValueError("--kev-source online requires an HTTPS URL override.")
            kev_source = pfh.ensure_readable_file(kev_override, label="KEV Local Cache File") if args.kev_source == "offline" else kev_override
        else:
            kev_source = kev_path if args.kev_source == "offline" else kev_feed

    epss_source = None
    if not args.no_epss:
        epss_override = getattr(args, "epss_feed", None)
        if epss_override:
            if args.epss_source == "offline" and _is_http_url(str(epss_override)):
                raise ValueError("--epss-source offline does not allow HTTP/HTTPS EPSS overrides.")
            if args.epss_source == "online" and (not _is_https_url(str(epss_override))):
                raise ValueError("--epss-source online requires an HTTPS URL override.")
            epss_source = pfh.ensure_readable_file(epss_override, label="EPSS Local Cache File") if args.epss_source == "offline" else epss_override
        else:
            epss_source = epss_path if args.epss_source == "offline" else epss_feed

    if (not args.no_kev) and args.kev_source == "offline":
        logger.print_info("[*] KEV offline mode enabled. Using local cache/file.", label="Mode-Offline")
        if not os.path.exists(str(kev_source)):
            logger.print_error(f"[OFFLINE] KEV cache not found: {kev_source}", label="Mode-Offline")
            raise FileNotFoundError("Missing KEV cache.")

    if (not args.no_epss) and args.epss_source == "offline":
        logger.print_info("[*] EPSS offline mode enabled. Using local cache/file.", label="Mode-Offline")
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
    )
