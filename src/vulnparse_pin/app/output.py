# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from copy import deepcopy
import inspect
import json
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from vulnparse_pin.app.runtime_helpers import authorize_output_dir, authorize_output_path
from vulnparse_pin.cli.errors import VppError
from vulnparse_pin.utils.csv_exporter import export_to_csv
from vulnparse_pin.utils.markdown_report import generate_markdown_report
from vulnparse_pin.utils.reportgen import materialize_presentation
from vulnparse_pin.utils.runmanifest import build_runmanifest, write_runmanifest
from vulnparse_pin.utils.webhook_delivery import emit_configured_webhooks


_PRESENTATION_ONLY_FINDING_KEYS = (
    "raw_risk_score",
    "risk_score",
    "risk_band",
    "score_trace",
)


def _materialize_default_json(scan_result: Any) -> Any:
    """Build default JSON output while keeping score fields in derived passes only."""
    if is_dataclass(scan_result):
        out = asdict(scan_result)
    elif isinstance(scan_result, dict):
        out = deepcopy(scan_result)
    else:
        return scan_result

    assets = out.get("assets") if isinstance(out, dict) else None
    if not isinstance(assets, list):
        return out

    for asset in assets:
        if not isinstance(asset, dict):
            continue
        findings = asset.get("findings")
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            for key in _PRESENTATION_ONLY_FINDING_KEYS:
                finding.pop(key, None)
    return out


def _json_payload_for_output(args: Any, scan_result: Any) -> Any:
    if args.presentation:
        if not scan_result.derived.get("Scoring@2.0"):
            raise RuntimeError("Presentation overlay requested, but Scoring@2.0 pass result not found.")
        return materialize_presentation(scan_result, overlay_mode=args.overlay_mode, scoring_pass_key="Scoring@2.0")
    return _materialize_default_json(scan_result)


def write_text_via_pfh(pfh: Any, out_path: Path, text: str, *, label: str) -> Path:
    """Write text report via PermFileHandler using authorized explicit output path."""
    target = authorize_output_path(pfh, out_path, label=label)
    with pfh.open_for_write(target, mode="w", encoding="utf-8", label=label) as fh:
        fh.write(text)
    return target


def _load_renderer():
    from vulnparse_pin.reporting import renderer as _renderer

    return _renderer


_MAX_PRETTY_REFORMAT_BYTES = 50 * 1024 * 1024


def invoke_duckdb_json_export(
    export_json_fn: Callable[..., Any],
    db: Any,
    run_id: str,
    json_path: Path,
    *,
    presentation: str,
    pfh: Any = None,
    pretty_print: bool = False,
) -> None:
    """Invoke export_duckdb_json forwarding pretty_print when supported, with bounded fallback."""
    kwargs: Dict[str, Any] = {"presentation": presentation, "pfh": pfh}
    supports_pretty = False
    try:
        params = inspect.signature(export_json_fn).parameters
        supports_pretty = "pretty_print" in params or any(
            p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()
        )
    except (TypeError, ValueError):
        supports_pretty = False

    if supports_pretty:
        kwargs["pretty_print"] = bool(pretty_print)
    export_json_fn(db, run_id, json_path, **kwargs)

    if pretty_print and not supports_pretty and json_path.is_file() and not json_path.is_symlink():
        if json_path.stat().st_size <= _MAX_PRETTY_REFORMAT_BYTES:
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            pretty_text = json.dumps(payload, indent=4) + "\n"
            if pfh is not None:
                write_text_via_pfh(pfh, json_path, pretty_text, label="JSON Output File")
            else:
                json_path.write_text(pretty_text, encoding="utf-8")


def invoke_duckdb_csv_export(
    export_csv_fn: Callable[..., Any],
    db: Any,
    run_id: str,
    csv_path: Path,
    *,
    profile: str,
    pfh: Any = None,
    csv_sanitization: bool = True,
) -> None:
    """Invoke export_duckdb_csv forwarding csv_sanitization when supported."""
    kwargs: Dict[str, Any] = {"profile": profile, "pfh": pfh}
    try:
        params = inspect.signature(export_csv_fn).parameters
        if "csv_sanitization" in params or any(
            p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()
        ):
            kwargs["csv_sanitization"] = bool(csv_sanitization)
    except (TypeError, ValueError):
        pass
    export_csv_fn(db, run_id, csv_path, **kwargs)


def export_v2_outputs(
    *,
    ctx: Any,
    db: Any,
    run_id: str,
    args: Any,
    diff_report: Optional[Any] = None,
    config_hashes: Optional[Dict[str, Optional[str]]] = None,
) -> Dict[str, Optional[Path]]:
    """Export requested v2 DuckDB artifacts (dossier, html, md, csv, json, runmanifest)."""
    from vulnparse_pin.utils import csv_exporter as _csv_exp
    from vulnparse_pin.utils import reportgen as _reportgen
    from vulnparse_pin.utils import runmanifest as _rm

    pfh = ctx.pfh
    template_dir = getattr(args, "template_dir", None)
    written: Dict[str, Optional[Path]] = {
        "json": None,
        "csv": None,
        "executive_markdown": None,
        "technical_markdown": None,
        "dossier_markdown": None,
        "dossier_html": None,
        "runmanifest": None,
    }

    output_all = getattr(args, "output_all", None)
    stem = str(Path(output_all).with_suffix("")) if output_all else None

    json_req = getattr(args, "output", None) or (f"{stem}.json" if stem else None)
    csv_req = getattr(args, "output_csv", None) or (f"{stem}.csv" if stem else None)
    md_req = getattr(args, "output_md", None) or (f"{stem}_summary.md" if stem else None)
    md_tech_req = getattr(args, "output_md_technical", None) or (f"{stem}_technical.md" if stem else None)
    html_req = getattr(args, "output_html", None)
    dossier_req = getattr(args, "output_dossier", None) or (f"{stem}_dossier" if stem and not html_req else None)
    rm_req = getattr(args, "output_runmanifest", None) or (f"{stem}_runmanifest.json" if stem else None)

    csv_sanitization = not bool(getattr(args, "no_csv_sanitize", False))
    if not csv_sanitization and not bool(getattr(args, "confirm_unsafe_csv", False)):
        raise VppError(
            "Refusing to disable CSV cell sanitization without explicit --confirm-unsafe-csv.",
            exit_code=2,
        )
    pretty_print = bool(getattr(args, "pretty_print", False))

    if json_req:
        json_path = authorize_output_path(pfh, json_req, label="JSON Output File")
        pres_mode = (
            str(getattr(args, "overlay_mode", "namespace") or "namespace")
            if getattr(args, "presentation", False)
            else "namespace"
        )
        if pres_mode == "flatten" and not getattr(args, "presentation", False):
            pres_mode = "namespace"
        export_json_fn = getattr(_reportgen, "export_duckdb_json", None)
        if callable(export_json_fn):
            invoke_duckdb_json_export(
                export_json_fn,
                db,
                run_id,
                json_path,
                presentation=pres_mode,
                pfh=pfh,
                pretty_print=pretty_print,
            )
        written["json"] = json_path

    if csv_req:
        csv_path = authorize_output_path(pfh, csv_req, label="CSV Output File")
        csv_profile = str(getattr(args, "csv_profile", "full") or "full")
        export_csv_fn = getattr(_csv_exp, "export_duckdb_csv", None)
        if callable(export_csv_fn):
            invoke_duckdb_csv_export(
                export_csv_fn,
                db,
                run_id,
                csv_path,
                profile=csv_profile,
                pfh=pfh,
                csv_sanitization=csv_sanitization,
            )
        written["csv"] = csv_path

    if dossier_req:
        _renderer = _load_renderer()
        raw_dos = str(dossier_req)
        dos_path = Path(raw_dos)
        if raw_dos.endswith(("/", os.sep)) or (dos_path.exists() and dos_path.is_dir()):
            dos_dir = authorize_output_dir(pfh, dos_path, label="Dossier Output Directory")
            bundle = _renderer.export_dossier_bundle(
                db,
                run_id,
                dos_dir,
                diff_report=diff_report,
                template_dir=template_dir,
                pfh=pfh,
            )
            written["dossier_markdown"] = Path(bundle["markdown"])
            written["dossier_html"] = Path(bundle["html"])
        else:
            md_target = dos_path.with_suffix(".md")
            html_target = dos_path.with_suffix(".html")
            md_text = _renderer.render_dossier_markdown(
                db, run_id, diff_report=diff_report, template_dir=template_dir
            )
            html_text = _renderer.render_dossier_html(
                db, run_id, diff_report=diff_report, template_dir=template_dir
            )
            written["dossier_markdown"] = write_text_via_pfh(
                pfh, md_target, md_text, label="Dossier Markdown"
            )
            written["dossier_html"] = write_text_via_pfh(
                pfh, html_target, html_text, label="Dossier HTML"
            )

    if html_req:
        _renderer = _load_renderer()
        html_text = _renderer.render_dossier_html(
            db, run_id, diff_report=diff_report, template_dir=template_dir
        )
        written["dossier_html"] = write_text_via_pfh(
            pfh, Path(html_req), html_text, label="HTML Dossier Report"
        )

    if md_req:
        _renderer = _load_renderer()
        md_text = _renderer.render_executive_roadmap_markdown(
            db, run_id, diff_report=diff_report, template_dir=template_dir
        )
        written["executive_markdown"] = write_text_via_pfh(
            pfh, Path(md_req), md_text, label="Markdown Report"
        )

    if md_tech_req:
        _renderer = _load_renderer()
        md_tech_text = _renderer.render_dossier_markdown(
            db, run_id, diff_report=diff_report, template_dir=template_dir
        )
        written["technical_markdown"] = write_text_via_pfh(
            pfh, Path(md_tech_req), md_tech_text, label="Markdown Technical Report"
        )

    if rm_req:
        rm_path = authorize_output_path(pfh, rm_req, label="RunManifest Output File")
        outputs_meta = {
            "json": str(written["json"]) if written["json"] else None,
            "csv": str(written["csv"]) if written["csv"] else None,
            "executive_markdown": str(written["executive_markdown"] or written["dossier_markdown"])
            if (written["executive_markdown"] or written["dossier_markdown"])
            else None,
            "technical_markdown": str(written["technical_markdown"] or written["dossier_markdown"])
            if (written["technical_markdown"] or written["dossier_markdown"])
            else None,
            "dossier_markdown": str(written["dossier_markdown"]) if written["dossier_markdown"] else None,
            "dossier_html": str(written["dossier_html"]) if written["dossier_html"] else None,
        }
        build_rm_db = getattr(_rm, "build_runmanifest_from_db", None)
        if callable(build_rm_db):
            manifest = build_rm_db(
                db,
                run_id,
                config_hashes=config_hashes,
                outputs=outputs_meta,
                mode=str(getattr(args, "runmanifest_mode", "compact") or "compact"),
            )
            write_runmanifest(ctx, manifest, rm_path)
            digest = (manifest.get("verification") or {}).get("manifest_digest")
            if digest:
                try:
                    db.execute("UPDATE runs SET manifest_digest = ? WHERE run_id = ?", [digest, run_id])
                except Exception:
                    pass
            written["runmanifest"] = rm_path

    return written


def run_output_and_summary(
    args,
    ctx,
    scan_result,
    sources: dict,
    json_output,
    csv_output,
    md_output,
    md_tech_output,
    runmanifest_output,
    scanner_input: Path,
    csv_sanitization_enabled: bool,
    kev_source,
    epss_source,
    start_time: float,
    write_output_fn: Callable[..., Any],
    print_summary_banner_fn: Callable[..., Any],
    json_default_fn: Callable[..., Any],
    format_runtime_fn: Callable[[float], str],
) -> int:
    logger = ctx.logger

    if args.output or args.output_csv:
        logger.phase("Output")

    if args.output_all:
        out = _json_payload_for_output(args, scan_result)
        write_output_fn(ctx, data=out, file_path=json_output, pretty_print=args.pretty_print)
        export_to_csv(
            ctx,
            scan_result,
            csv_path=csv_output,
            csv_sanitization=csv_sanitization_enabled,
            csv_profile=getattr(args, "csv_profile", "full"),
        )
        generate_markdown_report(ctx, scan_result, md_output, report_type="executive", args=args)
        generate_markdown_report(ctx, scan_result, md_tech_output, report_type="technical", args=args)
    else:
        if args.output:
            out = _json_payload_for_output(args, scan_result)
            write_output_fn(ctx, data=out, file_path=json_output, pretty_print=args.pretty_print)

        if args.output_csv:
            export_to_csv(
                ctx,
                scan_result,
                csv_path=csv_output,
                csv_sanitization=csv_sanitization_enabled,
                csv_profile=getattr(args, "csv_profile", "full"),
            )

        if md_output:
            generate_markdown_report(ctx, scan_result, md_output, report_type="executive", args=args)

        if md_tech_output:
            generate_markdown_report(ctx, scan_result, md_tech_output, report_type="technical", args=args)

    emit_configured_webhooks(
        ctx=ctx,
        scan_result=scan_result,
        scanner_input=scanner_input,
        output_paths={
            "json": json_output,
            "csv": csv_output,
            "md": md_output,
            "md_technical": md_tech_output,
            "runmanifest": runmanifest_output,
        },
    )

    if runmanifest_output:
        runmanifest = build_runmanifest(
            ctx=ctx,
            _args=args,
            scan_result=scan_result,
            sources=sources,
            scanner_input=scanner_input,
            output_paths={
                "json": json_output,
                "csv": csv_output,
                "md": md_output,
                "md_technical": md_tech_output,
            },
        )
        write_runmanifest(ctx, runmanifest, runmanifest_output)
        logger.print_success(f"Run manifest generated: {runmanifest_output}", label="RunManifest")

    if args.pretty_print and not args.output:
        logger.print_info("Displaying results to console...")
        out = _json_payload_for_output(args, scan_result)
        print(json.dumps(out, indent=4, default=json_default_fn))

    if kev_source or epss_source:
        logger.phase("Summary")
        print_summary_banner_fn(ctx, scan_result, json_output if json_output else None, sources=sources)

    total_runtime = time.time() - start_time
    print(f"Total runtime: {format_runtime_fn(total_runtime)}")
    return 0
