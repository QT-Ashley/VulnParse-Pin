# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

"""Interactive Textual terminal UI for VulnParse-Pin v2."""

from __future__ import annotations

import logging
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from uuid import uuid4

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Select,
    Static,
    TabbedContent,
    TabPane,
)

from vulnparse_pin import __version__
from vulnparse_pin.app.runtime_helpers import authorize_output_dir, authorize_output_path
from vulnparse_pin.core.apppaths import AppPaths
from vulnparse_pin.core.assets_context import DecisionsRegistry, upsert_decision
from vulnparse_pin.core.classes.dataclass import RunContext, Services
from vulnparse_pin.core.classes.execution_manifest import LedgerService
from vulnparse_pin.core.config_projector import ConfigProjector
from vulnparse_pin.core.diff_engine import DiffEngine
from vulnparse_pin.core.passes.Triage.triage_pass import TriageDecisionPass
from vulnparse_pin.storage.db import _check_no_symlinks_or_loops
from vulnparse_pin.utils.cvss_utils import resolve_effective_cvss_fields
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.storage.db import VppDatabase
from vulnparse_pin.storage.repositories import (
    get_finding_detail,
    get_run_summary_counts,
    get_shadow_assets,
    list_runs,
    query_findings_page,
)

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

_DEFAULT_CSS = """
Screen {
    layout: vertical;
    overflow-y: hidden;
}
#kpi-banner {
    height: auto;
    padding: 0 1;
    background: $panel;
    color: $text;
    border-bottom: solid $primary;
}
#filter-bar {
    height: auto;
    padding: 0 1;
    background: $surface;
    color: $text-muted;
}
#status-line {
    height: auto;
    padding: 0 1;
    color: $accent;
}
#search-input {
    margin: 0 1;
}
#main-tabs {
    height: 1fr;
}
TabPane {
    height: 1fr;
    padding: 0;
}
#findings-split {
    height: 1fr;
}
#findings-table {
    width: 58%;
    height: 1fr;
    border: solid $primary-darken-2;
}
#inspector-scroll {
    width: 42%;
    height: 1fr;
    border: solid $secondary-darken-2;
    padding: 0 1;
}
#diff-scroll {
    height: 1fr;
    padding: 0 1;
}
DeferralModal {
    align: center middle;
}
#defer-dialog {
    width: 68;
    max-width: 92%;
    height: auto;
    max-height: 90%;
    padding: 1 2;
    background: $surface;
    border: thick $primary;
}
#defer-buttons {
    margin-top: 1;
    height: auto;
    align: right middle;
}
#defer-buttons Button {
    margin-left: 1;
}
#defer-error {
    color: $error;
    height: auto;
}
"""


def _build_silent_ui_pfh(base_dir: Path) -> PermFileHandler:
    ui_logger = logging.getLogger("vulnparse_pin.ui")
    if not ui_logger.handlers:
        ui_logger.addHandler(logging.NullHandler())
    ui_logger.propagate = False
    return PermFileHandler(
        logger=ui_logger,
        root_dir=base_dir,
        allowed_roots=[base_dir],
        max_log_path_chars=32,
        hide_home=True,
        forbid_symlinks_read=True,
        forbid_symlinks_write=True,
        enforce_roots_on_read=False,
        enforce_roots_on_write=True,
        file_mode=0o600,
        dir_mode=0o700,
    )


def _format_score_trace_lines(detail: Dict[str, Any]) -> List[str]:
    trace = detail.get("score_trace") or {}
    lines: List[str] = ["[Score Trace]"]
    op_val = detail.get("operational_score")
    op_str = f"{float(op_val):.2f}" if isinstance(op_val, (int, float)) and not isinstance(op_val, bool) else "0.00"
    raw_val = detail.get("raw_risk_score") if detail.get("raw_risk_score") is not None else trace.get("raw_risk_score")
    raw_str = str(raw_val) if raw_val is not None else "n/a"
    sig_val = (
        detail.get("signal_reliability")
        if detail.get("signal_reliability") is not None
        else trace.get("signal_reliability")
    )
    sig_str = str(sig_val) if sig_val is not None else "n/a"
    trace_dict = trace if isinstance(trace, dict) else {}
    has_explicit_prov = bool(str(detail.get("cvss_provenance") or trace_dict.get("cvss_provenance") or "").strip())
    eff_cvss, eff_prov, eff_ver, _ = resolve_effective_cvss_fields(
        snap_cvss=detail.get("cvss_score"),
        snap_prov=detail.get("cvss_provenance"),
        snap_ver=detail.get("cvss_version"),
        snap_vec=detail.get("cvss_vector"),
        scanner_cvss=detail.get("scanner_cvss_score"),
        scanner_vec=detail.get("scanner_cvss_vector"),
        score_trace=trace_dict,
        treat_bare_zero_trace_as_score=not has_explicit_prov,
    )
    cvss_str = str(eff_cvss) if eff_cvss is not None else "n/a"
    prov_str = eff_prov if has_explicit_prov or eff_cvss is not None or eff_prov != "Missing" else "n/a"
    lines.append(
        f"  Track: {trace_dict.get('scoring_track') or detail.get('scoring_track') or 'unknown'} | "
        f"OpScore: {op_str} | "
        f"Raw: {raw_str} | "
        f"Signal Reliability: {sig_str}"
    )
    lines.append(
        f"  CVSS: {cvss_str} "
        f"({eff_ver or 'n/a'}, "
        f"prov={prov_str})"
    )
    epss_val = detail.get("epss_score") if detail.get("epss_score") is not None else trace_dict.get("epss_score")
    epss_pct = (
        detail.get("epss_percentile") if detail.get("epss_percentile") is not None else trace_dict.get("epss_percentile")
    )
    epss_str = f"{float(epss_val):.4f}" if epss_val is not None else "n/a"
    pct_str = f"{float(epss_pct) * 100:.1f}%" if epss_pct is not None else "n/a"
    lines.append(
        f"  EPSS: {epss_str} (pct={pct_str}, model={detail.get('epss_model_version') or trace_dict.get('epss_model_version') or 'n/a'})"
    )
    in_kev_val = bool(detail.get("in_kev") or trace_dict.get("in_kev"))
    lines.append(
        f"  KEV: {in_kev_val} | "
        f"Verified Exploit: {bool(detail.get('verified_exploit') or trace_dict.get('verified_exploit', False))} | "
        f"Detection Mode: {detail.get('detection_mode') or trace_dict.get('detection_mode') or 'n/a'}"
    )
    kev_added = detail.get("kev_date_added") or (trace_dict.get("kev_date_added") if in_kev_val else None)
    kev_due = detail.get("kev_due_date") or (trace_dict.get("kev_due_date") if in_kev_val else None)
    kev_ransom = detail.get("kev_ransomware")
    if in_kev_val and (kev_ransom is None or kev_ransom == ""):
        kev_ransom = trace_dict.get("kev_ransomware")
    if in_kev_val and (kev_added or kev_due or (kev_ransom is not None and kev_ransom != "")):
        lines.append(
            f"  KEV Dates: added={kev_added or 'n/a'}, "
            f"due={kev_due or 'n/a'}, ransomware={kev_ransom if kev_ransom not in (None, '') else 'n/a'}"
        )
    caps = detail.get("capabilities") or trace.get("aci_capabilities") or []
    chains = detail.get("chains") or trace.get("aci_chains") or []
    if caps or chains:
        lines.append(f"  ACI Capabilities: {', '.join(str(c) for c in caps) or 'none'}")
        if chains:
            lines.append(f"  ACI Chains: {', '.join(str(c) for c in chains)}")

    breakdown = trace.get("breakdown")
    if isinstance(breakdown, dict) and breakdown:
        lines.append("  Breakdown:")
        for key, val in breakdown.items():
            lines.append(f"    - {key}: {val}")
    return lines


def _format_finding_inspector(
    detail: Optional[Dict[str, Any]],
    *,
    has_findings: bool,
    db_path: Optional[Union[str, Path]] = None,
    run_id: Optional[str] = None,
    run_count: int = 0,
) -> str:
    if not detail:
        if not has_findings:
            lines = [
                "No findings match the current filter or run.",
                "",
            ]
            if db_path is not None:
                lines.append(f"Workspace DB : {db_path}")
            if run_id:
                lines.append(f"Active Run   : {run_id} ({run_count} run(s) in DB)")
            lines.extend(
                [
                    "",
                    "Tips:",
                    "  - Press '0' to clear active filters.",
                    "  - Press 'r' to cycle to another scan run in this DB.",
                    "  - Press 'd' to review Diff & Shadow Assets.",
                    "  - Pass '--db PATH' if your scan wrote elsewhere (e.g. 'vpp ui --db .vpp-demo.db').",
                ]
            )
            return "\n".join(lines)
        return "Select a finding row to inspect score_trace, SSVC path, and merged evidence."

    trace = detail.get("score_trace") or {}
    eff_primary_cve = detail.get("primary_cve") or (trace.get("primary_cve") if isinstance(trace, dict) else None)
    lines: List[str] = [
        f"=== {detail.get('title') or detail.get('finding_id')} ===",
        f"Finding ID   : {detail.get('finding_id')}",
        f"Primary CVE  : {eff_primary_cve or 'Non-CVE / Exposure'}",
        f"CVEs / CWEs  : {', '.join(detail.get('cves') or []) or 'none'} | {', '.join(detail.get('cwes') or []) or 'none'}",
        f"Priority     : {detail.get('priority_tier') or 'n/a'} ({detail.get('oal_compat') or 'n/a'}) | "
        f"SSVC={detail.get('ssvc_action') or 'n/a'} | SLA={detail.get('sla_bucket') or 'n/a'} ({detail.get('sla_days') or 'n/a'}d)",
        f"Decision     : {detail.get('decision_status') or 'active'}"
        + (f" [{detail.get('decision_id')}]" if detail.get("decision_id") else ""),
        "",
        "[Asset Context]",
        f"  Identity   : {detail.get('hostname') or detail.get('ip_address') or detail.get('target_uri') or detail.get('image_or_repo') or detail.get('asset_id')}",
        f"  Inventory  : {detail.get('inventory_status') or 'unknown'} | Internet-Facing: {bool(detail.get('internet_facing'))} | Owner: {detail.get('owner') or 'unassigned'}",
    ]
    aliases = detail.get("asset_aliases") or []
    if aliases:
        alias_strs = [
            f"{a.get('alias_type', '')}:{a.get('alias_value', '')}" if isinstance(a, dict) else str(a)
            for a in aliases
        ]
        lines.append(f"  Aliases    : {', '.join(alias_strs)}")
    ports = detail.get("open_ports") or []
    if ports:
        port_strs = [
            f"{p.get('port')}/{p.get('proto', 'tcp')}({p.get('service') or '?'})" if isinstance(p, dict) else str(p)
            for p in ports[:12]
        ]
        lines.append(f"  Open Ports : {', '.join(port_strs)}")

    lines.append("")
    lines.extend(_format_score_trace_lines(detail))

    assumed = detail.get("assumed_state") or {}
    if assumed or detail.get("rationale_summary"):
        lines.append("")
        lines.append("[Triage & Assumed State]")
        if detail.get("rationale_summary"):
            lines.append(f"  Rationale  : {detail.get('rationale_summary')}")
        if isinstance(assumed, dict) and assumed.get("ssvc_path"):
            lines.append(f"  SSVC Path  : {assumed.get('ssvc_path')}")

    evidence = detail.get("evidence") or []
    lines.append("")
    lines.append(f"[Merged Scanner Evidence ({len(evidence)} source(s))]")
    for idx, ev in enumerate(evidence, start=1):
        lines.append(
            f"  #{idx} [{ev.get('source_format') or 'unknown'}] sig={ev.get('scanner_sig') or 'n/a'} "
            f"| sev={ev.get('raw_severity') or 'n/a'} | cvss={ev.get('raw_cvss') or 'n/a'}"
        )
        if ev.get("raw_location"):
            lines.append(f"      location: {ev.get('raw_location')}")
        excerpt = str(ev.get("evidence_excerpt") or "").strip()
        if excerpt:
            lines.append(f"      excerpt : {excerpt[:180]}")

    return "\n".join(lines)


class DeferralModal(ModalScreen[Optional[Dict[str, Any]]]):
    """Modal form to record or update a finding deferral/acceptance/mitigation."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, *, finding: Optional[Dict[str, Any]] = None) -> None:
        super().__init__()
        self._finding = finding or {}

    def compose(self) -> ComposeResult:
        default_asset = str(
            self._finding.get("hostname")
            or self._finding.get("ip_address")
            or self._finding.get("image_or_repo")
            or self._finding.get("target_uri")
            or self._finding.get("asset_id")
            or "*"
        )
        cves = self._finding.get("cves") or []
        default_id = str(
            self._finding.get("primary_cve")
            or (cves[0] if cves else None)
            or self._finding.get("finding_id")
            or ""
        )

        with Vertical(id="defer-dialog"):
            yield Label("Record / Update Triage Decision")
            yield Label("Asset Pattern:")
            yield Input(value=default_asset, id="defer-asset")
            yield Label("CVE or Rule ID:")
            yield Input(value=default_id, id="defer-id")
            yield Label("Status:")
            yield Select(
                options=[
                    ("deferred", "deferred"),
                    ("accepted", "accepted"),
                    ("mitigated", "mitigated"),
                ],
                value="deferred",
                allow_blank=False,
                id="defer-status",
            )
            yield Label("Rationale:")
            yield Input(placeholder="Justification for deferral/acceptance/mitigation", id="defer-rationale")
            yield Label("Owner:")
            yield Input(placeholder="Owner (e.g., secops@acme.test)", id="defer-owner")
            yield Label("Expires (optional YYYY-MM-DD):")
            yield Input(placeholder="YYYY-MM-DD", id="defer-expires")
            yield Static("", id="defer-error")
            with Horizontal(id="defer-buttons"):
                yield Button("Save", variant="primary", id="defer-save")
                yield Button("Cancel", id="defer-cancel")

    def on_mount(self) -> None:
        self.query_one("#defer-rationale", Input).focus()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "defer-cancel":
            self.dismiss(None)
            return
        if event.button.id != "defer-save":
            return

        asset_pattern = self.query_one("#defer-asset", Input).value.strip()
        cve_or_rule_id = self.query_one("#defer-id", Input).value.strip()
        status_val = self.query_one("#defer-status", Select).value
        status = str(status_val if status_val is not None else "deferred").strip().lower()
        rationale = self.query_one("#defer-rationale", Input).value.strip()
        owner = self.query_one("#defer-owner", Input).value.strip()
        expires = self.query_one("#defer-expires", Input).value.strip()

        err_widget = self.query_one("#defer-error", Static)
        if not asset_pattern or not cve_or_rule_id or not rationale or not owner:
            err_widget.update("Asset Pattern, CVE/Rule ID, Rationale, and Owner are required.")
            return
        if expires:
            if not _DATE_RE.match(expires):
                err_widget.update("Expiry date must use YYYY-MM-DD format.")
                return
            try:
                date.fromisoformat(expires)
            except ValueError:
                err_widget.update(f"Invalid calendar expiry date: {expires}")
                return

        payload: Dict[str, Any] = {
            "asset_pattern": asset_pattern,
            "cve_or_rule_id": cve_or_rule_id,
            "status": status,
            "rationale": rationale,
            "owner": owner,
        }
        if expires:
            payload["expires_at"] = expires
        self.dismiss(payload)


class VppApp(App[None]):
    """Interactive DuckDB-backed triage, diff, and dossier defense console."""

    TITLE = f"VulnParse-Pin v{__version__}"
    SUB_TITLE = "Evidence-Backed Vulnerability Triage & Defense Console"
    CSS = _DEFAULT_CSS

    BINDINGS = [
        Binding("1", "filter_priority('P1')", "P1", priority=False),
        Binding("2", "filter_priority('P2')", "P2", priority=False),
        Binding("3", "filter_priority('P3')", "P3", priority=False),
        Binding("4", "filter_priority('P4')", "P4", priority=False),
        Binding("0", "clear_filters", "All", priority=False),
        Binding("t", "cycle_track", "Track", priority=False),
        Binding("k", "toggle_kev", "KEV", priority=False),
        Binding("u", "toggle_unmatched", "Shadow", priority=False),
        Binding("slash", "focus_search", "Search", key_display="/", priority=False),
        Binding("escape", "unfocus_search", "Table", priority=False, show=False),
        Binding("left_square_bracket", "prev_page", "Prev", key_display="[", priority=False),
        Binding("right_square_bracket", "next_page", "Next", key_display="]", priority=False),
        Binding("d", "switch_diff_tab", "Diff", priority=False),
        Binding("r", "cycle_run", "Run", priority=False),
        Binding("e", "export_selected_dossier", "Export Finding", priority=False),
        Binding("E", "export_full_dossier", "Export Run", priority=False),
        Binding("f", "open_defer_modal", "Defer", priority=False),
        Binding("q", "quit", "Quit", priority=False),
    ]

    _MAIN_ONLY_ACTIONS = {
        "filter_priority",
        "clear_filters",
        "cycle_track",
        "toggle_kev",
        "toggle_unmatched",
        "focus_search",
        "unfocus_search",
        "prev_page",
        "next_page",
        "switch_diff_tab",
        "cycle_run",
        "export_selected_dossier",
        "export_full_dossier",
        "open_defer_modal",
    }

    def __init__(
        self,
        db_path: Union[str, Path],
        *,
        run_id: Optional[str] = None,
        decisions_path: Optional[Union[str, Path]] = None,
        output_dir: Union[str, Path] = ".",
        template_dir: Optional[Union[str, Path]] = None,
        pfh: Optional[PermFileHandler] = None,
        page_size: int = 50,
    ) -> None:
        super().__init__()
        self.db_path = Path(db_path)
        self.run_id = run_id
        self._explicit_run_id: bool = run_id is not None
        self.decisions_path = Path(decisions_path) if decisions_path else None
        self.output_dir = Path(output_dir)
        self.template_dir = Path(template_dir) if template_dir else None
        self.pfh = pfh
        self.page_size = max(1, int(page_size))

        self.filter_priority: Optional[str] = None
        self.filter_track: Optional[str] = None
        self.filter_kev: Optional[bool] = None
        self.filter_inventory: Optional[str] = None
        self.search_query: str = ""
        self.page_offset: int = 0
        self.total_filtered: int = 0
        self.current_rows: List[Dict[str, Any]] = []
        self.selected_finding_id: Optional[str] = None
        self.available_runs: List[Dict[str, Any]] = []
        self.active_run_meta: Optional[Dict[str, Any]] = None
        self.summary_counts: Dict[str, Any] = {}
        self.shadow_assets: List[Dict[str, Any]] = []
        self.diff_report: Optional[Any] = None
        self.invalidated_count: int = 0
        self.last_status_message: str = ""

    def _ensure_pfh(self) -> PermFileHandler:
        if self.pfh is None:
            if self.db_path and str(self.db_path) != ":memory:":
                _check_no_symlinks_or_loops(Path(self.db_path), label="TUI workspace database path")
                base = self.db_path.resolve().parent
            else:
                base = Path.cwd()
            self.pfh = _build_silent_ui_pfh(base)
        return self.pfh

    def check_action(self, action: str, parameters: Tuple[object, ...]) -> Union[bool, None]:
        if action in self._MAIN_ONLY_ACTIONS:
            if isinstance(self.screen, ModalScreen):
                return False
            if isinstance(self.focused, Input) and action != "unfocus_search":
                return False
        if action == "quit" and isinstance(self.screen, ModalScreen):
            return False
        return True

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Loading workspace...", id="kpi-banner", markup=False)
        yield Static("", id="filter-bar", markup=False)
        yield Static("", id="status-line", markup=False)
        with TabbedContent(id="main-tabs"):
            with TabPane("Findings", id="tab-findings"):
                yield Input(
                    placeholder="Filter CVE, title, hostname, IP... (/ to focus, Enter to apply)",
                    id="search-input",
                )
                with Horizontal(id="findings-split"):
                    yield DataTable(id="findings-table", cursor_type="row")
                    with VerticalScroll(id="inspector-scroll"):
                        yield Static("", id="finding-inspector", markup=False)
            with TabPane("Diff & Stale Assumptions", id="tab-diff"):
                with VerticalScroll(id="diff-scroll"):
                    yield Static("Loading diff report...", id="diff-panel", markup=False)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.add_columns("Tier", "Score", "CVE / ID", "Track", "Asset", "SLA", "Status", "KEV", "Title")
        self._reload_all()
        table.focus()

    def _set_status(self, message: str) -> None:
        self.last_status_message = message
        try:
            self.query_one("#status-line", Static).update(message)
        except Exception:
            pass

    def _load_decisions_registry(self) -> Optional[DecisionsRegistry]:
        if self.decisions_path is not None and self.decisions_path.exists():
            return DecisionsRegistry.from_file(self.decisions_path, pfh=self._ensure_pfh())
        return None

    def _reload_all(self) -> None:
        if not self.db_path.exists() or self.db_path.is_symlink():
            self.available_runs = []
            self.summary_counts = {}
            self.shadow_assets = []
            self.diff_report = None
            self.current_rows = []
            self.total_filtered = 0
            self.selected_finding_id = None
            self.invalidated_count = 0
            self.query_one("#kpi-banner", Static).update(
                f"Workspace unavailable: {self.db_path}"
            )
            self.query_one("#filter-bar", Static).update("0 findings")
            self.query_one("#findings-table", DataTable).clear()
            self.query_one("#finding-inspector", Static).update(
                "No DuckDB database found. Run 'vpp scan' or 'vpp demo' first."
            )
            self.query_one("#diff-panel", Static).update("No runs available to compare.")
            return

        with VppDatabase(self.db_path, read_only=True) as db:
            runs = list_runs(db)
            self.available_runs = runs
            if not runs:
                self.summary_counts = {}
                self.shadow_assets = []
                self.diff_report = None
                self.current_rows = []
                self.total_filtered = 0
                self.selected_finding_id = None
                self.invalidated_count = 0
                self.query_one("#kpi-banner", Static).update(
                    f"DB: {self.db_path.name} | 0 runs recorded"
                )
                self.query_one("#filter-bar", Static).update("0 findings")
                self.query_one("#findings-table", DataTable).clear()
                self.query_one("#finding-inspector", Static).update(
                    "No scan runs recorded in this DuckDB workspace."
                )
                self.query_one("#diff-panel", Static).update("No scan runs recorded yet.")
                return

            if self.run_id and any(r["run_id"] == self.run_id for r in runs):
                selected_run = next(r for r in runs if r["run_id"] == self.run_id)
            else:
                selected_run = next(
                    (r for r in runs if int(r.get("finding_count") or 0) > 0),
                    runs[0],
                )
                self.run_id = selected_run["run_id"]
            self.active_run_meta = selected_run

            self.summary_counts = get_run_summary_counts(db, self.run_id)
            self.shadow_assets = get_shadow_assets(db, self.run_id)

            self.diff_report = None
            if len(runs) >= 2:
                try:
                    reg = self._load_decisions_registry()
                    self.diff_report = DiffEngine(db, decisions_registry=reg).compare(
                        target_run_id=self.run_id,
                        persist=False,
                    )
                except ValueError:
                    self.diff_report = None

            self._update_kpi_banner()
            self._reload_findings_with_db(db)
            self._render_diff_panel()

    def _update_kpi_banner(self) -> None:
        counts = self.summary_counts
        by_tier = counts.get("by_priority_tier", {})
        by_sla = counts.get("by_sla_bucket", {})
        by_status = counts.get("by_decision_status", {})

        inv_db = sum(
            int(by_status.get(k, 0) or 0)
            for k in ("deferred_invalidated", "accepted_invalidated", "mitigated_invalidated")
        )
        inv_diff = int(self.diff_report.summary.invalidated_assumptions) if self.diff_report else 0
        self.invalidated_count = max(inv_db, inv_diff)

        shadow_cnt = int(counts.get("shadow_assets", 0) or 0)
        shadow_badge = f"SHADOW ASSETS: {shadow_cnt} [ALERT]" if shadow_cnt > 0 else "SHADOW ASSETS: 0"
        inv_badge = (
            f"INVALIDATED DEFERRALS: {self.invalidated_count} [STALE]"
            if self.invalidated_count > 0
            else "INVALIDATED: 0"
        )
        profile = (self.active_run_meta or {}).get("profile") or "default"
        sla_text = ", ".join(f"{k}:{v}" for k, v in sorted(by_sla.items())) or "none"
        run_ids = [str(r["run_id"]) for r in self.available_runs]
        if self.run_id in run_ids:
            run_pos = f"{run_ids.index(self.run_id) + 1}/{len(run_ids)}"
        else:
            run_pos = f"1/{max(1, len(run_ids))}"

        banner = (
            f"DB: {self.db_path.name} | Run: {self.run_id} ({run_pos}) | Profile: {profile} | "
            f"Findings: {counts.get('total_findings', 0)} "
            f"(KEV={counts.get('kev_findings', 0)}, Dedup={counts.get('deduplicated_findings', 0)})\n"
            f"Tiers: P1={by_tier.get('P1', 0)} P1B={by_tier.get('P1B', 0)} P2={by_tier.get('P2', 0)} "
            f"P3={by_tier.get('P3', 0)} P4={by_tier.get('P4', 0)} | "
            f"{shadow_badge} | {inv_badge}\n"
            f"SLA: {sla_text}"
        )
        self.query_one("#kpi-banner", Static).update(banner)

    def _reload_findings(self) -> None:
        if not self.run_id or not self.db_path.exists():
            return
        with VppDatabase(self.db_path, read_only=True) as db:
            self._reload_findings_with_db(db)

    def _reload_findings_with_db(self, db: VppDatabase) -> None:
        if not self.run_id:
            return
        rows, total = query_findings_page(
            db,
            self.run_id,
            priority_tier=self.filter_priority,
            scoring_track=self.filter_track,
            in_kev=self.filter_kev,
            inventory_status=self.filter_inventory,
            search=self.search_query or None,
            limit=self.page_size,
            offset=self.page_offset,
        )
        if not rows and total > 0 and self.page_offset >= total:
            self.page_offset = max(0, ((total - 1) // self.page_size) * self.page_size)
            rows, total = query_findings_page(
                db,
                self.run_id,
                priority_tier=self.filter_priority,
                scoring_track=self.filter_track,
                in_kev=self.filter_kev,
                inventory_status=self.filter_inventory,
                search=self.search_query or None,
                limit=self.page_size,
                offset=self.page_offset,
            )

        self.current_rows = rows
        self.total_filtered = int(total)

        table = self.query_one("#findings-table", DataTable)
        table.clear()

        for row in rows:
            fid = str(row["finding_id"])
            cve_or_id = str(row.get("primary_cve") or fid)[:20]
            track_short = "CVE" if row.get("scoring_track") == "cve_threat" else "EXP"
            asset_label = str(
                row.get("hostname")
                or row.get("ip_address")
                or row.get("image_or_repo")
                or row.get("target_uri")
                or row.get("asset_id")
            )[:22]
            if row.get("inventory_status") == "unmatched_shadow":
                asset_label = f"{asset_label} [SHD]"
            score_val = row.get("operational_score")
            score_str = f"{float(score_val):.1f}" if score_val is not None else "0.0"
            kev_str = "YES" if row.get("in_kev") else "-"
            table.add_row(
                str(row.get("priority_tier") or "-"),
                score_str,
                cve_or_id,
                track_short,
                asset_label,
                str(row.get("sla_bucket") or "-")[:14],
                str(row.get("decision_status") or "active")[:18],
                kev_str,
                str(row.get("title") or "")[:36],
                key=fid,
            )

        page_num = (self.page_offset // self.page_size) + 1
        total_pages = max(1, (self.total_filtered + self.page_size - 1) // self.page_size)
        filters: List[str] = []
        if self.filter_priority:
            filters.append(f"tier={self.filter_priority}")
        if self.filter_track:
            filters.append(f"track={self.filter_track}")
        if self.filter_kev is True:
            filters.append("kev=true")
        if self.filter_inventory:
            filters.append(f"inventory={self.filter_inventory}")
        if self.search_query:
            filters.append(f"search='{self.search_query}'")
        filter_str = ", ".join(filters) if filters else "none"
        self.query_one("#filter-bar", Static).update(
            f"Filters: [{filter_str}] | Showing {len(rows)} of {self.total_filtered} (Page {page_num}/{total_pages})"
        )

        if rows:
            target_idx = 0
            if self.selected_finding_id:
                for idx, row in enumerate(rows):
                    if str(row["finding_id"]) == self.selected_finding_id:
                        target_idx = idx
                        break
            self.selected_finding_id = str(rows[target_idx]["finding_id"])
            table.move_cursor(row=target_idx)
            detail = get_finding_detail(db, self.run_id, self.selected_finding_id)
            self.query_one("#finding-inspector", Static).update(
                _format_finding_inspector(detail, has_findings=True)
            )
        else:
            self.selected_finding_id = None
            has_any = int(self.summary_counts.get("total_findings", 0) or 0) > 0
            self.query_one("#finding-inspector", Static).update(
                _format_finding_inspector(
                    None,
                    has_findings=has_any,
                    db_path=self.db_path,
                    run_id=self.run_id,
                    run_count=len(self.available_runs),
                )
            )

    def _render_diff_panel(self) -> None:
        lines: List[str] = []
        if self.shadow_assets:
            lines.append(f"=== Unmatched Shadow Assets ({len(self.shadow_assets)}) ===")
            for s in self.shadow_assets:
                ident = s.get("ip_address") or s.get("hostname") or s.get("target_uri") or s.get("canonical_key")
                lines.append(
                    f"  - {ident} (findings={s.get('finding_count', 0)}, kev={s.get('kev_count', 0)}, "
                    f"internet_facing={bool(s.get('internet_facing'))})"
                )
            lines.append("")

        if self.diff_report is None:
            lines.append("Diff requires at least 2 runs in DuckDB (baseline + target).")
            self.query_one("#diff-panel", Static).update("\n".join(lines))
            return

        r = self.diff_report
        sm = r.summary
        lines.extend(
            [
                f"=== Diff Report: {r.base_run_id} -> {r.target_run_id} ===",
                f"  Newly Introduced High Risk : {sm.newly_introduced_high_risk} (all new={sm.newly_introduced_all})",
                f"  Threat Intel Escalated     : {sm.threat_intel_escalated}",
                f"  Verified Remediated        : {sm.verified_remediated} (patched={sm.verified_remediated_confirmed}, asset_missing={sm.verified_remediated_asset_missing})",
                f"  Invalidated Assumptions    : {sm.invalidated_assumptions}",
                f"  Shadow Assets Delta        : +{sm.shadow_assets_new} new / -{sm.shadow_assets_resolved} resolved",
                "",
            ]
        )

        sections = [
            ("Invalidated Assumptions", r.invalidated_assumptions),
            ("Newly Introduced High Risk", r.newly_introduced_high_risk),
            ("Threat Intel Escalated", r.threat_intel_escalated),
            ("Verified Remediated", r.verified_remediated),
        ]
        for label, items in sections:
            lines.append(f"[{label} ({len(items)})]")
            if not items:
                lines.append("  (none)")
                continue
            for item in items[:25]:
                cve = getattr(item, "primary_cve", None) or getattr(item, "finding_id", "")
                asset = (
                    getattr(item, "hostname", None)
                    or getattr(item, "ip_address", None)
                    or getattr(item, "canonical_key", None)
                    or getattr(item, "asset_id", "")
                )
                extra = getattr(item, "invalidated_reasons", None) or getattr(item, "escalation_reasons", None)
                detail_note = f" | reasons={extra}" if extra else ""
                lines.append(
                    f"  - {cve} @ {asset} | tier={getattr(item, 'priority_tier', None) or getattr(item, 'target_priority_tier', None)}"
                    f"{detail_note}"
                )
        self.query_one("#diff-panel", Static).update("\n".join(lines))

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None or event.row_key.value is None or not self.run_id:
            return
        fid = str(event.row_key.value)
        if fid == self.selected_finding_id:
            return
        self.selected_finding_id = fid
        with VppDatabase(self.db_path, read_only=True) as db:
            detail = get_finding_detail(db, self.run_id, fid)
        self.query_one("#finding-inspector", Static).update(
            _format_finding_inspector(detail, has_findings=True)
        )

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "search-input":
            return
        self.search_query = event.value.strip()
        self.page_offset = 0
        self._reload_findings()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "search-input":
            return
        self.search_query = event.value.strip()
        self.page_offset = 0
        self._reload_findings()
        self.query_one("#findings-table", DataTable).focus()

    def action_filter_priority(self, tier: str) -> None:
        self.filter_priority = None if self.filter_priority == tier else tier
        self.page_offset = 0
        self._reload_findings()

    def action_clear_filters(self) -> None:
        self.filter_priority = None
        self.filter_track = None
        self.filter_kev = None
        self.filter_inventory = None
        self.search_query = ""
        self.page_offset = 0
        search_inp = self.query_one("#search-input", Input)
        if search_inp.value:
            search_inp.value = ""
        self._reload_findings()
        self._set_status("Cleared all filters.")

    def action_cycle_track(self) -> None:
        order = [None, "cve_threat", "exposure_weakness"]
        idx = order.index(self.filter_track) if self.filter_track in order else 0
        self.filter_track = order[(idx + 1) % len(order)]
        self.page_offset = 0
        self._reload_findings()

    def action_toggle_kev(self) -> None:
        self.filter_kev = None if self.filter_kev is True else True
        self.page_offset = 0
        self._reload_findings()

    def action_toggle_unmatched(self) -> None:
        self.filter_inventory = None if self.filter_inventory == "unmatched_shadow" else "unmatched_shadow"
        self.page_offset = 0
        self._reload_findings()

    def action_focus_search(self) -> None:
        self.query_one("#main-tabs", TabbedContent).active = "tab-findings"
        self.query_one("#search-input", Input).focus()

    def action_unfocus_search(self) -> None:
        if isinstance(self.focused, Input):
            self.query_one("#findings-table", DataTable).focus()

    def action_prev_page(self) -> None:
        if self.page_offset > 0:
            self.page_offset = max(0, self.page_offset - self.page_size)
            self._reload_findings()

    def action_next_page(self) -> None:
        if (self.page_offset + self.page_size) < self.total_filtered:
            self.page_offset += self.page_size
            self._reload_findings()

    def action_switch_diff_tab(self) -> None:
        tabs = self.query_one("#main-tabs", TabbedContent)
        if tabs.active == "tab-diff":
            tabs.active = "tab-findings"
            self.query_one("#findings-table", DataTable).focus()
        else:
            tabs.active = "tab-diff"
            self.query_one("#diff-scroll", VerticalScroll).focus()

    def action_cycle_run(self) -> None:
        if len(self.available_runs) <= 1:
            self._set_status(f"Only {len(self.available_runs)} run recorded in {self.db_path.name}.")
            return
        run_ids = [str(r["run_id"]) for r in self.available_runs]
        cur_idx = run_ids.index(self.run_id) if self.run_id in run_ids else -1
        next_idx = (cur_idx + 1) % len(self.available_runs)
        next_run = self.available_runs[next_idx]
        self.run_id = str(next_run["run_id"])
        self.page_offset = 0
        self.selected_finding_id = None
        self._reload_all()
        self._set_status(
            f"Switched to run {next_idx + 1}/{len(self.available_runs)}: "
            f"{self.run_id} (findings={int(next_run.get('finding_count') or 0)})"
        )

    def _export_dossier(self, *, finding_id: Optional[str]) -> None:
        if not self.run_id or not self.db_path.exists():
            self._set_status("[WARN] No active run available to export.")
            return
        if finding_id is not None and not self.selected_finding_id:
            self._set_status("[WARN] No finding selected to export.")
            return

        try:
            from vulnparse_pin.reporting import renderer as _renderer
        except ImportError as exc:
            self._set_status(f"[ERR] Reporting renderer unavailable: {exc}")
            return

        try:
            pfh = self._ensure_pfh()
            out_dir = authorize_output_dir(pfh, self.output_dir, label="TUI Dossier Export Directory")
            with VppDatabase(self.db_path, read_only=True) as db:
                bundle = _renderer.export_dossier_bundle(
                    db,
                    self.run_id,
                    out_dir,
                    finding_id=finding_id,
                    diff_report=self.diff_report,
                    template_dir=self.template_dir,
                    pfh=pfh,
                )
            scope_label = f"finding {finding_id}" if finding_id else f"run {self.run_id}"
            self._set_status(
                f"[OK] Exported {scope_label} dossier -> {bundle.get('html') or bundle.get('markdown') or out_dir}"
            )
        except Exception as exc:
            self._set_status(f"[ERR] Export failed: {exc}")

    def action_export_selected_dossier(self) -> None:
        self._export_dossier(finding_id=self.selected_finding_id or "__none__")

    def action_export_full_dossier(self) -> None:
        self._export_dossier(finding_id=None)

    def action_open_defer_modal(self) -> None:
        if not self.run_id or not self.selected_finding_id or not self.db_path.exists():
            self._set_status("[WARN] Select a finding first to defer.")
            return
        with VppDatabase(self.db_path, read_only=True) as db:
            detail = get_finding_detail(db, self.run_id, self.selected_finding_id)
        self.push_screen(DeferralModal(finding=detail), callback=self._on_defer_saved)

    def _on_defer_saved(self, result: Optional[Dict[str, Any]]) -> None:
        if not result:
            self._set_status("Deferral cancelled.")
            return

        try:
            pfh = self._ensure_pfh()
            decisions_src = self.decisions_path or (self.db_path.parent / "decisions.yaml")
            decisions_target = authorize_output_path(pfh, decisions_src, label="TUI Decisions Config")

            raw_slug = re.sub(
                r"[^a-z0-9]+",
                "-",
                f"{result['cve_or_rule_id']}-{result['asset_pattern']}".lower(),
            ).strip("-")[:48]
            entry: Dict[str, Any] = {
                "id": f"dec-{raw_slug or uuid4().hex[:8]}",
                "asset_pattern": result["asset_pattern"],
                "cve_or_rule_id": result["cve_or_rule_id"],
                "status": result["status"],
                "rationale": result["rationale"],
                "owner": result["owner"],
                "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            }
            if result.get("expires_at"):
                entry["expires_at"] = result["expires_at"]

            saved = upsert_decision(decisions_target, entry, pfh=pfh)
            self.decisions_path = decisions_target
            reg = DecisionsRegistry.from_file(decisions_target, pfh=pfh)

            if self.run_id and self.db_path.exists():
                cfg_bundle = ConfigProjector.load_packaged_default_bundle()
                profile = (self.active_run_meta or {}).get("profile") or "default"
                ui_logger = pfh.logger
                base = self.db_path.resolve().parent
                paths = AppPaths(
                    portable=True,
                    base_dir=base,
                    config_dir=base,
                    data_dir=base,
                    cache_dir=base,
                    log_dir=base,
                    output_dir=self.output_dir.resolve(),
                    nvd_dir=base,
                    nvd_feeds_dir=base,
                    kev_dir=base,
                    epss_dir=base,
                    exploitdb_dir=base,
                )
                with VppDatabase(self.db_path, read_only=False) as db:
                    services = Services(
                        db=db,
                        run_id=self.run_id,
                        decisions_registry=reg,
                        ledger=LedgerService(),
                    )
                    ctx = RunContext(
                        paths=paths,
                        pfh=pfh,
                        logger=ui_logger,
                        services=services,
                        db=db,
                        run_id=self.run_id,
                        decisions_registry=reg,
                    )
                    TriageDecisionPass(
                        cfg_bundle.triage_policy,
                        profile=profile,
                        decisions_registry=reg,
                    ).run(ctx)

            self._reload_all()
            self._set_status(
                f"[OK] Saved {saved['status']} '{saved['id']}' -> {decisions_target}"
            )
        except Exception as exc:
            self._set_status(f"[ERR] Failed to save deferral: {exc}")


__all__ = ["DeferralModal", "VppApp"]
