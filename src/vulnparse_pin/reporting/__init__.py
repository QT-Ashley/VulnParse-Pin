# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

"""Jinja2 Decision Defense Dossier, Executive Roadmap, and PR diff reporting."""

from vulnparse_pin.reporting.renderer import (
    export_dossier_bundle,
    md_escape,
    render_diff_pr_comment,
    render_dossier_html,
    render_dossier_markdown,
    render_executive_roadmap_html,
    render_executive_roadmap_markdown,
)

__all__ = [
    "export_dossier_bundle",
    "md_escape",
    "render_diff_pr_comment",
    "render_dossier_html",
    "render_dossier_markdown",
    "render_executive_roadmap_html",
    "render_executive_roadmap_markdown",
]
