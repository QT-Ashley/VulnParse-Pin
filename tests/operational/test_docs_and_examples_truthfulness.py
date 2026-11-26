# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

"""Operational truthfulness gates for documentation, README/PyPI links, and runnable examples."""

from __future__ import annotations

import json
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set, Tuple
from urllib.parse import unquote

from ruamel.yaml import YAML

from vulnparse_pin.cli.args import SUBCOMMANDS, build_parser

_RUAMEL_YAML = YAML(typ="safe", pure=True)


def _load_yaml_all(text: str) -> List[Any]:
    return list(_RUAMEL_YAML.load_all(text))


def _load_yaml_one(text: str) -> Any:
    return _RUAMEL_YAML.load(text)

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCS_ROOT = REPO_ROOT / "documentation" / "docs"
MKDOCS_PATH = REPO_ROOT / "documentation" / "mkdocs.yml"
EXAMPLES_ROOT = REPO_ROOT / "examples"
README_PATH = REPO_ROOT / "README.md"

_FENCED_BLOCK_RE = re.compile(r"```[^\n]*\n([\s\S]*?)```")
_MD_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
_IMG_SRC_RE = re.compile(r"<img\b[^>]*\bsrc=[\"']([^\"']+)[\"']", re.IGNORECASE)
_HTML_HREF_RE = re.compile(r"<a\b[^>]*\bhref=[\"']([^\"']+)[\"']", re.IGNORECASE)

_GITHUB_RAW_PREFIX = "https://raw.githubusercontent.com/QT-Ashley/VulnParse-Pin/main/"
_GITHUB_BLOB_PREFIX = "https://github.com/QT-Ashley/VulnParse-Pin/blob/main/"
_GITHUB_TREE_PREFIX = "https://github.com/QT-Ashley/VulnParse-Pin/tree/main/"


def _collect_mkdocs_nav_paths(node: object) -> List[str]:
    paths: List[str] = []
    if isinstance(node, list):
        for item in node:
            paths.extend(_collect_mkdocs_nav_paths(item))
    elif isinstance(node, dict):
        for value in node.values():
            paths.extend(_collect_mkdocs_nav_paths(value))
    elif isinstance(node, str):
        paths.append(node)
    return paths


def _parser_flag_catalog() -> Dict[str, Set[str]]:
    _, subparsers_map = build_parser()
    catalog: Dict[str, Set[str]] = {}
    for subcommand, subparser in subparsers_map.items():
        opts: Set[str] = set()
        for action in subparser._actions:
            for opt in action.option_strings:
                opts.add(opt)
        catalog[subcommand] = opts
    return catalog


def _strip_code_from_markdown(text: str) -> str:
    without_fences = _FENCED_BLOCK_RE.sub("", text)
    return re.sub(r"`[^`]+`", "", without_fences)


def _extract_vpp_commands_from_shell_text(
    text: str,
    *,
    skip_legacy_comments: bool = False,
) -> List[Tuple[str, List[str]]]:
    """
    Extract (subcommand_or_first_arg, remaining_tokens) for vpp invocations and
    explicit bash argument arrays (`*_args=(scan ...)`).
    """
    extracted: List[Tuple[str, List[str]]] = []
    joined = re.sub(r"\\\r?\n", " ", text)
    lines = joined.splitlines()

    skip_next_legacy_cmd = False
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            if skip_legacy_comments and re.match(r"^#\s*Legacy\s+v1\.", line, re.IGNORECASE):
                skip_next_legacy_cmd = True
            continue

        # Capture bash array definitions like `scan_args=(scan ...)` or `diff_args=(--db ...)`
        arr_match = re.match(r"^[A-Za-z_][A-Za-z0-9_]*_args=\((.*)\)$", line)
        if arr_match:
            inner = arr_match.group(1).strip()
            try:
                arr_toks = shlex.split(inner, comments=True)
            except ValueError:
                arr_toks = inner.split()
            if arr_toks:
                if arr_toks[0] in SUBCOMMANDS:
                    extracted.append((arr_toks[0], arr_toks[1:]))
                elif line.startswith("diff_args="):
                    extracted.append(("diff", arr_toks))
            continue

        for seg in re.split(r"\s*(?:&&|\|\||;|\|)\s*", line):
            seg = seg.strip()
            if not seg:
                continue
            try:
                toks = shlex.split(seg, comments=True)
            except ValueError:
                continue
            if not toks:
                continue

            if toks[0] not in ("vpp", "$VPP_BIN", "vulnparse-pin"):
                continue

            if skip_next_legacy_cmd:
                skip_next_legacy_cmd = False
                continue

            if len(toks) < 2:
                continue

            first_arg = toks[1]
            # Ignore usage placeholders, top-level --version/--help, and bash array expansions
            if first_arg in ("--version", "-v", "--help", "-h", "[--version"):
                continue
            if first_arg.startswith("${") and first_arg.endswith("}"):
                continue

            extracted.append((first_arg, toks[2:]))

    return extracted


def _iter_example_command_sources() -> Iterable[Tuple[str, str]]:
    for path in sorted(EXAMPLES_ROOT.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".md":
            for blk in _FENCED_BLOCK_RE.findall(text):
                yield rel, blk
        elif path.suffix == ".sh":
            yield rel, text
        elif path.suffix in (".yml", ".yaml"):
            docs = _load_yaml_all(text)
            for doc in docs:
                if not isinstance(doc, dict):
                    continue
                # Extract multi-line shell strings from CI workflows & k8s/compose files
                yield rel, text
                break


def test_mkdocs_nav_parity() -> None:
    """Every mkdocs.yml nav entry resolves to an existing .md and every docs .md is in nav."""
    assert MKDOCS_PATH.is_file(), f"Missing mkdocs.yml at {MKDOCS_PATH}"
    config = _load_yaml_one(MKDOCS_PATH.read_text(encoding="utf-8"))
    assert isinstance(config, dict) and "nav" in config

    nav_paths = _collect_mkdocs_nav_paths(config["nav"])
    assert nav_paths, "mkdocs.yml nav must not be empty"

    nav_set = set(nav_paths)
    assert len(nav_set) == len(nav_paths), "Duplicate entries detected in mkdocs.yml nav"

    disk_set = {
        p.relative_to(DOCS_ROOT).as_posix()
        for p in DOCS_ROOT.rglob("*.md")
    }

    missing_on_disk = sorted(nav_set - disk_set)
    missing_from_nav = sorted(disk_set - nav_set)
    assert not missing_on_disk, f"mkdocs.yml nav references missing files: {missing_on_disk}"
    assert not missing_from_nav, f"Markdown files missing from mkdocs.yml nav: {missing_from_nav}"


def test_zero_broken_relative_markdown_links() -> None:
    """Every relative Markdown link in documentation/docs/**/*.md and examples/README.md resolves."""
    md_files = sorted(DOCS_ROOT.rglob("*.md")) + [EXAMPLES_ROOT / "README.md"]
    broken: List[Tuple[str, str]] = []

    for md_path in md_files:
        cleaned = _strip_code_from_markdown(md_path.read_text(encoding="utf-8"))
        for match in _MD_LINK_RE.finditer(cleaned):
            raw_target = match.group(1).strip()
            if not raw_target or raw_target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            target_no_fragment = unquote(raw_target.split("#", 1)[0])
            if not target_no_fragment:
                continue
            resolved = (md_path.parent / target_no_fragment).resolve()
            if not resolved.exists():
                broken.append((md_path.relative_to(REPO_ROOT).as_posix(), raw_target))

    assert not broken, f"Broken relative Markdown links detected: {broken}"


def test_cli_truthfulness_against_build_parser() -> None:
    """All fenced vpp <subcommand> commands and --long-flags in docs/README/examples exist in build_parser()."""
    flag_catalog = _parser_flag_catalog()
    unknown_items: List[Tuple[str, str, str]] = []

    md_targets = [README_PATH] + sorted(DOCS_ROOT.rglob("*.md"))
    command_sources: List[Tuple[str, str, bool]] = []
    for md_path in md_targets:
        rel = md_path.relative_to(REPO_ROOT).as_posix()
        is_upgrade_doc = md_path.name == "Upgrade and Migration.md"
        for block in _FENCED_BLOCK_RE.findall(md_path.read_text(encoding="utf-8")):
            command_sources.append((rel, block, is_upgrade_doc))

    for rel, shell_text in _iter_example_command_sources():
        command_sources.append((rel, shell_text, False))

    for source_rel, snippet, skip_legacy in command_sources:
        for subcommand, rest_tokens in _extract_vpp_commands_from_shell_text(
            snippet, skip_legacy_comments=skip_legacy
        ):
            if subcommand not in SUBCOMMANDS:
                unknown_items.append((source_rel, f"unknown subcommand '{subcommand}'", " ".join(rest_tokens)))
                continue

            valid_flags = flag_catalog[subcommand]
            for token in rest_tokens:
                if not token.startswith("--") or token == "--":
                    continue
                flag_name = token.split("=", 1)[0]
                if flag_name not in valid_flags:
                    unknown_items.append((source_rel, f"unknown flag '{flag_name}' on '{subcommand}'", token))

    # Also validate docker-compose command arrays that target the `ENTRYPOINT ["vpp"]` container
    compose_path = EXAMPLES_ROOT / "deploy" / "docker-compose.yml"
    compose_data = _load_yaml_one(compose_path.read_text(encoding="utf-8"))
    for svc_name, svc_cfg in (compose_data.get("services") or {}).items():
        cmd = svc_cfg.get("command")
        if isinstance(cmd, list) and cmd and isinstance(cmd[0], str) and not svc_cfg.get("entrypoint"):
            sub = cmd[0]
            if sub not in SUBCOMMANDS:
                unknown_items.append((f"examples/deploy/docker-compose.yml:{svc_name}", f"unknown subcommand '{sub}'", str(cmd)))
                continue
            valid_flags = flag_catalog[sub]
            for tok in cmd[1:]:
                if isinstance(tok, str) and tok.startswith("--"):
                    flag_name = tok.split("=", 1)[0]
                    if flag_name not in valid_flags:
                        unknown_items.append(
                            (f"examples/deploy/docker-compose.yml:{svc_name}", f"unknown flag '{flag_name}' on '{sub}'", tok)
                        )

    assert not unknown_items, f"CLI truthfulness failures against build_parser(): {unknown_items}"


def test_yaml_json_and_shell_syntax_valid() -> None:
    """Validate YAML/JSON files and run bash -n across all workflow shell scripts."""
    yaml_targets = [MKDOCS_PATH]
    yaml_targets.extend(sorted((EXAMPLES_ROOT / "configs").glob("*.yaml")))
    yaml_targets.extend(sorted((EXAMPLES_ROOT / "ci").glob("*.yml")))
    yaml_targets.extend(sorted((EXAMPLES_ROOT / "deploy").rglob("*.y*ml")))
    yaml_targets.extend(sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")))

    assert len(yaml_targets) >= 6, "Expected YAML targets under mkdocs, examples, and .github/workflows"
    for yf in yaml_targets:
        docs = _load_yaml_all(yf.read_text(encoding="utf-8"))
        assert docs and all(d is not None for d in docs), f"Empty or null YAML document in {yf}"

    for jf in sorted(EXAMPLES_ROOT.rglob("*.json")):
        json.loads(jf.read_text(encoding="utf-8"))

    bash_bin = shutil.which("bash")
    assert bash_bin is not None, "bash binary is required for bash -n validation"
    sh_targets = sorted((EXAMPLES_ROOT / "workflows").glob("*.sh"))
    assert sh_targets, "Expected workflow scripts under examples/workflows/*.sh"
    for sh_file in sh_targets:
        proc = subprocess.run([bash_bin, "-n", str(sh_file)], capture_output=True, text=True, check=False)
        assert proc.returncode == 0, f"bash -n failed for {sh_file}: {proc.stderr}"


def test_readme_pypi_readiness_no_relative_assets_or_links() -> None:
    """README.md must contain zero relative img src, html href, or Markdown links that 404 on PyPI/TestPyPI."""
    readme_text = README_PATH.read_text(encoding="utf-8")

    rel_imgs = [
        src for src in _IMG_SRC_RE.findall(readme_text)
        if not src.startswith(("https://", "http://"))
    ]
    assert not rel_imgs, f"Relative <img src=...> paths found in README.md: {rel_imgs}"

    rel_hrefs = [
        href for href in _HTML_HREF_RE.findall(readme_text)
        if not href.startswith(("https://", "http://", "#"))
    ]
    assert not rel_hrefs, f"Relative <a href=...> links found in README.md: {rel_hrefs}"

    cleaned = _strip_code_from_markdown(readme_text)
    rel_md_links = [
        target for target in _MD_LINK_RE.findall(cleaned)
        if not target.strip().startswith(("https://", "http://", "mailto:", "#"))
    ]
    assert not rel_md_links, f"Relative Markdown links found in README.md: {rel_md_links}"

    # Verify every GitHub raw/blob/tree target referenced in README.md maps to a real repo file/dir
    missing_targets: List[str] = []
    all_urls = (
        _IMG_SRC_RE.findall(readme_text)
        + _HTML_HREF_RE.findall(readme_text)
        + _MD_LINK_RE.findall(cleaned)
    )
    for url in all_urls:
        for prefix in (_GITHUB_RAW_PREFIX, _GITHUB_BLOB_PREFIX, _GITHUB_TREE_PREFIX):
            if url.startswith(prefix):
                rel_part = unquote(url[len(prefix):].split("#", 1)[0])
                if not (REPO_ROOT / rel_part).exists():
                    missing_targets.append(url)
    assert not missing_targets, f"GitHub URLs in README.md point to nonexistent repo paths: {missing_targets}"


def test_container_manifest_and_release_workflow_yaml_valid() -> None:
    """Validate release.yml (including publish-ghcr) and container compose/k8s manifests."""
    compose_data = _load_yaml_one((EXAMPLES_ROOT / "deploy" / "docker-compose.yml").read_text(encoding="utf-8"))
    assert compose_data["services"]["vpp-scan"]["build"]["dockerfile"] == "Dockerfile"

    release_data = _load_yaml_one((REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8"))
    assert "publish-ghcr" in release_data["jobs"]
    assert "Dockerfile" in (REPO_ROOT / "Dockerfile").name
    assert (REPO_ROOT / "Dockerfile").is_file()
    assert (REPO_ROOT / ".dockerignore").is_file()
