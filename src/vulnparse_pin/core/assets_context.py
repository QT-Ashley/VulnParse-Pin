# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timezone
import fnmatch
from importlib import resources
import ipaddress
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from ruamel.yaml import YAML

from vulnparse_pin.core.id import (
    canonicalize_target_key,
    make_asset_id_v2,
    normalize_hostname_value,
    normalize_image_or_repo,
    normalize_ip_value,
    normalize_target_uri,
)

_GLOB_CHARS = frozenset("*?[")
_SAFE_YAML = YAML(typ="safe", pure=True)


def _to_json_compatible(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _to_json_compatible(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_json_compatible(v) for v in value]
    if isinstance(value, tuple):
        return [_to_json_compatible(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    return value


def _load_schema(filename: str) -> Dict[str, Any]:
    return json.loads(
        resources.files("vulnparse_pin.core.schemas").joinpath(filename).read_text(encoding="utf-8")
    )


def _validate_against_schema(payload: Dict[str, Any], schema_filename: str, label: str) -> None:
    schema = _load_schema(schema_filename)
    validator = Draft202012Validator(schema)
    clean_payload = _to_json_compatible(payload)
    try:
        validator.validate(clean_payload)
    except JsonSchemaValidationError as exc:
        path = "/".join(str(p) for p in exc.path) if exc.path else "<root>"
        raise ValueError(f"{label} schema validation failed at {path}: {exc.message}") from exc


def _validate_decision_entry(entry: Dict[str, Any]) -> None:
    schema = _load_schema("decisions.schema.json")
    entry_schema = {
        "$schema": schema["$schema"],
        "$defs": schema["$defs"],
        "$ref": "#/$defs/DecisionEntry",
    }
    validator = Draft202012Validator(entry_schema)
    clean_entry = _to_json_compatible(entry)
    try:
        validator.validate(clean_entry)
    except JsonSchemaValidationError as exc:
        path = "/".join(str(p) for p in exc.path) if exc.path else "<root>"
        raise ValueError(f"Decision entry schema validation failed at {path}: {exc.message}") from exc


def _is_glob_pattern(pattern: str) -> bool:
    return any(ch in pattern for ch in _GLOB_CHARS)


def _normalize_env_list(val: Any) -> Tuple[str, ...]:
    if val is None:
        return ()
    if isinstance(val, str):
        s = val.strip()
        return (s,) if s else ()
    if isinstance(val, (list, tuple)):
        return tuple(str(x).strip() for x in val if x is not None and str(x).strip())
    return ()


def _normalize_alias_value(raw: str) -> Tuple[str, ...]:
    """Return normalized comparison forms for an alias string (IP, URI, image/repo, hostname)."""
    s = str(raw).strip()
    if not s:
        return ()
    forms: List[str] = [s.lower()]
    nip = normalize_ip_value(s)
    if nip:
        forms.append(nip)
    nhost = normalize_hostname_value(s)
    if nhost and nhost not in forms:
        forms.append(nhost)
    if "://" in s:
        nuri = normalize_target_uri(s)
        if nuri and nuri not in forms:
            forms.append(nuri)
    nimg = normalize_image_or_repo(s)
    if nimg and nimg not in forms:
        forms.append(nimg)
    return tuple(dict.fromkeys(forms))


def _glob_specificity(pattern: str) -> Tuple[int, int]:
    """Higher tuple means more specific glob pattern (more literal chars, fewer wildcards)."""
    literal_chars = sum(1 for ch in pattern if ch not in _GLOB_CHARS)
    wildcard_count = sum(1 for ch in pattern if ch in _GLOB_CHARS)
    return (literal_chars, -wildcard_count)


@dataclass(frozen=True)
class AssetRule:
    rule_id: str
    order_idx: int
    asset_id: Optional[str]
    aliases: Tuple[str, ...]
    cidrs: Tuple[str, ...]
    hostnames: Tuple[str, ...]
    uris: Tuple[str, ...]
    images: Tuple[str, ...]
    repos: Tuple[str, ...]
    internet_facing: Optional[bool]
    criticality: Optional[str]
    owner: Optional[str]
    env_tags: Tuple[str, ...]
    tags: Dict[str, str]


@dataclass(frozen=True)
class AssetContext:
    asset_id: str
    canonical_key: str
    declared_criticality: Optional[str]
    internet_facing: Optional[bool]
    owner: Optional[str]
    env_tags: Tuple[str, ...]
    tags: Dict[str, str]
    inventory_status: str
    matched_rule_id: Optional[str]
    match_tier: str
    aliases: Tuple[str, ...] = ()


class AssetContextMatcher:
    """
    Pattern-based asset inventory context matcher for assets.yaml (v1/v2).

    Resolution precedence:
      1. Explicit alias / canonical asset_id match
      2. Exact IP / FQDN / URI / image / repo match
      3. Longest-prefix CIDR match
      4. Glob match (fnmatchcase lowercased)
      5. Unmatched -> inventory_status = "unmatched_shadow", declared_criticality = default, internet_facing = None
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        cfg = dict(config or {})
        if cfg:
            _validate_against_schema(cfg, "assets.schema.json", "Assets config")

        defaults = cfg.get("defaults") or {}
        self.default_criticality: Optional[str] = (
            str(defaults.get("criticality")).strip().lower()
            if defaults.get("criticality") is not None
            else "medium"
        )
        self.default_internet_facing: Optional[bool] = defaults.get("internet_facing")
        self.default_owner: Optional[str] = defaults.get("owner")
        self.default_env_tags: Tuple[str, ...] = _normalize_env_list(defaults.get("env"))
        self.default_tags: Dict[str, str] = {
            str(k): str(v) for k, v in (defaults.get("tags") or {}).items()
        }

        self.rules: List[AssetRule] = []
        self.inline_decisions: List[Dict[str, Any]] = [
            _to_json_compatible(d) for d in (cfg.get("decisions") or []) if isinstance(d, dict)
        ]

        # Lookup structures for deterministic precedence matching
        self._rule_by_explicit_id: Dict[str, AssetRule] = {}
        self._alias_map: Dict[str, AssetRule] = {}
        self._exact_ips: Dict[str, AssetRule] = {}
        self._exact_hosts: Dict[str, AssetRule] = {}
        self._exact_uris: Dict[str, AssetRule] = {}
        self._exact_images: Dict[str, AssetRule] = {}
        self._cidr_networks: List[Tuple[Union[ipaddress.IPv4Network, ipaddress.IPv6Network], AssetRule]] = []
        self._glob_hosts: List[Tuple[str, AssetRule]] = []
        self._glob_uris: List[Tuple[str, AssetRule]] = []
        self._glob_images: List[Tuple[str, AssetRule]] = []

        for idx, raw_rule in enumerate(cfg.get("rules") or []):
            rule = AssetRule(
                rule_id=str(raw_rule["id"]).strip(),
                order_idx=idx,
                asset_id=str(raw_rule["asset_id"]).strip() if raw_rule.get("asset_id") else None,
                aliases=tuple(str(a).strip() for a in (raw_rule.get("aliases") or []) if str(a).strip()),
                cidrs=tuple(str(c).strip() for c in (raw_rule.get("cidrs") or []) if str(c).strip()),
                hostnames=tuple(str(h).strip() for h in (raw_rule.get("hostnames") or []) if str(h).strip()),
                uris=tuple(str(u).strip() for u in (raw_rule.get("uris") or []) if str(u).strip()),
                images=tuple(str(i).strip() for i in (raw_rule.get("images") or []) if str(i).strip()),
                repos=tuple(str(r).strip() for r in (raw_rule.get("repos") or []) if str(r).strip()),
                internet_facing=raw_rule.get("internet_facing"),
                criticality=(
                    str(raw_rule["criticality"]).strip().lower()
                    if raw_rule.get("criticality") is not None
                    else None
                ),
                owner=str(raw_rule["owner"]).strip() if raw_rule.get("owner") else None,
                env_tags=_normalize_env_list(raw_rule.get("env")),
                tags={str(k): str(v) for k, v in (raw_rule.get("tags") or {}).items()},
            )
            self.rules.append(rule)

            if rule.asset_id:
                self._rule_by_explicit_id.setdefault(rule.asset_id.lower(), rule)
            self._rule_by_explicit_id.setdefault(rule.rule_id.lower(), rule)

            for alias in rule.aliases:
                for norm_form in _normalize_alias_value(alias):
                    self._alias_map.setdefault(norm_form, rule)

            for cidr_str in rule.cidrs:
                if "/" not in cidr_str:
                    nip = normalize_ip_value(cidr_str)
                    if nip:
                        self._exact_ips.setdefault(nip, rule)
                        continue
                try:
                    net = ipaddress.ip_network(cidr_str, strict=False)
                except ValueError as exc:
                    raise ValueError(f"Invalid CIDR '{cidr_str}' in assets rule '{rule.rule_id}': {exc}") from exc
                self._cidr_networks.append((net, rule))

            for host_pat in rule.hostnames:
                if _is_glob_pattern(host_pat):
                    self._glob_hosts.append((host_pat.lower().rstrip("."), rule))
                else:
                    nip = normalize_ip_value(host_pat)
                    if nip:
                        self._exact_ips.setdefault(nip, rule)
                    nhost = normalize_hostname_value(host_pat)
                    if nhost:
                        self._exact_hosts.setdefault(nhost, rule)

            for uri_pat in rule.uris:
                if _is_glob_pattern(uri_pat):
                    self._glob_uris.append((uri_pat.lower().rstrip("/"), rule))
                else:
                    nuri = normalize_target_uri(uri_pat)
                    if nuri:
                        self._exact_uris.setdefault(nuri, rule)
                    self._exact_uris.setdefault(uri_pat.lower().rstrip("/"), rule)

            for img_pat in (*rule.images, *rule.repos):
                if _is_glob_pattern(img_pat):
                    self._glob_images.append((img_pat.lower().rstrip("/"), rule))
                else:
                    nimg = normalize_image_or_repo(img_pat)
                    if nimg:
                        self._exact_images.setdefault(nimg, rule)
                    self._exact_images.setdefault(img_pat.lower().rstrip("/"), rule)

        # Longest prefix first, then rule order
        self._cidr_networks.sort(key=lambda item: (-item[0].prefixlen, item[1].order_idx))
        # Most specific glob first, then rule order
        self._glob_hosts.sort(key=lambda item: (-_glob_specificity(item[0])[0], -_glob_specificity(item[0])[1], item[1].order_idx))
        self._glob_uris.sort(key=lambda item: (-_glob_specificity(item[0])[0], -_glob_specificity(item[0])[1], item[1].order_idx))
        self._glob_images.sort(key=lambda item: (-_glob_specificity(item[0])[0], -_glob_specificity(item[0])[1], item[1].order_idx))

    @classmethod
    def from_yaml_text(cls, text: str) -> "AssetContextMatcher":
        loaded = _SAFE_YAML.load(text) if text.strip() else {}
        if loaded is None:
            loaded = {}
        if not isinstance(loaded, dict):
            raise ValueError("assets.yaml root must be a mapping/object.")
        return cls(loaded)

    @classmethod
    def from_file(cls, path: Union[Path, str], *, pfh: Optional[Any] = None) -> "AssetContextMatcher":
        p = Path(path)
        if pfh is not None:
            with pfh.open_for_read(p, mode="r", encoding="utf-8", label="Assets Config") as handle:
                text = handle.read()
        else:
            text = p.read_text(encoding="utf-8")
        return cls.from_yaml_text(text)

    def inline_decisions_registry(self) -> "DecisionsRegistry":
        return DecisionsRegistry(self.inline_decisions)

    def _build_matched_context(
        self,
        rule: AssetRule,
        match_tier: str,
        canonical_key: str,
    ) -> AssetContext:
        if rule.asset_id:
            resolved_asset_id = rule.asset_id
        elif rule.aliases:
            resolved_asset_id = make_asset_id_v2(f"rule:{rule.rule_id}")
        else:
            resolved_asset_id = make_asset_id_v2(canonical_key)

        merged_tags = dict(self.default_tags)
        merged_tags.update(rule.tags)
        env_tags = rule.env_tags if rule.env_tags else self.default_env_tags
        criticality = rule.criticality if rule.criticality is not None else self.default_criticality
        internet_facing = (
            rule.internet_facing if rule.internet_facing is not None else self.default_internet_facing
        )
        owner = rule.owner if rule.owner is not None else self.default_owner

        return AssetContext(
            asset_id=resolved_asset_id,
            canonical_key=canonical_key,
            declared_criticality=criticality,
            internet_facing=internet_facing,
            owner=owner,
            env_tags=env_tags,
            tags=merged_tags,
            inventory_status="matched",
            matched_rule_id=rule.rule_id,
            match_tier=match_tier,
            aliases=rule.aliases,
        )

    def resolve(
        self,
        ip: Optional[str] = None,
        hostname: Optional[str] = None,
        target_uri: Optional[str] = None,
        image_or_repo: Optional[str] = None,
        *,
        asset_id: Optional[str] = None,
    ) -> AssetContext:
        norm_ip = normalize_ip_value(ip)
        norm_host = normalize_hostname_value(hostname)
        if norm_host:
            host_as_ip = normalize_ip_value(norm_host)
            if host_as_ip:
                if norm_ip is None:
                    norm_ip = host_as_ip
                norm_host = None
            elif norm_ip and norm_host == norm_ip:
                norm_host = None

        norm_uri = normalize_target_uri(target_uri)
        uri_host: Optional[str] = None
        uri_ip: Optional[str] = None
        uri_origin: Optional[str] = None
        if target_uri and "://" in str(target_uri):
            parsed = urlsplit(str(target_uri).strip())
            parsed_host = parsed.hostname
            if parsed_host:
                uri_ip = normalize_ip_value(parsed_host)
                if uri_ip is None:
                    uri_host = normalize_hostname_value(parsed_host)
                scheme = parsed.scheme.lower()
                try:
                    port = parsed.port
                except ValueError:
                    port = None
                if (scheme in ("http", "ws") and port == 80) or (scheme in ("https", "wss") and port == 443):
                    port = None
                host_l = parsed_host.lower().rstrip(".")
                host_fmt = f"[{host_l}]" if ":" in host_l and not host_l.startswith("[") else host_l
                netloc = f"{host_fmt}:{port}" if port is not None else host_fmt
                uri_origin = f"{scheme}://{netloc}"

        norm_image = normalize_image_or_repo(image_or_repo)
        canonical_key = canonicalize_target_key(
            ip=norm_ip,
            hostname=norm_host,
            target_uri=norm_uri,
            image_or_repo=norm_image,
            explicit_asset_id=asset_id,
        )

        # Tier 1: Explicit canonical asset_id or alias match
        if asset_id and str(asset_id).strip():
            aid_key = str(asset_id).strip().lower()
            if aid_key in self._rule_by_explicit_id:
                return self._build_matched_context(self._rule_by_explicit_id[aid_key], "alias", canonical_key)
            if aid_key in self._alias_map:
                return self._build_matched_context(self._alias_map[aid_key], "alias", canonical_key)

        alias_candidates: List[str] = []
        for raw_val in (ip, hostname, target_uri, image_or_repo):
            if raw_val:
                alias_candidates.extend(_normalize_alias_value(str(raw_val)))
        for cand in (norm_ip, norm_host, norm_uri, uri_origin, norm_image, uri_host, uri_ip):
            if cand and cand not in alias_candidates:
                alias_candidates.append(cand)
        for cand in alias_candidates:
            if cand in self._alias_map:
                return self._build_matched_context(self._alias_map[cand], "alias", canonical_key)

        # Tier 2: Exact IP / FQDN / image / URI match
        for ip_cand in (norm_ip, uri_ip):
            if ip_cand and ip_cand in self._exact_ips:
                return self._build_matched_context(self._exact_ips[ip_cand], "exact", canonical_key)

        for host_cand in (norm_host, uri_host):
            if host_cand and host_cand in self._exact_hosts:
                return self._build_matched_context(self._exact_hosts[host_cand], "exact", canonical_key)

        if norm_image and norm_image in self._exact_images:
            return self._build_matched_context(self._exact_images[norm_image], "exact", canonical_key)
        if image_or_repo:
            raw_img_low = str(image_or_repo).strip().lower().rstrip("/")
            if raw_img_low in self._exact_images:
                return self._build_matched_context(self._exact_images[raw_img_low], "exact", canonical_key)

        if norm_uri and norm_uri in self._exact_uris:
            return self._build_matched_context(self._exact_uris[norm_uri], "exact", canonical_key)
        if target_uri:
            raw_uri_low = str(target_uri).strip().lower().rstrip("/")
            if raw_uri_low in self._exact_uris:
                return self._build_matched_context(self._exact_uris[raw_uri_low], "exact", canonical_key)

        # Tier 3: Longest-prefix CIDR match
        ip_obj: Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = None
        for ip_cand in (norm_ip, uri_ip):
            if ip_cand:
                try:
                    ip_obj = ipaddress.ip_address(ip_cand)
                    break
                except ValueError:
                    continue
        if ip_obj is not None:
            for net, rule in self._cidr_networks:
                if ip_obj.version == net.version and ip_obj in net:
                    return self._build_matched_context(rule, "cidr", canonical_key)

        # Tier 4: Glob match (fnmatchcase lowercased)
        for host_cand in (norm_host, uri_host):
            if host_cand:
                for pat, rule in self._glob_hosts:
                    if fnmatch.fnmatchcase(host_cand, pat):
                        return self._build_matched_context(rule, "glob", canonical_key)

        uri_candidates = [u for u in (norm_uri, str(target_uri).strip().lower().rstrip("/") if target_uri else None) if u]
        for uri_cand in uri_candidates:
            for pat, rule in self._glob_uris:
                if fnmatch.fnmatchcase(uri_cand, pat):
                    return self._build_matched_context(rule, "glob", canonical_key)

        img_candidates = [i for i in (norm_image, str(image_or_repo).strip().lower().rstrip("/") if image_or_repo else None) if i]
        for img_cand in img_candidates:
            for pat, rule in self._glob_images:
                if fnmatch.fnmatchcase(img_cand, pat):
                    return self._build_matched_context(rule, "glob", canonical_key)

        # Tier 5: Unmatched -> shadow asset (internet_facing stays None so exposure inference can run)
        return AssetContext(
            asset_id=asset_id if asset_id else make_asset_id_v2(canonical_key),
            canonical_key=canonical_key,
            declared_criticality=self.default_criticality,
            internet_facing=None,
            owner=self.default_owner,
            env_tags=self.default_env_tags,
            tags=dict(self.default_tags),
            inventory_status="unmatched_shadow",
            matched_rule_id=None,
            match_tier="unmatched",
            aliases=(),
        )


def _parse_iso_datetime(value: Union[datetime, date, str], *, end_of_day_for_date: bool = False) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, date):
        t = time(23, 59, 59, 999999) if end_of_day_for_date else time(0, 0, 0)
        return datetime.combine(value, t, tzinfo=timezone.utc)
    raw = str(value).strip()
    if len(raw) == 10 and raw[4] == "-" and raw[7] == "-":
        d = date.fromisoformat(raw)
        t = time(23, 59, 59, 999999) if end_of_day_for_date else time(0, 0, 0)
        return datetime.combine(d, t, tzinfo=timezone.utc)
    iso = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    dt = datetime.fromisoformat(iso)
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _get_field(obj: Any, *names: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        for n in names:
            if n in obj and obj[n] is not None:
                return obj[n]
        return default
    for n in names:
        val = getattr(obj, n, None)
        if val is not None:
            return val
    return default


@dataclass(frozen=True)
class DecisionEntry:
    id: str
    asset_id: Optional[str]
    asset_pattern: Optional[str]
    cve_or_rule_id: str
    status: str
    rationale: str
    owner: Optional[str]
    created_at: Optional[str]
    expires_at: Optional[str]
    assumptions: Dict[str, Any]


@dataclass(frozen=True)
class DecisionEvaluation:
    matched: bool
    status: str  # "valid" | "invalidated" | "none"
    decision_id: Optional[str] = None
    decision_status: Optional[str] = None  # "deferred" | "accepted" | "mitigated"
    violated_predicates: Tuple[str, ...] = ()
    reasons: Tuple[str, ...] = ()
    assumed_state: Dict[str, Any] = None  # type: ignore[assignment]
    rationale: Optional[str] = None
    owner: Optional[str] = None
    expires_at: Optional[str] = None

    def __post_init__(self) -> None:
        if self.assumed_state is None:
            object.__setattr__(self, "assumed_state", {})


class DecisionsRegistry:
    """
    Registry of triage exceptions / deferrals / acceptances / mitigations (decisions.yaml)
    with assumption-drift invalidation evaluation.
    """

    def __init__(self, decisions: Optional[Sequence[Dict[str, Any]]] = None) -> None:
        self.entries: List[DecisionEntry] = []
        exact_index: Dict[str, List[Tuple[int, DecisionEntry]]] = {}
        wildcard_entries: List[Tuple[int, DecisionEntry]] = []
        exact_ids: Set[str] = set()

        for raw in decisions or []:
            clean = _to_json_compatible(raw)
            _validate_decision_entry(clean)
            entry = DecisionEntry(
                id=str(clean["id"]).strip(),
                asset_id=str(clean["asset_id"]).strip() if clean.get("asset_id") else None,
                asset_pattern=str(clean["asset_pattern"]).strip() if clean.get("asset_pattern") else None,
                cve_or_rule_id=str(clean["cve_or_rule_id"]).strip(),
                status=str(clean["status"]).strip(),
                rationale=str(clean["rationale"]).strip(),
                owner=str(clean["owner"]).strip() if clean.get("owner") else None,
                created_at=str(clean["created_at"]).strip() if clean.get("created_at") else None,
                expires_at=str(clean["expires_at"]).strip() if clean.get("expires_at") else None,
                assumptions=dict(clean.get("assumptions") or {}),
            )
            idx = len(self.entries)
            self.entries.append(entry)
            pat = entry.cve_or_rule_id.strip().lower()
            if "*" in pat or "?" in pat or "[" in pat:
                wildcard_entries.append((idx, entry))
            else:
                exact_index.setdefault(pat, []).append((idx, entry))
                exact_ids.add(pat)

        self._exact_finding_index = exact_index
        self._wildcard_entries = wildcard_entries
        self.exact_finding_ids = frozenset(exact_ids)
        self.has_wildcard_finding_ids = bool(wildcard_entries)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DecisionsRegistry":
        clean = _to_json_compatible(data or {})
        if clean:
            _validate_against_schema(clean, "decisions.schema.json", "Decisions config")
        return cls(clean.get("decisions") or [])

    @classmethod
    def from_yaml_text(cls, text: str) -> "DecisionsRegistry":
        loaded = _SAFE_YAML.load(text) if text.strip() else {}
        if loaded is None:
            loaded = {}
        if not isinstance(loaded, dict):
            raise ValueError("decisions.yaml root must be a mapping/object.")
        return cls.from_dict(loaded)

    @classmethod
    def from_file(cls, path: Union[Path, str], *, pfh: Optional[Any] = None) -> "DecisionsRegistry":
        p = Path(path)
        if pfh is not None:
            with pfh.open_for_read(p, mode="r", encoding="utf-8", label="Decisions Config") as handle:
                text = handle.read()
        else:
            text = p.read_text(encoding="utf-8")
        return cls.from_yaml_text(text)

    @staticmethod
    def _matches_finding_id(entry: DecisionEntry, finding_facts: Any) -> bool:
        target_pat = entry.cve_or_rule_id.strip().lower()
        candidates: List[str] = []
        for field_name in ("primary_cve", "scanner_sig", "rule_id", "vuln_id", "cve_or_rule_id"):
            val = _get_field(finding_facts, field_name)
            if val:
                candidates.append(str(val).strip().lower())
        for list_field in ("cves", "scanner_sigs", "rule_ids"):
            raw_vals = _get_field(finding_facts, list_field, default=[])
            if isinstance(raw_vals, (list, tuple, set)):
                for item in raw_vals:
                    if item:
                        candidates.append(str(item).strip().lower())
        for cand in candidates:
            if cand == target_pat or fnmatch.fnmatchcase(cand, target_pat):
                return True
        return False

    @staticmethod
    def _matches_asset(entry: DecisionEntry, asset_context: Any) -> Tuple[bool, int]:
        aid = _get_field(asset_context, "asset_id")
        rule_id = _get_field(asset_context, "matched_rule_id")
        if entry.asset_id:
            entry_aid = entry.asset_id.strip()
            if aid == entry_aid or (rule_id and rule_id == entry_aid):
                return True, 3
            return False, 0

        if entry.asset_pattern:
            pat = entry.asset_pattern.strip().lower()
            targets = []
            for field_name in (
                "asset_id",
                "matched_rule_id",
                "canonical_key",
                "hostname",
                "ip_address",
                "ip",
                "target_uri",
                "image_or_repo",
            ):
                val = _get_field(asset_context, field_name)
                if val:
                    targets.append(str(val).strip().lower())
            aliases = _get_field(asset_context, "aliases", default=())
            if isinstance(aliases, (list, tuple)):
                for a in aliases:
                    if a:
                        targets.append(str(a).strip().lower())
            for t in targets:
                if fnmatch.fnmatchcase(t, pat):
                    return True, 2
            return False, 0

        return True, 1

    def evaluate(
        self,
        asset_context: Any,
        finding_facts: Any,
        now_utc: Optional[Union[datetime, date, str]] = None,
    ) -> DecisionEvaluation:
        if not self.entries:
            return DecisionEvaluation(matched=False, status="none")

        cand_list: List[str] = []
        seen_cands: Set[str] = set()
        for field_name in ("primary_cve", "scanner_sig", "rule_id", "vuln_id", "cve_or_rule_id"):
            val = _get_field(finding_facts, field_name)
            if val:
                c = str(val).strip().lower()
                if c and c not in seen_cands:
                    seen_cands.add(c)
                    cand_list.append(c)
        for list_field in ("cves", "scanner_sigs", "rule_ids"):
            raw_vals = _get_field(finding_facts, list_field, default=[])
            if isinstance(raw_vals, (list, tuple, set)):
                for c_raw in raw_vals:
                    if c_raw:
                        c = str(c_raw).strip().lower()
                        if c and c not in seen_cands:
                            seen_cands.add(c)
                            cand_list.append(c)

        candidate_entries: List[Tuple[int, DecisionEntry]] = []
        seen_indices: Set[int] = set()
        for cand in cand_list:
            for pair in self._exact_finding_index.get(cand, ()):
                if pair[0] not in seen_indices:
                    seen_indices.add(pair[0])
                    candidate_entries.append(pair)
        for pair in self._wildcard_entries:
            if self._matches_finding_id(pair[1], finding_facts):
                if pair[0] not in seen_indices:
                    seen_indices.add(pair[0])
                    candidate_entries.append(pair)

        if not candidate_entries:
            return DecisionEvaluation(matched=False, status="none")

        best_entry: Optional[DecisionEntry] = None
        best_score: Tuple[int, int] = (-1, -1)
        for idx, entry in candidate_entries:
            asset_ok, specificity = self._matches_asset(entry, asset_context)
            if not asset_ok:
                continue
            score = (specificity, idx)
            if score > best_score:
                best_score = score
                best_entry = entry

        if best_entry is None:
            return DecisionEvaluation(matched=False, status="none")

        now_dt = (
            _parse_iso_datetime(now_utc, end_of_day_for_date=False)
            if now_utc is not None
            else datetime.now(timezone.utc)
        )

        violated: List[str] = []
        reasons: List[str] = []

        if best_entry.expires_at:
            exp_dt = _parse_iso_datetime(best_entry.expires_at, end_of_day_for_date=True)
            if now_dt > exp_dt:
                violated.append("expired")
                reasons.append(f"expired: decision expired at {best_entry.expires_at}")

        assumptions = best_entry.assumptions
        if assumptions.get("in_kev") is not None:
            expected_kev = bool(assumptions["in_kev"])
            actual_kev = bool(_get_field(finding_facts, "in_kev", "cisa_kev", default=False))
            if actual_kev != expected_kev:
                violated.append("kev_flipped")
                reasons.append(f"kev_flipped: expected in_kev={expected_kev}, actual={actual_kev}")

        if assumptions.get("max_epss") is not None:
            actual_epss = _get_field(finding_facts, "epss_score", "epss")
            if actual_epss is not None and float(actual_epss) > float(assumptions["max_epss"]):
                violated.append("epss_exceeded")
                reasons.append(
                    f"epss_exceeded: epss={float(actual_epss):.4f} > max_epss={float(assumptions['max_epss']):.4f}"
                )

        if assumptions.get("max_epss_percentile") is not None:
            actual_pct = _get_field(finding_facts, "epss_percentile")
            if actual_pct is not None and float(actual_pct) > float(assumptions["max_epss_percentile"]):
                violated.append("epss_percentile_exceeded")
                reasons.append(
                    f"epss_percentile_exceeded: percentile={float(actual_pct):.4f} > "
                    f"max_epss_percentile={float(assumptions['max_epss_percentile']):.4f}"
                )

        if assumptions.get("internet_facing") is not None:
            expected_facing = bool(assumptions["internet_facing"])
            actual_facing = _get_field(finding_facts, "internet_facing")
            if actual_facing is None:
                actual_facing = _get_field(asset_context, "internet_facing")
            if actual_facing is not None and bool(actual_facing) != expected_facing:
                violated.append("exposure_flipped")
                reasons.append(
                    f"exposure_flipped: expected internet_facing={expected_facing}, actual={bool(actual_facing)}"
                )

        if assumptions.get("max_cvss") is not None:
            actual_cvss = _get_field(finding_facts, "cvss_score", "cvss")
            if actual_cvss is not None and float(actual_cvss) > float(assumptions["max_cvss"]):
                violated.append("cvss_exceeded")
                reasons.append(
                    f"cvss_exceeded: cvss={float(actual_cvss):.1f} > max_cvss={float(assumptions['max_cvss']):.1f}"
                )

        status = "valid" if not violated else "invalidated"
        return DecisionEvaluation(
            matched=True,
            status=status,
            decision_id=best_entry.id,
            decision_status=best_entry.status,
            violated_predicates=tuple(violated),
            reasons=tuple(reasons),
            assumed_state=dict(assumptions),
            rationale=best_entry.rationale,
            owner=best_entry.owner,
            expires_at=best_entry.expires_at,
        )


def upsert_decision(
    path: Union[Path, str],
    entry: Dict[str, Any],
    *,
    pfh: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Safely insert or update a decision entry in decisions.yaml using ruamel.yaml,
    validating against decisions.schema.json before writing.
    """
    clean_entry = _to_json_compatible(entry)
    _validate_decision_entry(clean_entry)

    p = Path(path)
    rt_yaml = YAML(typ="rt")
    rt_yaml.preserve_quotes = True
    rt_yaml.indent(mapping=2, sequence=4, offset=2)

    data: Any = None
    if p.exists():
        if pfh is not None:
            with pfh.open_for_read(p, mode="r", encoding="utf-8", label="Decisions Config") as handle:
                raw_text = handle.read()
        else:
            raw_text = p.read_text(encoding="utf-8")
        if raw_text.strip():
            # Verify safe load structure first, then load round-trip to preserve comments
            safe_obj = _SAFE_YAML.load(raw_text)
            if safe_obj is not None and not isinstance(safe_obj, dict):
                raise ValueError("decisions.yaml root must be a mapping/object.")
            data = rt_yaml.load(raw_text)

    if data is None:
        data = {"version": "v2", "decisions": []}
    if "version" not in data:
        data["version"] = "v2"
    if "decisions" not in data or data["decisions"] is None:
        data["decisions"] = []

    decisions_list = data["decisions"]
    entry_id = str(clean_entry["id"]).strip()
    replaced = False
    for idx, existing in enumerate(decisions_list):
        if isinstance(existing, dict) and str(existing.get("id", "")).strip() == entry_id:
            decisions_list[idx] = clean_entry
            replaced = True
            break
    if not replaced:
        decisions_list.append(clean_entry)

    _validate_against_schema(dict(data), "decisions.schema.json", "Decisions config")

    if pfh is not None:
        with pfh.open_for_write(p, mode="w", encoding="utf-8", label="Decisions Config") as handle:
            rt_yaml.dump(data, handle)
    else:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = p.with_name(f".{p.name}.tmp.{os.getpid()}")
        with tmp_path.open("w", encoding="utf-8") as handle:
            rt_yaml.dump(data, handle)
        os.replace(tmp_path, p)

    return clean_entry
