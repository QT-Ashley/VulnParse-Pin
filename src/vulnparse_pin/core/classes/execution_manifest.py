from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Any, Dict, List, Optional


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_text(text: str) -> str:
    return f"sha256:{sha256(text.encode('utf-8')).hexdigest()}"


EMPTY_LEDGER_ROOT = _sha256_text("vpp-ledger-empty-root-v1")


@dataclass(frozen=True)
class DecisionWhy:
    reason_code: str
    reason_text: str
    factor_refs: List[str] = field(default_factory=list)
    confidence: Optional[str] = None
    weight_context: Optional[str] = None


@dataclass(frozen=True)
class DecisionLedgerEntry:
    seq: int
    ts: str
    component: str
    event_type: str
    subject_ref: str
    why: DecisionWhy
    evidence_digest: str
    prev_hash: str
    entry_hash: str


@dataclass(frozen=True)
class DecisionLedgerSnapshot:
    chain_version: str
    entry_count: int
    chain_root: str
    entries: List[DecisionLedgerEntry]


class LedgerService:
    """Runtime decision ledger with append-only hash-chaining semantics."""

    def __init__(self, chain_version: str = "1.0"):
        self._chain_version = chain_version
        self._entries: List[DecisionLedgerEntry] = []

    def append_event(
        self,
        *,
        component: str,
        event_type: str,
        subject_ref: str,
        reason_code: str,
        reason_text: str,
        factor_refs: Optional[List[str]] = None,
        confidence: Optional[str] = None,
        weight_context: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> DecisionLedgerEntry:
        seq = len(self._entries) + 1
        ts = _utc_now_z()
        why = DecisionWhy(
            reason_code=reason_code,
            reason_text=reason_text,
            factor_refs=list(factor_refs or []),
            confidence=confidence,
            weight_context=weight_context,
        )

        evidence_payload = evidence or {}
        evidence_digest = _sha256_text(_canonical_json(evidence_payload))
        prev_hash = self._entries[-1].entry_hash if self._entries else EMPTY_LEDGER_ROOT

        hash_input = {
            "seq": seq,
            "ts": ts,
            "component": component,
            "event_type": event_type,
            "subject_ref": subject_ref,
            "why": asdict(why),
            "evidence_digest": evidence_digest,
            "prev_hash": prev_hash,
        }
        entry_hash = _sha256_text(_canonical_json(hash_input))

        entry = DecisionLedgerEntry(
            seq=seq,
            ts=ts,
            component=component,
            event_type=event_type,
            subject_ref=subject_ref,
            why=why,
            evidence_digest=evidence_digest,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self._entries.append(entry)
        return entry

    def snapshot(self) -> DecisionLedgerSnapshot:
        chain_root = self._entries[-1].entry_hash if self._entries else EMPTY_LEDGER_ROOT
        return DecisionLedgerSnapshot(
            chain_version=self._chain_version,
            entry_count=len(self._entries),
            chain_root=chain_root,
            entries=list(self._entries),
        )
