"""Immutable, scoped interpretation rules over source-linked code candidates."""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import asdict, dataclass

from .errors import FoundationError

OUTCOME_RESOLVER_VERSION = "p24-scoped-outcomes.2r.1"


@dataclass(frozen=True)
class OutcomeRule:
    rule_id: str
    revision: str
    endpoint: str
    role: str
    layer: str
    path: str
    code: str
    outcome: str
    evidence_ref: str
    entry_id: str | None = None
    entry_sha256: str | None = None
    symbol: str | None = None
    effective_from_ns: int | None = None
    effective_until_ns: int | None = None


# Finite bindings already reviewed against retained samples. These do not
# declare workbook ownership of other operations or general service semantics.
_ELECTRICITY = "559ee31240a6554076affa08cdc1763b5698da4669b191e422938b66660534b5"
_CREDENTIAL = "b1b0a24ee625418b4d056461d29d3a6ace769544ab84e00fc8666631a1242aa2"
REVIEWED_RULES = (
    OutcomeRule("credential-client-rejection", "1", "Core.v1/LoginByUserCredential", "client_http",
                "platform_log", "message.status.code", "GR0054", "failure",
                "fixtures/session_activity.sanitized.json", "Pishkhan24:Sheet1:55", _CREDENTIAL),
    OutcomeRule("electricity-client-failure", "1", "Services.v3/ElectricBillsExport", "client_http",
                "platform_log", "message.status.code", "GD2016", "failure",
                "fixtures/boundary.sanitized.json", "WebCrawler:WebCrawler:17", _ELECTRICITY),
    OutcomeRule("electricity-provider-body-failure", "1", "ClientAyanCoInquiry.ElectricityBillInquiryGetBillImage",
                "provider", "provider_body", "Output[0].Status.Code", "GD2016", "failure",
                "fixtures/boundary.sanitized.json", "WebCrawler:WebCrawler:17", _ELECTRICITY),
)


class ScopedOutcomeResolver:
    def __init__(self, catalog, *, rules=REVIEWED_RULES):
        self.by_code = defaultdict(list)
        for row in catalog.get("records", []):
            if isinstance(row, dict) and isinstance(row.get("code"), str):
                self.by_code[row["code"]].append(row)
        self.rules = tuple(rules)
        ids = set()
        for rule in self.rules:
            identity = rule.rule_id, rule.revision
            if (not all(isinstance(v, str) and v for v in (
                    rule.rule_id, rule.revision, rule.endpoint, rule.role, rule.layer,
                    rule.path, rule.code, rule.evidence_ref)) or identity in ids
                    or rule.outcome not in {"success", "failure", "pending", "partial", "unknown"}
                    or (rule.entry_id is None) != (rule.entry_sha256 is None)
                    or (rule.effective_from_ns is not None and rule.effective_until_ns is not None
                        and rule.effective_from_ns >= rule.effective_until_ns)):
                raise FoundationError("invalid_scoped_outcome_rule")
            ids.add(identity)
        content = dict(version=OUTCOME_RESOLVER_VERSION, catalog=catalog,
                       rules=sorted((asdict(r) for r in self.rules), key=lambda r: (r["rule_id"], r["revision"])))
        self.digest = hashlib.sha256(json.dumps(content, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False).encode()).hexdigest()

    @staticmethod
    def _candidate(row):
        return {key: row.get(key) for key in (
            "entry_id", "code_system", "source_file", "source_sha256", "source_sheet", "source_row",
            "definition_state", "log_symbol_normalized")}

    def resolve(self, code, *, endpoint, role, layer, path, symbol=None, at_ns=None):
        candidates = sorted((self._candidate(r) for r in self.by_code.get(code, [])),
                            key=lambda r: (r.get("entry_id") or "", r.get("source_sha256") or ""))
        matched = []
        for rule in self.rules:
            if (rule.endpoint, rule.role, rule.layer, rule.path, rule.code) != (endpoint, role, layer, path, code):
                continue
            if rule.symbol is not None and rule.symbol != symbol:
                continue
            if rule.effective_from_ns is not None or rule.effective_until_ns is not None:
                if at_ns is None:
                    continue
                if rule.effective_from_ns is not None and at_ns < rule.effective_from_ns:
                    continue
                if rule.effective_until_ns is not None and at_ns >= rule.effective_until_ns:
                    continue
            matched.append(rule)
        result = dict(outcome="unknown", meaning_fa=None, meaning_source=None,
                      validation="unresolved", resolver_version=OUTCOME_RESOLVER_VERSION,
                      interpretation_state="candidate_only" if candidates else "undocumented",
                      meaning_candidates=candidates, applied_rule=None)
        # Multiple active revisions are a conflict even when they happen to
        # return the same outcome. A future rule never silently wins.
        if len(matched) > 1:
            result.update(outcome="conflicting", interpretation_state="conflicting_rules",
                          validation="conflicting_scoped_rules")
        elif matched:
            rule = matched[0]
            entries = [r for r in self.by_code.get(code, []) if r.get("entry_id") == rule.entry_id
                       and r.get("source_sha256") == rule.entry_sha256]
            if rule.entry_id is not None and len(entries) != 1:
                result.update(interpretation_state="binding_source_unavailable", validation="binding_source_unavailable")
                return result
            result.update(outcome=rule.outcome, interpretation_state="reviewed_sample_binding",
                          validation="reviewed_sample_and_catalog", applied_rule=dict(
                              id=rule.rule_id, revision=rule.revision, evidence_ref=rule.evidence_ref))
            if entries and entries[0].get("definition_state") in {"complete_definition", "partial_definition"}:
                entry = entries[0]
                result.update(meaning_fa=entry.get("user_message_fa"), meaning_source=dict(
                    entry_id=entry["entry_id"], source_sha256=entry["source_sha256"]))
        elif layer == "platform_log" and code == "G00000" and symbol == "successful":
            result.update(outcome="success", interpretation_state="literal_log_label", validation="observed_log_label")
        return result
