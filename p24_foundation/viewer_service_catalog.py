"""Exact, source-backed proposals; operator choices and unknown versions win."""
from __future__ import annotations
from functools import lru_cache
import hashlib
import json
from pathlib import Path

CATALOG_PATH=Path(__file__).resolve().parents[1]/'catalogs/viewer_service_roles.json'


@lru_cache(maxsize=1)
def source_catalog():
    data=json.loads(CATALOG_PATH.read_text(encoding='utf-8'))
    for path,row in data['routes'].items():
        if row['role'] not in ('business','user_management','support','system','unknown'):
            raise ValueError('invalid_source_catalog_role')
        if not row.get('evidence'):raise ValueError('source_catalog_evidence_missing')
    return data


def role_proposal(path):
    path=str(path or '').split(' Line:',1)[0].strip()
    return source_catalog()['routes'].get(path)


def catalog_fingerprint(owner_rules,candidate_rules):
    data=dict(catalog=source_catalog(),owner_rules=owner_rules,candidate_rules=candidate_rules,policy='exact-role-sync-2-keyed-dispatch')
    return hashlib.sha256(json.dumps(data,sort_keys=True,ensure_ascii=True,separators=(',',':')).encode()).hexdigest()
