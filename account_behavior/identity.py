"""Resolve only the structured NLog UserID, within one logical RequestID."""
from dataclasses import dataclass
import re

MAX_ID = 2**63-1  # Session.Info obtains a CLR Int64.
DECIMAL = re.compile('[0-9]{1,19}', re.ASCII)
ABSENT = frozenset(('', 'n/a', 'null', 'none', 'unknown', '-'))


def normalize(value):
    if value is None:
        return None, 'NULL'
    if type(value) is str:
        value=value.strip()
        if value.casefold() in ABSENT:
            return None,'EMPTY'
        if value and set(value)=={'*'}:
            return None,'MASKED'
        if not DECIMAL.fullmatch(value):
            return None,'INVALID'
        value=int(value)
    if type(value) is not int or not 0 <= value <= MAX_ID:
        return None,'INVALID'
    if value==0:
        return None,'ZERO_UNATTRIBUTED'
    return value,'VALID'


def observed(row):
    """Compare normalized source/doc-value representations, without payload traversal."""
    containers=[row.get('_source',row if 'fields' not in row else {}),row.get('fields',{})]
    values=set()
    reasons=[]
    for obj in containers:
        if not isinstance(obj,dict) or 'UserID' not in obj:
            continue
        raw=obj['UserID']
        if isinstance(raw,list):
            if not raw:
                reasons.append('EMPTY')
                continue
            if len(raw)!=1:
                return None,'CONFLICT'
            raw=raw[0]
        value,reason=normalize(raw)
        reasons.append(reason)
        if value is not None:
            values.add(value)
    if len(values)>1 or (values and any(r!='VALID' for r in reasons)):
        return None,'CONFLICT'
    if values:
        return values.pop(),'VALID'
    return None, (reasons[0] if reasons else 'MISSING')


@dataclass(frozen=True)
class Evidence:
    # Two earliest distinct observations suffice to answer every as-of query.
    witnesses: tuple = ()
    conflict_at: int|None = None

    @classmethod
    def from_row(cls,row,at):
        uid,reason=observed(row)
        return cls(((at,uid),)) if uid is not None else cls((),at if reason=='CONFLICT' else None)

    def merge(self,other):
        earliest={}
        for at,uid in self.witnesses+other.witnesses:
            earliest[uid]=min(earliest.get(uid,at),at)
        pairs=tuple(sorted((at,uid) for uid,at in earliest.items())[:2])
        conflicts=[at for at in (self.conflict_at,other.conflict_at) if at is not None]
        return Evidence(pairs,min(conflicts,default=None))

    def resolve(self,before=None):
        visible=[uid for at,uid in self.witnesses if before is None or at<before]
        if len(visible)>1 or (self.conflict_at is not None and (before is None or self.conflict_at<before)):
            return None,'CONFLICT'
        return (visible[0],'VERIFIED') if visible else (None,'UNATTRIBUTED')
