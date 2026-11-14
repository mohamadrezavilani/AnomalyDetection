"""Material revision and capture projection are distinct (R5)."""
from __future__ import annotations
import json,re,zlib
from datetime import datetime,timezone

_CAPTURE_META={'_es_export_meta','_source_id','_index','_id','_type','_score','sort','highlight'}

def instant(raw):
    if not isinstance(raw,str):return None
    try:
        dt=datetime.fromisoformat(raw.replace('Z','+00:00'))
        if dt.tzinfo is None:return None
        return dt.astimezone(timezone.utc)
    except (ValueError,OverflowError):return None

def precision(raw):
    if not isinstance(raw,str):return 0
    m=re.search(r'\.(\d+)(?:Z|[+-]\d\d:\d\d)$',raw)
    return min(len(m.group(1)),6) if m else 0

def compatible_capture(previous, incoming):
    """Identical overlapping *material* fields; timestamp precision tolerant.

    Never infer equivalence from common RequestID/IP/session alone: message,
    callpath and other overlapping fields must have equal values.
    """
    if not isinstance(previous,dict) or not isinstance(incoming,dict):return False
    before=instant(previous.get('@timestamp'));after=instant(incoming.get('@timestamp'))
    if before and after:
        # Truncate UTC wallclock microseconds to the less precise capture.
        digits=min(precision(previous['@timestamp']),precision(incoming['@timestamp']))
        unit=10**(6-digits)
        a=int(before.timestamp())*1_000_000+before.microsecond
        b=int(after.timestamp())*1_000_000+after.microsecond
        if a//unit!=b//unit:return False
    elif previous.get('@timestamp')!=incoming.get('@timestamp'):
        return False
    keys=(set(previous)&set(incoming))-(_CAPTURE_META|{'@timestamp'})
    if not {'RequestID','CallPath','message'}.issubset(keys):return False
    return all(previous[k]==incoming[k] for k in keys)

class CaptureMixin:
    def init_capture(self):
        blob='BLOB' if self.sqlite else 'BYTEA'
        self.sql(f'''CREATE TABLE IF NOT EXISTS viewer_capture_projections(
            origin_key TEXT NOT NULL, capture_key TEXT NOT NULL,canonical_version_key TEXT NOT NULL,
            file_hash TEXT NOT NULL, filename TEXT NOT NULL,row_number INTEGER NOT NULL,
            payload {blob} NOT NULL, PRIMARY KEY(origin_key,capture_key))''')
        self.sql('CREATE INDEX IF NOT EXISTS vcp_canonical ON viewer_capture_projections(origin_key,canonical_version_key)')
        self.conn.commit()

    def compatible_known_capture(self,origin,row,*,known_versions=None,raw_lookup=None):
        from .viewer_origin_storage import parameter_equal
        versions=known_versions if known_versions is not None else self.all('SELECT version_key FROM viewer_events WHERE '+parameter_equal(self,'origin_key'),(origin,))
        for old in versions:
            original=raw_lookup.get((origin,old['version_key'])) if raw_lookup is not None else self.get_raw(origin,old['version_key'])
            if original and compatible_capture(original,row):return old['version_key']
        return None

    def record_compatible_capture(self,origin,signature,canonical,digest,name,n,row):
        blob=zlib.compress(json.dumps(row,ensure_ascii=False,separators=(',',':')).encode(),6)
        if getattr(self,'_ingest_buffers',None) is not None:
            self._ingest_insert('viewer_capture_projections',(origin,signature,canonical,digest,name,n,blob))
            return
        self.sql('''INSERT INTO viewer_capture_projections VALUES(?,?,?,?,?,?,?) ON CONFLICT DO NOTHING''',
                 (origin,signature,canonical,digest,name,n,blob))
