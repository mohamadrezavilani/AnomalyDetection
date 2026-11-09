"""Local-only, full-fidelity forensic event storage for the Viewer.

Payload is zlib-compressed JSON, not encrypted. The database and its backups
contain full source credentials/PII, so access must be restricted accordingly.
"""
from __future__ import annotations
import gzip
import hashlib
import json
import zlib
from pathlib import Path

from .parser import opaque


class RawEvidenceMixin:
    def init_raw(self):
        typ='BLOB' if self.sqlite else 'BYTEA'
        self.sql('''CREATE TABLE IF NOT EXISTS viewer_raw_events(
            origin_key TEXT NOT NULL, version_key TEXT NOT NULL,
            raw_request_id TEXT, raw_session_id TEXT, raw_ip TEXT,
            payload '''+typ+''' NOT NULL,
            PRIMARY KEY(origin_key,version_key))''')
        self.conn.commit()

    def raw_fields(self,row):
        data=json.dumps(row,ensure_ascii=False,separators=(',',':')).encode('utf-8')
        return (opaque(row.get('RequestID')),opaque(row.get('Session')),
                opaque(row.get('IP')),zlib.compress(data,6))

    def raw_keys(self,row,hash_value,ordinal):
        from .viewer_data import token, source_identity
        idx,docid=source_identity(row)
        origin=token(self.keys,'origin',[idx,docid] if idx else [hash_value,ordinal])
        version=token(self.keys,'version',row)
        return origin,version

    def insert_raw_event(self,origin,version,row):
        if getattr(self,'_ingest_buffers',None) is not None:
            self._ingest_insert('viewer_raw_events',(origin,version,*self.raw_fields(row)))
            return
        self.sql('''INSERT INTO viewer_raw_events(origin_key,version_key,raw_request_id,raw_session_id,raw_ip,payload)
                    VALUES (?,?,?,?,?,?) ON CONFLICT(origin_key,version_key) DO NOTHING''',
                 (origin,version,*self.raw_fields(row)))

    def hydrate_raw(self,paths):
        """Non-destructively load source record bodies into an already populated DB.

        Only accepts imported file hashes; only persists records for matching
        pre-existing origin/version keys. File order and repeated calls are safe.
        """
        self.init_raw()
        report=[]
        for source in paths:
            source=Path(source).resolve()
            sha256=hashlib.sha256(source.read_bytes()).hexdigest()
            file_row=self.one('SELECT record_count FROM viewer_files WHERE file_hash=?',(sha256,))
            if not file_row:
                report.append(dict(file=source.name,status='SHA_MISMATCH_OR_NOT_IMPORTED'))
                continue
            try:
                with gzip.open(source,'rt',encoding='utf-8') as f: payload=json.load(f)
                rows=payload['logs']
                if len(rows)!=file_row['record_count']:raise ValueError('row_count_mismatch')
                before=self.one('SELECT COUNT(*) AS n FROM viewer_raw_events')['n']
                if self.sqlite:
                    statement='''INSERT OR IGNORE INTO viewer_raw_events
                             SELECT ?,?,?,?,?,? WHERE EXISTS (
                               SELECT 1 FROM viewer_events WHERE origin_key=? AND version_key=?)'''
                    batch=[]
                    for n,row in enumerate(rows):
                        keys=self.raw_keys(row,sha256,n)
                        batch.append((*keys,*self.raw_fields(row),*keys))
                        if len(batch)>=1000:
                            self.conn.executemany(statement,batch);batch.clear()
                    if batch:self.conn.executemany(statement,batch)
                else:
                    # COPY once per window, not 50k individual network round trips.
                    self.sql('''CREATE TEMP TABLE viewer_raw_stage(
                      origin_key TEXT,version_key TEXT,raw_request_id TEXT,
                      raw_session_id TEXT,raw_ip TEXT,payload BYTEA) ON COMMIT DROP''')
                    with self.conn.cursor() as cur:
                        with cur.copy('''COPY viewer_raw_stage
                          (origin_key,version_key,raw_request_id,raw_session_id,raw_ip,payload)
                          FROM STDIN''') as copy:
                            for n,row in enumerate(rows):
                                copy.write_row((*self.raw_keys(row,sha256,n),*self.raw_fields(row)))
                    self.sql('''INSERT INTO viewer_raw_events(origin_key,version_key,raw_request_id,raw_session_id,raw_ip,payload)
                       SELECT t.origin_key,t.version_key,t.raw_request_id,t.raw_session_id,t.raw_ip,t.payload
                       FROM viewer_raw_stage t JOIN viewer_events e
                       ON e.origin_key=t.origin_key AND e.version_key=t.version_key
                       ON CONFLICT(origin_key,version_key) DO NOTHING''')
                    self.sql('DROP TABLE viewer_raw_stage')
                after=self.one('SELECT COUNT(*) AS n FROM viewer_raw_events')['n']
                self.conn.commit()
                report.append(dict(file=source.name,status='HYDRATED',rows=len(rows),added=after-before))
            except Exception as exc:
                self.conn.rollback()
                report.append(dict(file=source.name,status='FAILED',error=type(exc).__name__))
        return report

    def raw_coverage(self):
        total=self.one('SELECT COUNT(*) AS n FROM viewer_events')['n']
        stored=self.one('SELECT COUNT(*) AS n FROM viewer_raw_events')['n']
        return dict(events=total,raw_events=stored,missing=total-stored,complete=(total==stored))

    def get_raw(self,origin,version):
        row=self.one('SELECT payload FROM viewer_raw_events WHERE origin_key=? AND version_key=?',(origin,version))
        if not row:return None
        return json.loads(zlib.decompress(bytes(row['payload'])).decode('utf-8'))

    def raw_session_id(self,session_key):
        if not self.sqlite:return self._indexed_raw_identity('session_key','raw_session_id',session_key)
        row=self.one('''SELECT b.raw_session_id FROM viewer_events e
            JOIN viewer_raw_events b ON b.origin_key=e.origin_key AND b.version_key=e.version_key
            WHERE e.session_key=? AND b.raw_session_id IS NOT NULL LIMIT 1''',(session_key,))
        return row['raw_session_id'] if row else None

    def raw_request_id(self,request_key):
        if not self.sqlite:return self._indexed_raw_identity('request_key','raw_request_id',request_key)
        row=self.one('''SELECT b.raw_request_id FROM viewer_events e
            JOIN viewer_raw_events b ON b.origin_key=e.origin_key AND b.version_key=e.version_key
            WHERE e.request_key=? AND b.raw_request_id IS NOT NULL LIMIT 1''',(request_key,))
        return row['raw_request_id'] if row else None

    def _indexed_raw_identity(self,scope_column,raw_column,key):
        # The outer scan is limited by the event's indexed HMAC identity. The
        # lateral fence keeps LIMIT 1 from choosing a global raw-body scan on
        # every home row while the online writer is inserting new evidence.
        if (scope_column,raw_column) not in (('session_key','raw_session_id'),('request_key','raw_request_id')):
            raise ValueError('invalid_raw_identity_columns')
        row=self.one('SELECT body.value FROM viewer_events e CROSS JOIN LATERAL ('+
            'SELECT b.'+raw_column+' AS value FROM viewer_raw_events b '+
            'WHERE b.origin_key=e.origin_key AND b.version_key=e.version_key '+
            'AND b.'+raw_column+' IS NOT NULL OFFSET 0) body '+
            'WHERE e.'+scope_column+'=? LIMIT 1',(key,))
        return row['value'] if row else None
