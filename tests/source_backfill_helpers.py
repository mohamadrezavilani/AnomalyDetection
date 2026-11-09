"""Populated pre-2H schema fixtures, isolated from every existing schema.

Only the schema identifier is substituted. SQL bodies, constraints, migration
checksums, psycopg transactions and the actual initialize/backfill path run.
The fixture writer creates synthetic legacy evidence without any 2H tables.
"""
import hashlib
import re
import uuid
from datetime import datetime, timezone

from p24_foundation.parser import PARSER_VERSION
from p24_foundation.store import ROOT, execute_many, jsonb
from tests.helpers import batch, normalized


class SchemaConnection:
    def __init__(self, connection, schema):
        if not re.fullmatch(r"p24_backfill_[a-f0-9]{32}", schema):
            raise ValueError("invalid fixture schema")
        self.connection, self.schema = connection, schema

    @property
    def autocommit(self):
        return self.connection.autocommit

    def query(self, query):
        return re.sub(r"\bp24_next\b", self.schema, query)

    def params(self, params):
        if params is None:
            return None
        return tuple(self.query(p) if isinstance(p,str) and re.fullmatch(r"p24_next\.[a-z0-9_]+",p)
                     else p for p in params)

    def execute(self, query, params=None, **kwargs):
        return self.connection.execute(self.query(query), self.params(params), **kwargs)

    def transaction(self):
        return self.connection.transaction()

    def cursor(self):
        return SchemaCursor(self)


class SchemaCursor:
    def __init__(self, connection):
        self.connection=connection
        self.cursor=connection.connection.cursor()

    def __enter__(self):
        self.cursor.__enter__()
        return self

    def __exit__(self, *args):
        return self.cursor.__exit__(*args)

    def executemany(self, query, rows):
        return self.cursor.executemany(self.connection.query(query),
                                      [self.connection.params(p) for p in rows])


def pre_2h_schema(connection):
    versions=("p24-domain.3","p24-foundation.2a.1","p24-foundation.2b.1",
              "p24-foundation.2c.1","p24-foundation.2d.1","p24-foundation.2e.1",
              "p24-foundation.2f.1","p24-foundation.2g.1")
    migrations=sorted((ROOT/"sql").glob("*.sql"))[:8]
    for version,path in zip(versions,migrations):
        text=path.read_text(encoding="utf-8")
        digest=hashlib.sha256(text.encode()).hexdigest()
        before,_,_=text.rpartition("COMMIT;")
        connection.execute(before+"INSERT INTO p24_next.design_version(version_key,content_sha256) "
                           "VALUES('"+version+"','"+digest+"');\nCOMMIT;",prepare=False)


def legacy_source(store, ordinal, *, rows=(), assessment=None, basis="synthetic_fixture",
                  omit_metadata=False, omit_object=False):
    """Write only predecessor-schema columns using public synthetic evidence."""
    c=store.c;n=store.namespace_id;sid=uuid.UUID(int=ordinal+1);oid=uuid.uuid4()
    source=batch(list(rows));digest=hashlib.sha256(source.original).hexdigest()
    archived=store.vault.put(source.original,object_scope=str(sid))
    received=datetime(2026,10,20,7,40,tzinfo=timezone.utc)
    window="synthetic-legacy-"+str(ordinal)
    with c.transaction():
        c.execute("INSERT INTO p24_next.source_window VALUES(%s,%s,'2026-10-20T07:25:00Z','2026-10-20T07:45:00Z')",(n,window))
        c.execute("""INSERT INTO p24_next.source_snapshot
            (namespace_id,window_key,snapshot_id,intake_revision,source_digest,observed_at,source_complete,raw_event_count)
            VALUES(%s,%s,%s,1,%s,%s,false,%s)""",(n,window,sid,digest,received,len(rows)))
        if not omit_object:
            c.execute("""INSERT INTO p24_next.raw_object
                (namespace_id,object_id,snapshot_id,storage_key,content_sha256,format_key,byte_count,row_count,encryption_key_ref,manifest_key)
                VALUES(%s,%s,%s,%s,%s,'json',%s,%s,%s,%s)""",
                (n,oid,sid,archived['storage_key'],digest,len(source.original),len(rows),store.keys.version,"synthetic-legacy"))
        if not omit_metadata:
            c.execute("INSERT INTO p24_next.foundation_snapshot_metadata VALUES(%s,%s,%s,%s,%s,%s)",
                      (n,sid,source.coverage['input_format'],jsonb(source.coverage),archived['cipher_sha256'],basis))
        if assessment is not None:
            c.execute("""INSERT INTO p24_next.foundation_acquisition_assessment
                (namespace_id,snapshot_id,assessment_version,source_digest,capture_claim_state,
                 query_traversal_complete,source_window_complete,assessment) VALUES
                (%s,%s,'p24-scroll-capture.1',%s,'unverified_local_capture',false,false,%s)""",
                (n,sid,digest,jsonb(assessment)))
        events=normalized(list(rows),store.namespace)
        for e in events:
            q=e['request_key'];v=e['event_version_id'];d=e['descriptor']
            c.execute("INSERT INTO p24_next.logical_request VALUES(%s,%s,%s,clock_timestamp()) ON CONFLICT DO NOTHING",(n,q,store.keys.version))
            for session in d['session_candidates']:
                c.execute("INSERT INTO p24_next.user_session(namespace_id,session_key,key_version) VALUES(%s,%s,%s) ON CONFLICT DO NOTHING",(n,session,store.keys.version))
            c.execute("INSERT INTO p24_next.event_identity VALUES(%s,%s,%s,'origin-index-id.1') ON CONFLICT DO NOTHING",(n,e['event_key'],e['identity_kind']))
            c.execute("""INSERT INTO p24_next.event_version
                (namespace_id,event_version_id,event_key,content_sha256,source_event_time,timestamp_precision,request_key,source_role,endpoint,event_kind,received_at,source_time_epoch_ns,source_time_fraction_digits)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                (n,v,e['event_key'],e['content_digest'],e['time'].floor,e['time'].precision,q,d['role'],d['endpoint'],d['event_kind'],received,str(e['time'].epoch_ns),e['time'].fraction_digits))
            c.execute("INSERT INTO p24_next.foundation_event_descriptor VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING",(n,v,PARSER_VERSION,jsonb(e['payload'])))
        execute_many(c,"INSERT INTO p24_next.foundation_row_membership VALUES(%s,%s,%s,%s)",[(n,sid,i,e['event_version_id']) for i,e in enumerate(events)])
        execute_many(c,"INSERT INTO p24_next.event_source VALUES(%s,%s,%s,%s,0,%s)",[(n,sid,e['event_version_id'],oid,i) for i,e in enumerate(events)])
        execute_many(c,"INSERT INTO p24_next.request_source VALUES(%s,%s,%s,1,1)",[(n,e['request_key'],sid) for e in events])
    return sid
