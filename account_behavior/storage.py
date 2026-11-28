"""Fresh-database identity ledger. Nothing here opens a writer on the old database."""
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import re

import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from compact_behavior import FIVE
from compact_behavior.extract import field,identity,instant
from . import CONTRACT
from .identity import Evidence,observed

NEW_DATABASE='p24_accounts_20261127'
ORIGIN='2026-11-27T00:00:00+03:30'


def connect(settings, database=None):
    params={k:v for k,v in settings.items() if k not in ('options','application_name','autocommit','row_factory')}
    if database:params['dbname']=database
    params.update(application_name='P24.AccountQualification',autocommit=True,row_factory=dict_row)
    return psycopg.connect(**params)


DDL = (
    'CREATE SCHEMA p24_account',
    """CREATE TABLE p24_account.contract(singleton boolean PRIMARY KEY CHECK(singleton), version text NOT NULL,
        original_database text NOT NULL, original_oid oid NOT NULL, stream_id text NOT NULL, start_ns bigint NOT NULL,
        next_ns bigint NOT NULL)""",
    """CREATE TABLE p24_account.windows(start_ns bigint PRIMARY KEY, records bigint NOT NULL,
        request_count bigint NOT NULL, digest text NOT NULL, revision bigint NOT NULL)""",
    """CREATE TABLE p24_account.window_requests(start_ns bigint NOT NULL,request_id text NOT NULL,
        first_ns bigint NOT NULL,last_ns bigint NOT NULL,at1 bigint,uid1 bigint CHECK(uid1>0),
        at2 bigint,uid2 bigint CHECK(uid2>0),conflict_at bigint, PRIMARY KEY(start_ns,request_id))""",
    'CREATE INDEX account_fragment_request ON p24_account.window_requests(request_id,start_ns)',
    """CREATE TABLE p24_account.requests(request_id text PRIMARY KEY,first_ns bigint NOT NULL,last_ns bigint NOT NULL,
        user_id bigint CHECK(user_id>0),status text NOT NULL CHECK(status IN ('VERIFIED','CONFLICT','UNATTRIBUTED')),
        first_valid_ns bigint,conflict_from_ns bigint,revision bigint NOT NULL,
        CHECK ((status='VERIFIED')=(user_id IS NOT NULL)))""",
    'CREATE INDEX account_requests_by_user ON p24_account.requests(user_id, first_ns,request_id) WHERE user_id IS NOT NULL',
    """CREATE TABLE p24_account.identity_changes(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        request_id text NOT NULL,former_user_id bigint,current_user_id bigint,old_first_ns bigint,
        old_last_ns bigint,new_first_ns bigint,new_last_ns bigint,revision bigint NOT NULL,
        previous_status text,current_status text,changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
        UNIQUE(request_id,revision))""",
)


def prepare(settings,stream,name=NEW_DATABASE):
    if not re.fullmatch(r'p24_accounts_[a-z0-9_]{1,35}',name):raise ValueError('distinct_project_database_name_required')
    # The same original database and target name serialize prepare and recovery.
    with connect(settings) as origin:
        original=origin.execute('SELECT current_database() AS name,oid FROM pg_database WHERE datname=current_database()').fetchone()
        if name==original['name']:raise ValueError('target_equals_original_database')
        origin.execute("SELECT pg_advisory_lock(hashtextextended(%s,0))",('P24.AccountPrepare.'+name,))
        found=origin.execute('SELECT oid FROM pg_database WHERE datname=%s',(name,)).fetchone()
        if not found:origin.execute(sql.SQL('CREATE DATABASE {} TEMPLATE template0').format(sql.Identifier(name)))
        with connect(settings,name) as target,target.transaction():
            target.execute("SELECT pg_advisory_xact_lock(hashtextextended('P24.AccountSchema',0))")
            marker=target.execute("SELECT to_regclass('p24_account.contract') AS marker").fetchone()['marker']
            if not marker:
                objects=target.execute("""SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname NOT LIKE 'pg_%'
                    AND nspname NOT IN ('public','information_schema')) OR EXISTS(SELECT 1 FROM pg_class c
                    JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public') AS existing""").fetchone()
                if objects['existing']:raise ValueError('unmarked_target_contains_existing_objects')
                for ddl in DDL:target.execute(ddl)
                start=instant(ORIGIN)
                target.execute('INSERT INTO p24_account.contract VALUES(true,%s,%s,%s,%s,%s,%s)',
                               (CONTRACT,original['name'],original['oid'],stream,start,start))
            row=target.execute('SELECT * FROM p24_account.contract WHERE singleton').fetchone()
            if (not row or (row['version'],row['original_database'],row['original_oid'],row['stream_id'],row['start_ns'])
                    !=(CONTRACT,original['name'],original['oid'],stream,instant(ORIGIN))):
                raise ValueError('target_contract_source_or_origin_mismatch')
    return dict(status='ACCOUNT_DATABASE_PREPARED',database=name,source_database=original['name'],
                schema='p24_account',contract=CONTRACT,origin=ORIGIN,created=not bool(found))


@dataclass
class Fragment:
    first: int
    last: int
    evidence: Evidence

    def columns(self):
        pairs=list(self.evidence.witnesses)+[(None,None)]*2
        return (self.first,self.last,*pairs[0],*pairs[1],self.evidence.conflict_at)


def scan(source,start):
    fragments={};quality=Counter()
    for hit in source.records():
        raw,_=field(hit,'RequestID');request=identity(raw)
        value,_=field(hit,'@timestamp');at=instant(value)
        if not start<=at<start+FIVE:raise ValueError('record_outside_source_window')
        uid, reason = observed(hit)
        quality[reason] += 1
        if not request or set(request)=={'*'}:continue
        evidence = Evidence.from_observation(uid, reason, at)
        old=fragments.get(request)
        fragments[request]=Fragment(min(at,old.first),max(at,old.last),old.evidence.merge(evidence)) if old else Fragment(at,at,evidence)
    count=sum(quality.values());m=source.metadata
    if not (m.get('complete') is True and count==m.get('count')==m.get('expected_count')):
        raise ValueError('unverified_source_window')
    return fragments,count,dict(quality)


# Keep this lookup parameterized at any history depth. Each selected request can
# have evidence in several windows, so LIMIT 1 from the behavior lookup would lose data.
AFFECTED_FRAGMENTS = """SELECT f.* FROM affected k CROSS JOIN LATERAL (
    SELECT f.* FROM p24_account.window_requests f WHERE f.request_id=k.request_id OFFSET 0
) f"""


def publish(db,stream,start,fragments,count):
    """Replace one complete window, reconcile all fragments of its affected requests and commit the cursor."""
    if start % FIVE:raise ValueError('unaligned_window')
    digest=hashlib.sha256()
    for request,f in sorted(fragments.items()):
        digest.update(json.dumps((request,*f.columns()),separators=(',',':')).encode()+b'\n')
    signature=digest.hexdigest()
    with db.transaction():
        header=db.execute('SELECT * FROM p24_account.contract WHERE singleton FOR UPDATE').fetchone()
        if (not header or header['version']!=CONTRACT or header['stream_id']!=stream or
            not header['start_ns']<=start<=header['next_ns']):raise ValueError('account_source_or_checkpoint_mismatch')
        previous=db.execute('SELECT * FROM p24_account.windows WHERE start_ns=%s',(start,)).fetchone()
        if previous and (previous['digest'],previous['records'])==(signature,count):
            return dict(status='UNCHANGED',changes=0)
        db.execute('CREATE TEMP TABLE account_input (LIKE p24_account.window_requests) ON COMMIT DROP')
        with db.cursor().copy('COPY account_input FROM STDIN') as spool:
            for request,f in fragments.items():spool.write_row((start,request,*f.columns()))
        db.execute('CREATE TEMP TABLE affected ON COMMIT DROP AS SELECT request_id FROM account_input UNION SELECT request_id FROM p24_account.window_requests WHERE start_ns=%s',(start,))
        db.execute('CREATE UNIQUE INDEX ON affected(request_id)')
        db.execute('ANALYZE affected')
        db.execute('DELETE FROM p24_account.window_requests WHERE start_ns=%s',(start,))
        db.execute('INSERT INTO p24_account.window_requests SELECT * FROM account_input')
        # SQL recomputes claims after superseding a window. Missing earlier lines
        # can acquire a user, and a removed conflicting witness can restore one.
        db.execute(f"""CREATE TEMP TABLE new_account_requests ON COMMIT DROP AS
            WITH fragments AS MATERIALIZED (
                {AFFECTED_FRAGMENTS}),
            spans AS (SELECT request_id,min(first_ns) AS first_ns,max(last_ns) AS last_ns,min(conflict_at) AS bad FROM fragments GROUP BY request_id),
            candidates AS (SELECT request_id,uid,min(at) AS at FROM fragments CROSS JOIN LATERAL
                (VALUES(uid1,at1),(uid2,at2)) v(uid,at) WHERE uid IS NOT NULL GROUP BY request_id,uid),
            numbered AS (SELECT *,row_number() OVER(PARTITION BY request_id ORDER BY at,uid) AS seq FROM candidates),
            known AS (SELECT request_id,max(uid) FILTER(WHERE seq=1) AS uid,min(at) AS first_valid_ns,
                min(at) FILTER(WHERE seq=2) AS second_ns FROM numbered GROUP BY request_id),
            resolved AS (SELECT s.*, k.uid,k.first_valid_ns,least(s.bad,k.second_ns) AS conflict_from_ns
                FROM spans s LEFT JOIN known k USING(request_id))
            SELECT request_id,first_ns,last_ns,CASE WHEN conflict_from_ns IS NULL THEN uid END AS user_id,
                CASE WHEN conflict_from_ns IS NOT NULL THEN 'CONFLICT' WHEN uid IS NULL THEN 'UNATTRIBUTED'
                ELSE 'VERIFIED' END AS status,first_valid_ns,conflict_from_ns FROM resolved""")
        db.execute('CREATE UNIQUE INDEX ON new_account_requests(request_id)')
        db.execute('ANALYZE new_account_requests')
        changed=db.execute("""INSERT INTO p24_account.identity_changes
            (request_id,former_user_id,current_user_id,old_first_ns,old_last_ns,new_first_ns,new_last_ns,revision,previous_status,current_status)
            SELECT k.request_id,o.user_id,n.user_id,o.first_ns,o.last_ns,n.first_ns,n.last_ns,
            coalesce(o.revision, (SELECT max(c.revision) FROM p24_account.identity_changes c WHERE c.request_id=k.request_id),0)+1,
            o.status,n.status FROM affected k LEFT JOIN p24_account.requests o USING(request_id)
            LEFT JOIN new_account_requests n USING(request_id) WHERE
            (o.first_ns,o.last_ns,o.user_id,o.status,o.first_valid_ns,o.conflict_from_ns) IS DISTINCT FROM
            (n.first_ns,n.last_ns,n.user_id,n.status,n.first_valid_ns,n.conflict_from_ns)""").rowcount
        db.execute("""DELETE FROM p24_account.requests r USING affected k WHERE r.request_id=k.request_id
            AND NOT EXISTS(SELECT 1 FROM new_account_requests n WHERE n.request_id=r.request_id)""")
        db.execute("""INSERT INTO p24_account.requests AS old
            SELECT n.*,c.revision FROM new_account_requests n CROSS JOIN LATERAL
            (SELECT revision FROM p24_account.identity_changes WHERE request_id=n.request_id ORDER BY revision DESC LIMIT 1) c
            ON CONFLICT(request_id) DO UPDATE SET (first_ns,last_ns,user_id,status,first_valid_ns,conflict_from_ns,revision)=
            (excluded.first_ns,excluded.last_ns,excluded.user_id,excluded.status,excluded.first_valid_ns,excluded.conflict_from_ns,excluded.revision)
            WHERE old.revision<>excluded.revision""")
        db.execute("""INSERT INTO p24_account.windows AS w VALUES(%s,%s,%s,%s,1)
            ON CONFLICT(start_ns) DO UPDATE SET records=excluded.records,request_count=excluded.request_count,
            digest=excluded.digest,revision=w.revision+1""",(start,count,len(fragments),signature))
        db.execute('UPDATE p24_account.contract SET next_ns=greatest(next_ns,%s) WHERE singleton',(start+FIVE,))
    return dict(status='COMMITTED',changes=changed)
