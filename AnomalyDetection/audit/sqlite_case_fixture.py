"""Actual case SQL on an isolated SQLite memory database, not PostgreSQL.

Only explicit dialect adaptations are made: bind lists, json text extraction,
BOOL_OR and GREATEST. This proves case transitions with real SQL execution;
PostgreSQL parsing, locks, concurrent CAS and durability remain separate.
"""
import json,re,sqlite3
from contextlib import nullcontext


def pg_text(body,key):
    value=json.loads(body).get(key)
    if value is None:return None
    if isinstance(value,bool):return 'true' if value else 'false'
    return str(value)


class Store:
    def __init__(self):
        self.db=sqlite3.connect(':memory:');self.db.row_factory=sqlite3.Row
        self.db.execute("ATTACH DATABASE ':memory:' AS anomaly_detection")
        class BoolOr:
            def __init__(self):self.value=False
            def step(self,x):self.value|=bool(x)
            def finalize(self):return self.value
        self.db.create_aggregate('BOOL_OR',1,BoolOr)
        self.db.create_function('GREATEST',-1,max);self.db.create_function('pg_text',2,pg_text)
        self.raw=self
    def close(self):self.db.close()
    def transaction(self):return nullcontext()
    def execute(self,sql,params=()):
        binds=[];it=iter(params)
        def bind(match):
            value=next(it)
            if match.group().startswith('=ANY'):
                binds.extend(value);return ' IN ('+(','.join('?' for _ in value) if value else 'NULL')+')'
            binds.append(value);return '?'
        sql=re.sub(r'=ANY\(%s\)|%s',bind,sql)
        sql=re.sub(r"([a-z]+\.body)::jsonb->>'([a-z_]+)'",r"pg_text(\1,'\2')",sql)
        sql=sql.replace('::jsonb','')
        return self.db.execute(sql,binds)
    def create_case_tables(self):
        from anomaly_detection.cases import DDL
        for sql in DDL:
            if sql.startswith('CREATE TABLE') and 'GENERATED' not in sql:self.execute(sql)
        self.execute('ALTER TABLE anomaly_detection.adp_case_signals ADD COLUMN primary_version BIGINT')
        for sql in (
            'CREATE TABLE anomaly_detection.adp_versions(request_key TEXT,observed_ns BIGINT)',
            'CREATE TABLE anomaly_detection.adp_profiles(request_key TEXT PRIMARY KEY,session_key TEXT,service_path TEXT,at_ns BIGINT,body TEXT,observed_ns BIGINT)',
            'CREATE TABLE anomaly_detection.adp_traffic_members(request_key TEXT,start_ns BIGINT,body TEXT)',
        ):self.execute(sql)
    def insert(self,table,row,fields=None):
        fields=fields or list(row)
        self.execute('INSERT INTO anomaly_detection.'+table+' ('+','.join(fields)+') VALUES ('+','.join('%s' for _ in fields)+')',tuple(row[k] for k in fields))
