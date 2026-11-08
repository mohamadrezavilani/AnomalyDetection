"""Test-only PostgreSQL WASM engine transport over pipes, not a native server.

PGlite has one database/session. This harness selects each virtual connection's
role, substitutes the test database name, and implements COPY rows as parameter
INSERTs. Native authentication, COPY protocol, socket timing, multi-session
isolation and server durability are explicitly NOT validated by this transport.
"""
import base64
from contextlib import contextmanager
import json
from pathlib import Path
import subprocess
from decimal import Decimal

import psycopg
from psycopg.rows import dict_row


class Engine:
    def __init__(self):
        self.process=subprocess.Popen(['node',str(Path(__file__).with_name('engine.mjs'))],stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
        assert json.loads(self.process.stdout.readline())['ready']
    def close(self):
        self.process.stdin.close()
        try: self.process.wait(timeout=5)
        except subprocess.TimeoutExpired: self.process.kill(); self.process.wait()
    def connect(self,*_args,**kwargs):
        role=kwargs.get('user','postgres')
        if role!='postgres':
            rows=self.query('postgres','SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=$1',(role,))['rows']
            if not rows:raise psycopg.errors.InvalidAuthorizationSpecification('test role not created')
        connection=Connection(self,role)
        if kwargs.get('autocommit') is False:connection.execute('BEGIN')
        return connection
    def query(self,role,query,params):
        if not isinstance(query,str): query=query.as_string()
        query=query.replace('current_database()',"'p24_design_viewer'::name")
        query=query.replace('DATABASE "p24_design_viewer"','DATABASE "postgres"')
        params=[str(x) if type(x) is int else x for x in params]
        self.process.stdin.write(json.dumps({'role':role,'sql':query,'params':params})+'\n'); self.process.stdin.flush()
        raw=self.process.stdout.readline()
        def decode(value):
            if '__pg_int' in value:return int(value['__pg_int'])
            if '__pg_float' in value:return float(value['__pg_float'])
            if '__pg_numeric' in value:return Decimal(value['__pg_numeric'])
            if '__pg_bytes' in value:return base64.b64decode(value['__pg_bytes'])
            return value
        value=json.loads(raw,object_hook=decode)
        if 'error' in value:
            error=RuntimeError(value['error']); error.sqlstate=value.get('code'); raise error
        return value


class Cursor:
    def __init__(self,c): self.c=c; self.rows=[]; self.rowcount=0; self.description=None
    def __enter__(self): return self
    def __exit__(self,*_): pass
    def execute(self,query,params=()):
        if not isinstance(query,str): query=query.as_string()
        parts=query.split('%s')
        query=''.join(part+('$'+str(i+1) if i<len(parts)-1 else '') for i,part in enumerate(parts)).replace('%%','%')
        data=self.c.engine.query(self.c.role,query,params)
        self.rows=data['rows']; self.rowcount=data['rowcount']; self.description=bool(self.rows)
        return self
    def fetchone(self): return self.rows.pop(0) if self.rows else None
    def fetchall(self): rows=self.rows; self.rows=[]; return rows
    def executemany(self,query,rows):
        count=0
        for row in rows:
            self.execute(query,row); count+=self.rowcount
        self.rowcount=count
        return self
    @contextmanager
    def copy(self,query):
        text=query.as_string()
        prefix=text.replace('COPY ','INSERT INTO ',1).replace(' FROM STDIN','')
        cursor=self
        class Copy:
            def write_row(self,row): cursor.execute(prefix+' VALUES ('+','.join(['%s']*len(row))+')',row)
        yield Copy()


class Connection:
    def __init__(self,engine,role): self.engine=engine; self.role=role; self.closed=False;self.depth=0
    def __enter__(self): return self
    def __exit__(self,*_): self.close()
    def cursor(self): return Cursor(self)
    def execute(self,query,params=()):
        if not isinstance(query,str): query=query.as_string()
        return Cursor(self).execute(query,params)
    def commit(self): self.execute('COMMIT')
    def rollback(self): self.execute('ROLLBACK')
    def close(self): self.closed=True
    @contextmanager
    def transaction(self):
        nested=self.depth>0;name='test_savepoint_'+str(self.depth);self.depth+=1
        self.execute('SAVEPOINT '+name if nested else 'BEGIN')
        try:
            yield self
            self.execute('RELEASE SAVEPOINT '+name) if nested else self.commit()
        except BaseException:
            self.execute('ROLLBACK TO SAVEPOINT '+name) if nested else self.rollback()
            raise
        finally:self.depth-=1
