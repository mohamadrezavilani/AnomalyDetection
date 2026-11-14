"""Exact reversible origin/version index keys, without rewriting evidence.

Canonical 64-character lowercase HMAC hex uses 33 bytes, including a type
prefix. Other text uses a different prefix plus its complete UTF-8 bytes.
The mapping is injective; this is not a truncation or a second hash.
"""
from __future__ import annotations

import re
from contextlib import contextmanager
from .viewer_storage_keys import _autocommit

FUNCTION = 'public.viewer_hmac_bytes_v1'
LAYOUT = 'binary_origin_keys_v1'
BODY = """SELECT CASE WHEN pg_catalog.length(key_text)=64
    AND pg_catalog.translate(key_text,'0123456789abcdef','')=''
    THEN pg_catalog.decode('00','hex') || pg_catalog.decode(key_text,'hex')
    ELSE pg_catalog.decode('01','hex') || pg_catalog.convert_to(key_text,'UTF8') END"""
INDEXES = {'vei_binary_origin_v1': 'viewer_events', 'vre_binary_origin_v1': 'viewer_raw_events'}
MARKER = '/* viewer_binary_origin_v1 */'
# Quoted values/identifiers, comments and function bodies are never rewritten.
PROTECTED = re.compile(r"[eE]'(?:\\.|''|[^'\\])*'|'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|--[^\n]*|/\*.*?\*/|\$(?P<tag>[a-zA-Z_][a-zA-Z_0-9]*|)\$.*?\$(?P=tag)\$", re.S)
COMPARISON = re.compile(r'(?<![a-zA-Z_0-9.])(?P<left>[a-zA-Z_][a-zA-Z_0-9]*\.[a-zA-Z_][a-zA-Z_0-9]*)\s*=\s*'
    r'(?P<right>[a-zA-Z_][a-zA-Z_0-9]*(?:\.[a-zA-Z_][a-zA-Z_0-9]*)?)(?![a-zA-Z_0-9.])')


def key_sql(column):
    return FUNCTION+'('+column+')'


def _comparisons(statement):
    masked = PROTECTED.sub(lambda m: ' '*len(m[0]), statement)
    for match in COMPARISON.finditer(masked):
        left, right = match['left'], match['right']
        if not ({left.rsplit('.',1)[-1].lower(),right.rsplit('.',1)[-1].lower()} & {'origin_key','version_key'}):
            continue
        # Only column operands. Function calls, literals and parameters keep
        # their original SQL. Qualified assignment targets are invalid SQL, so
        # requiring a qualified left operand also excludes UPDATE SET targets.
        tail=masked[match.end():].lstrip()
        if ('.' not in right and right.lower() not in ('origin_key','version_key')
                or tail.startswith(('(',':','[','-','+','*','/','|','#','>','<'))):
            continue
        yield match


def needs_qualification(statement):
    return MARKER not in statement and next(_comparisons(statement), None) is not None


def qualify(statement):
    """Add index equality while retaining original equality for temporary keys.

    No binding is duplicated or changed. Original temporary-table text indexes
    remain usable, and the permanent binary index gets an exact equality too.
    """
    if MARKER in statement:
        return statement
    matches = list(_comparisons(statement))
    if not matches:
        return statement
    for match in reversed(matches):
        original = statement[match.start():match.end()]
        extra = key_sql(match['left'])+'='+key_sql(match['right'])
        statement = statement[:match.start()]+'('+original+' AND '+extra+')'+statement[match.end():]
    return statement+' '+MARKER


def active(db):
    if getattr(db,'sqlite',False):
        return False
    if not hasattr(db,'_binary_origin_keys'):
        present = db.one("SELECT to_regclass('public.viewer_origin_key_layout') IS NOT NULL AS present")
        row = db.one('SELECT layout FROM public.viewer_origin_key_layout WHERE id=1') if present and present['present'] else None
        db._binary_origin_keys = bool(row and row['layout']==LAYOUT)
    return db._binary_origin_keys


def parameter_equal(db, column):
    return key_sql(column)+'='+key_sql('?') if active(db) else column+'=?'


def origin_list(db, count, column='origin_key'):
    if not 1 <= count <= 4096:
        raise ValueError('invalid_origin_list_size')
    return (key_sql(column)+' IN ('+','.join(key_sql('?') for _ in range(count))+')'
        if active(db) else column+' IN ('+','.join('?' for _ in range(count))+')')



def origin_lookup_sql(db, table, columns, origins):
    """One indexed parameterized probe per origin, including cold index stats.

    A large IN list on an unanalyzed expression can be estimated as matching
    the whole history. OFFSET 0 fences the lateral subquery: the origin list
    cannot be flattened into another whole-table scan. No version is limited.
    """
    allowed={'viewer_events':('origin_key','version_key','request_key'),
        'viewer_raw_events':('origin_key','version_key','payload')}
    if table not in allowed or tuple(columns)!=allowed[table] or not 1<=len(origins)<=4096:
        raise ValueError('invalid_origin_lookup')
    if not active(db):
        return ('SELECT '+','.join(columns)+' FROM '+table+' WHERE '+origin_list(db,len(origins)),tuple(origins))
    return ('SELECT found.* FROM unnest(CAST(? AS text[])) AS wanted(origin_key) CROSS JOIN LATERAL ('+
        'SELECT '+','.join('source.'+c for c in columns)+' FROM public.'+table+' source WHERE '+
        key_sql('source.origin_key')+'='+key_sql('wanted.origin_key')+' OFFSET 0) found',(list(origins),))


def lookup_origins(db, table, origins):
    columns=('origin_key','version_key','request_key' if table=='viewer_events' else 'payload')
    statement,params=origin_lookup_sql(db,table,columns,origins)
    return db.all(statement,params)


def raw_conflict(db):
    if active(db):
        return ' ON CONFLICT (('+key_sql('origin_key')+'),('+key_sql('version_key')+')) DO NOTHING'
    return ' ON CONFLICT(origin_key,version_key) DO NOTHING'


@contextmanager
def _locked(db):
    with _autocommit(db):
        locked = db.one('SELECT pg_try_advisory_lock(240026,1) AS locked')['locked']
        if not locked:
            raise ValueError('origin_storage_worker_must_be_stopped')
        try:
            db.sql('SELECT pg_advisory_lock(240026,2)')
            try:yield
            finally:db.sql('SELECT pg_advisory_unlock(240026,2)')
        finally:db.sql('SELECT pg_advisory_unlock(240026,1)')


def _index(db, name, table, *, binary):
    row = db.one('''SELECT i.indisvalid,i.indisready,i.indisunique,
        i.indrelid=CAST(? AS regclass) AS correct_table,
        i.indpred IS NULL AND i.indnkeyatts=2 AND i.indnatts=2 AS unfiltered,
        pg_get_expr(i.indexprs,i.indrelid) AS expression,
        ARRAY(SELECT a.attname FROM unnest(i.indkey) WITH ORDINALITY k(attnum,n)
          JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum ORDER BY k.n) AS columns
        FROM pg_index i WHERE i.indexrelid=to_regclass(?)''',(table,'public.'+name))
    if row:
        expression=re.sub(r'\s+','',(row['expression'] or '').replace('public.',''))
        expected='viewer_hmac_bytes_v1(origin_key),viewer_hmac_bytes_v1(version_key)' if binary else ''
        if (not row['correct_table'] or not row['unfiltered'] or not row['indisunique']
                or expression!=expected or (not binary and row['columns']!=['origin_key','version_key'])):
            raise ValueError('origin_index_definition_mismatch')
    return row


def _primary(db, table):
    row = db.one('''SELECT c.conname,ARRAY(SELECT a.attname FROM unnest(c.conkey)
        WITH ORDINALITY k(attnum,n) JOIN pg_attribute a ON a.attrelid=c.conrelid
        AND a.attnum=k.attnum ORDER BY k.n) AS columns FROM pg_constraint c
        WHERE c.conrelid=CAST(? AS regclass) AND c.contype='p' ''',(table,))
    if row and (row['conname']!=table+'_pkey' or row['columns']!=['origin_key','version_key']):
        raise ValueError('origin_primary_definition_mismatch')
    return row


def _redundant(db):
    row = db.one('''SELECT i.indisunique,i.indexprs IS NULL AND i.indpred IS NULL
        AND i.indnkeyatts=2 AND i.indnatts=2 AS ordinary,
        i.indrelid='public.viewer_events'::regclass AS correct_table,
        ARRAY(SELECT a.attname FROM unnest(i.indkey) WITH ORDINALITY k(attnum,n)
          JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum ORDER BY k.n) AS columns
        FROM pg_index i WHERE i.indexrelid=to_regclass('public.vei_origin_request')''')
    if row and (row['indisunique'] or not row['ordinary'] or not row['correct_table']
                or row['columns']!=['origin_key','request_key']):
        raise ValueError('origin_redundant_index_definition_mismatch')
    return row


def ensure(db):
    if db.sqlite:return
    with _locked(db):
        function=db.one('''SELECT p.prosrc,p.provolatile,p.proparallel,p.proisstrict,p.proconfig,
            p.prorettype='bytea'::regtype AS returns_bytea FROM pg_proc p
            WHERE p.oid=to_regprocedure('public.viewer_hmac_bytes_v1(text)')''')
        if function:
            if (function['prosrc'].strip()!=BODY.strip() or function['provolatile']!='i'
                    or function['proparallel']!='s' or not function['proisstrict']
                    or not function['returns_bytea'] or function['proconfig']!=['search_path=pg_catalog']):
                raise ValueError('origin_function_definition_mismatch')
        else:
            db.sql('CREATE FUNCTION '+FUNCTION+'(key_text text) RETURNS bytea LANGUAGE SQL '
                'IMMUTABLE STRICT PARALLEL SAFE SET search_path=pg_catalog AS $origin$'+BODY+'$origin$')
        nondeterministic=db.one('''SELECT EXISTS(SELECT 1 FROM pg_attribute a
            JOIN pg_collation c ON c.oid=a.attcollation WHERE a.attrelid=ANY(ARRAY[
              'public.viewer_events'::regclass,'public.viewer_raw_events'::regclass])
            AND a.attname IN ('origin_key','version_key') AND NOT c.collisdeterministic) AS present''')
        if nondeterministic['present']:
            raise ValueError('origin_storage_requires_deterministic_collation')
        columns=db.one('''SELECT COUNT(*) AS n,BOOL_AND(a.atttypid='text'::regtype AND a.attnotnull) AS valid
            FROM pg_attribute a WHERE a.attrelid=ANY(ARRAY['public.viewer_events'::regclass,
              'public.viewer_raw_events'::regclass]) AND a.attname IN ('origin_key','version_key')
              AND a.attnum>0 AND NOT a.attisdropped''')
        if columns['n']!=4 or not columns['valid']:
            raise ValueError('origin_storage_requires_nonnull_text_keys')
        # Publish the capability table before concurrent builds so a reader
        # role initialized during maintenance can receive its normal SELECT
        # grant. The legacy marker keeps all reads/writes on original keys
        # until the atomic cutover below.
        db.sql('''CREATE TABLE IF NOT EXISTS public.viewer_origin_key_layout(
            id INTEGER PRIMARY KEY CHECK(id=1),layout TEXT NOT NULL)''')
        db.sql("INSERT INTO public.viewer_origin_key_layout VALUES(1,'legacy_origin_keys') ON CONFLICT(id) DO NOTHING")
        for name, table in INDEXES.items():
            status=_index(db,name,table,binary=True)
            if status and status['indisvalid'] and status['indisready']:continue
            if status:db.sql('DROP INDEX CONCURRENTLY public.'+name)
            db.progress('origin_index_build',table=table,index=name,concurrent=True)
            db.sql('CREATE UNIQUE INDEX CONCURRENTLY '+name+' ON public.'+table+
                '('+key_sql('origin_key')+','+key_sql('version_key')+')')
            db.progress('origin_index_ready',table=table,index=name)
        from .viewer_storage_keys import ensure_expression_statistics
        ensure_expression_statistics(db,INDEXES)
        redundant=_redundant(db)
        with db.conn.transaction():
            db.sql('SET LOCAL lock_timeout=1000')
            for table in INDEXES.values():
                primary=_primary(db,table)
                if primary:db.sql('ALTER TABLE public.'+table+' DROP CONSTRAINT '+table+'_pkey')
                db.sql('ALTER TABLE public.'+table+' ALTER COLUMN origin_key SET NOT NULL, ALTER COLUMN version_key SET NOT NULL')
            db.sql("INSERT INTO public.viewer_origin_key_layout VALUES(1,'"+LAYOUT+
                "') ON CONFLICT(id) DO UPDATE SET layout=excluded.layout WHERE viewer_origin_key_layout.layout IS DISTINCT FROM excluded.layout")
        db._binary_origin_keys=True
        if redundant:db.sql('DROP INDEX CONCURRENTLY public.vei_origin_request')
    db.progress('origin_layout_ready',layout=LAYOUT,evidence_deleted=False,columns_changed=False)


def restore_original_keys(db):
    """Explicit rollback before code downgrade. Never rewrites evidence rows."""
    if db.sqlite:return
    with _locked(db):
        for table in INDEXES.values():
            if _primary(db,table):continue
            name=table+'_origin_restore_v1'
            status=_index(db,name,table,binary=False)
            if status and not (status['indisvalid'] and status['indisready']):
                db.sql('DROP INDEX CONCURRENTLY public.'+name);status=None
            if not status:
                db.progress('origin_restore_index_build',table=table)
                db.sql('CREATE UNIQUE INDEX CONCURRENTLY '+name+' ON public.'+table+'(origin_key,version_key)')
        with db.conn.transaction():
            db.sql('SET LOCAL lock_timeout=1000')
            for table in INDEXES.values():
                if not _primary(db,table):
                    db.sql('ALTER TABLE public.'+table+' ADD CONSTRAINT '+table+
                        '_pkey PRIMARY KEY USING INDEX '+table+'_origin_restore_v1')
            marker=db.one("SELECT to_regclass('public.viewer_origin_key_layout') IS NOT NULL AS present")
            if marker['present']:db.sql("UPDATE public.viewer_origin_key_layout SET layout='legacy_origin_keys' WHERE id=1")
        db._binary_origin_keys=False
        if not _redundant(db):
            db.sql('CREATE INDEX CONCURRENTLY vei_origin_request ON public.viewer_events(origin_key,request_key)')
        for name in INDEXES:
            if _index(db,name,INDEXES[name],binary=True):db.sql('DROP INDEX CONCURRENTLY public.'+name)
    db.progress('origin_layout_restored',evidence_deleted=False)
