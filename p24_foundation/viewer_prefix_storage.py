"""One ordered prefix key replaces independent identity/origin hash indexes.

All original identity columns remain authoritative. A digest collision can
reject a publication, never merge witnesses. Existing exact origin predicates
use the leading expression of the new unique index without query rewrites.
"""
from __future__ import annotations

import re
from . import viewer_storage_keys as legacy

LAYOUT='prefix_evidence_keys_v2'
FUNCTION='public.viewer_origin_prefix_v2'
BODY='SELECT pg_catalog.substring(public.viewer_key_digest_v1(origin_text,version_text),1,16)'
INDEXES={
    'vli_prefix_key_v2':'viewer_links',
    'vci_prefix_key_v2':'viewer_contract_identifiers',
    'vco_prefix_key_v2':'viewer_contract_observations',
}


def expressions(table):
    keys=legacy.KEYS[table]
    return origin_sql(),legacy.digest_sql(keys[2:])


def origin_sql(alias=''):
    head=alias+'.' if alias else ''
    return FUNCTION+'('+head+'origin_key,'+head+'version_key)'


def ordered_key_sql(table):
    # Rows sharing an origin fit adjacent leaves. Sorting the suffix again
    # adds a second per-row digest evaluation without helping global locality.
    return expressions(table)[0]
def conflict_target(table):return '('+','.join('('+part+')' for part in expressions(table))+')'


def active(db):
    if db.sqlite:return False
    if not hasattr(db,'_prefix_evidence_keys'):
        present=db.one("SELECT to_regclass('public.viewer_storage_layout') IS NOT NULL AS present")
        row=db.one('SELECT layout FROM public.viewer_storage_layout WHERE id=1') if present['present'] else None
        db._prefix_evidence_keys=bool(row and row['layout']==LAYOUT)
    return db._prefix_evidence_keys


def index_status(db,name,table,columns,*,unique):
    row=db.one('''SELECT i.indisvalid,i.indisready,i.indisunique,
        i.indrelid=CAST(? AS regclass) AS correct_table,
        pg_get_expr(i.indexprs,i.indrelid) AS expression,
        i.indpred IS NULL AND i.indnatts=i.indnkeyatts AS unfiltered,
        i.indnkeyatts,am.amname FROM pg_index i
        JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_am am ON am.oid=c.relam
        WHERE i.indexrelid=to_regclass(?)''',(table,'public.'+name))
    if row:
        normalized=re.sub(r'\s+','',(row['expression'] or '').replace('public.',''))
        expected=','.join('viewer_origin_prefix_v2('+','.join(group)+')' if len(columns)==2 and n==0
            else 'viewer_key_digest_v1(VARIADICARRAY['+','.join(group)+'])' for n,group in enumerate(columns))
        if (not row['correct_table'] or not row['unfiltered'] or row['indisunique']!=unique
                or row['indnkeyatts']!=len(columns) or normalized!=expected or row['amname']!='btree'):
            raise ValueError('prefix_index_definition_mismatch')
    return row


def ensure_function(db):
    function=db.one('''SELECT p.prosrc,p.provolatile,p.proparallel,p.proisstrict,p.proconfig,p.proretset,
        p.prorettype='bytea'::regtype AS returns_bytea FROM pg_proc p
        WHERE p.oid=to_regprocedure('public.viewer_origin_prefix_v2(text,text)')''')
    if function:
        if (function['prosrc'].strip()!=BODY or function['provolatile']!='i' or function['proparallel']!='s'
                or not function['proisstrict'] or function['proconfig'] is not None or function['proretset']
                or not function['returns_bytea']):raise ValueError('prefix_function_definition_mismatch')
    else:
        # Every function in this inlinable body is explicitly schema-qualified.
        # The 128-bit prefix is an accelerator, never the witness identity.
        db.sql('CREATE FUNCTION '+FUNCTION+'(origin_text text,version_text text) RETURNS bytea '
            'LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE AS $prefix$'+BODY+'$prefix$')


def _ensure(db):
    ensure_function(db)
    for name,table in INDEXES.items():
        keys=legacy.KEYS[table]
        status=index_status(db,name,table,(keys[:2],keys[2:]),unique=True)
        if status and status['indisvalid'] and status['indisready']:continue
        if status:db.sql('DROP INDEX CONCURRENTLY public.'+name)
        db.progress('prefix_index_build',table=table,index=name,concurrent=True)
        db.sql('CREATE UNIQUE INDEX CONCURRENTLY '+name+' ON public.'+table+' ('+','.join(expressions(table))+')')
        db.progress('prefix_index_ready',table=table,index=name)
    legacy.ensure_expression_statistics(db,INDEXES)
    # Both old indexes protect all rows until every replacement is valid.
    with db.conn.transaction():
        db.sql('SET LOCAL lock_timeout=1000')
        db.sql("UPDATE public.viewer_storage_layout SET layout=? WHERE id=1 AND layout IS DISTINCT FROM ?",(LAYOUT,LAYOUT))
    db._prefix_evidence_keys=True
    for name,(table,columns,unique) in legacy.INDEXES.items():
        status=index_status(db,name,table,(columns,),unique=unique)
        if status:
            db.progress('prefix_old_index_remove',table=table,index=name)
            db.sql('DROP INDEX CONCURRENTLY public.'+name)
    db.progress('prefix_layout_ready',layout=LAYOUT,evidence_deleted=False,columns_changed=False)


def ensure(db):
    if db.sqlite:return
    with legacy._autocommit(db):
        db.sql('SELECT pg_advisory_lock(240026,2)')
        try:
            # Validate the same functions, collations and collision policy as
            # R3.5. This also adopts a legacy installation before its cutover.
            legacy._ensure(db)
            if not active(db):_ensure(db)
        finally:db.sql('SELECT pg_advisory_unlock(240026,2)')


def restore(db):
    if db.sqlite:return
    with legacy._autocommit(db):
        db.sql('SELECT pg_advisory_lock(240026,2)')
        try:
            legacy._ensure(db,allow_prefix=False)
            db._prefix_evidence_keys=False
            for name,table in INDEXES.items():
                keys=legacy.KEYS[table]
                if index_status(db,name,table,(keys[:2],keys[2:]),unique=True):
                    db.sql('DROP INDEX CONCURRENTLY public.'+name)
        finally:db.sql('SELECT pg_advisory_unlock(240026,2)')
    db.progress('prefix_layout_restored',layout='compact_evidence_keys_v1',evidence_deleted=False)
