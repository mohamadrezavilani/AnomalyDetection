"""Compact PostgreSQL indexes for immutable, fully retained evidence keys.

The digest is an index accelerator, never the evidence identity returned to a
reader. Exact joins still compare every original component. A digest collision
rejects the write (or index build); it cannot merge two witnesses. Installation
builds replacement indexes concurrently before the short, atomic cutover.
"""
from __future__ import annotations

from contextlib import contextmanager
import re


FUNCTION = 'public.viewer_key_digest_v1'
BODY = """SELECT pg_catalog.sha256(pg_catalog.convert_to(
    COALESCE((SELECT pg_catalog.string_agg(
        CASE WHEN part IS NULL THEN '-:' ELSE pg_catalog.length(part)::text || ':' || part END,
        '' ORDER BY ordinal)
        FROM pg_catalog.unnest(parts) WITH ORDINALITY AS item(part, ordinal)), ''), 'UTF8'))"""
COLLISION_BODY = """BEGIN
    IF NOT same_identity THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='viewer_storage_key_collision';
    END IF;
    RETURN false;
END"""
KEYS = {
    'viewer_links': ('origin_key', 'version_key', 'link_domain', 'link_key'),
    'viewer_contract_identifiers': ('origin_key', 'version_key', 'issuer', 'kind',
                                    'scope', 'field_path', 'identity_key'),
    'viewer_contract_observations': ('origin_key', 'version_key', 'axis', 'value', 'field_path'),
}
INDEXES = {
    'vli_compact_key_v1': ('viewer_links', KEYS['viewer_links'], True),
    'vli_origin_version_v1': ('viewer_links', ('origin_key', 'version_key'), False),
    'vci_compact_key_v1': ('viewer_contract_identifiers', KEYS['viewer_contract_identifiers'], True),
    'vci_origin_version_v1': ('viewer_contract_identifiers', ('origin_key', 'version_key'), False),
    'vco_compact_key_v1': ('viewer_contract_observations', KEYS['viewer_contract_observations'], True),
    'vco_origin_version_v1': ('viewer_contract_observations', ('origin_key', 'version_key'), False),
}


def digest_sql(columns, alias=''):
    prefix = alias + '.' if alias else ''
    return FUNCTION + '(' + ','.join(prefix + c for c in columns) + ')'


def exact_origin_join(db, left, right):
    exact = left + '.origin_key=' + right + '.origin_key AND ' + left + '.version_key=' + right + '.version_key'
    if detect(db):
        return digest_sql(('origin_key', 'version_key'), left) + '=' + digest_sql(('origin_key', 'version_key'), right) + ' AND ' + exact
    return exact


def conflict_clause(db, table):
    """Idempotence on original components, with a fail-closed digest collision.

    Private build tables retain their original full unique keys. Only durable
    compact tables need the collision branch, evaluated on conflicts only.
    """
    if (db.sqlite or (getattr(db, '_projection_routes', None) or {}).get(table)
            or table not in KEYS or not detect(db)):
        return ' ON CONFLICT DO NOTHING'
    keys = KEYS[table]
    same = ' AND '.join(table + '.' + c + '=excluded.' + c for c in keys)
    return (' ON CONFLICT ((' + digest_sql(keys) + ')) DO UPDATE SET request_key=' + table +
            '.request_key WHERE public.viewer_reject_key_collision_v1(' + same + ')')


def detect(db):
    """Called after the read transaction has been configured, never in __init__."""
    if getattr(db, 'sqlite', False):
        db._compact_storage_keys = False
    elif not hasattr(db, '_compact_storage_keys'):
        row = db.one("SELECT to_regprocedure('public.viewer_key_digest_v1(text[])') IS NOT NULL AS present")
        db._compact_storage_keys = bool(row and row.get('present'))
    return db._compact_storage_keys


@contextmanager
def _autocommit(db):
    # init() owns this connection, outside a publication. Never end an unknown
    # transaction here: callers must finish their own initialization first.
    from psycopg.pq import TransactionStatus
    if db.conn.info.transaction_status != TransactionStatus.IDLE:
        raise RuntimeError('storage_upgrade_requires_idle_connection')
    previous = db.conn.autocommit
    db.conn.autocommit = True
    try:
        yield
    finally:
        db.conn.autocommit = previous



def ensure_expression_statistics(db, indexes):
    """Collect missing expression statistics once, before layout readiness.

    Concurrent CREATE INDEX doesn't populate expression pg_statistic rows.
    A full-table ANALYZE (without a column list) collects them. Empty tables
    need no scan; their normal future autoanalyze remains available.
    """
    tables=set()
    for name, definition in indexes.items():
        table=definition if isinstance(definition,str) else definition[0]
        row=db.one("""SELECT t.reltuples,
            (SELECT COUNT(*) FROM unnest(i.indkey) k(attnum) WHERE k.attnum=0) AS expressions,
            (SELECT COUNT(*) FROM pg_catalog.pg_statistic s
             WHERE s.starelid=i.indexrelid AND NOT s.stainherit) AS statistics
            FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class t ON t.oid=i.indrelid
            WHERE i.indexrelid=to_regclass(?) AND i.indisvalid AND i.indisready""",('public.'+name,))
        if row and row['reltuples']>0 and row['statistics']<row['expressions']:tables.add(table)
    for table in sorted(tables):
        db.progress('index_statistics',table=table,operation='ANALYZE')
        db.sql('ANALYZE public.'+table)
        db.progress('index_statistics_ready',table=table)


def ensure(db):
    if db.sqlite:
        return
    with _autocommit(db):
        # The existing singleton and all application writers use these same
        # advisory locks. A session lock survives the concurrent-index phases.
        db.sql('SELECT pg_advisory_lock(240026, 2)')
        try:
            _ensure(db)
        finally:
            db.sql('SELECT pg_advisory_unlock(240026, 2)')
    db._compact_storage_keys = True


def _ensure(db):
    function = db.one("""SELECT p.prosrc,p.provolatile,p.proparallel,p.proconfig,p.proisstrict,
        p.prorettype='bytea'::regtype AS returns_bytea
        FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('public.viewer_key_digest_v1(text[])')""")
    if function:
        if (function['prosrc'].strip() != BODY.strip() or function['provolatile'] != 'i'
                or function['proparallel'] != 's' or not function['returns_bytea'] or not function['proisstrict']
                or function['proconfig'] != ['search_path=pg_catalog']):
            raise ValueError('storage_digest_definition_mismatch')
    else:
        db.sql('CREATE FUNCTION ' + FUNCTION + '(VARIADIC parts text[]) RETURNS bytea '
               'LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE SET search_path=pg_catalog AS $body$' + BODY + '$body$')
    collision = db.one("SELECT prosrc FROM pg_catalog.pg_proc WHERE oid=to_regprocedure('public.viewer_reject_key_collision_v1(boolean)')")
    if collision:
        if collision['prosrc'].strip() != COLLISION_BODY.strip():
            raise ValueError('storage_digest_definition_mismatch')
    else:
        db.sql('CREATE FUNCTION public.viewer_reject_key_collision_v1(same_identity boolean) RETURNS boolean '
               'LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog AS $body$' + COLLISION_BODY + '$body$')
    nondeterministic = db.one('''SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a
        JOIN pg_catalog.pg_collation c ON c.oid=a.attcollation
        WHERE a.attrelid=ANY(ARRAY[CAST(? AS regclass),CAST(? AS regclass),CAST(? AS regclass)])
          AND a.attnum>0 AND NOT a.attisdropped AND NOT c.collisdeterministic) AS present''', tuple(KEYS))
    if nondeterministic['present']:
        raise ValueError('storage_requires_deterministic_collation')
    for name, (table, columns, unique) in INDEXES.items():
        row = db.one('''SELECT i.indisvalid,i.indisready,i.indisunique,
            i.indrelid=CAST(? AS regclass) AS correct_table,
            pg_get_expr(i.indexprs,i.indrelid) AS expression,
            i.indpred IS NULL AND i.indnkeyatts=1 AND i.indnatts=1 AS unfiltered
            FROM pg_catalog.pg_index i WHERE i.indexrelid=to_regclass(?)''', (table, 'public.' + name))
        if row:
            # pg_get_expr renders a VARIADIC call as an explicit text array.
            expression = re.sub(r'\s+', '', (row['expression'] or '').replace('public.', ''))
            expected = 'viewer_key_digest_v1(VARIADICARRAY[' + ','.join(columns) + '])'
            if (not row['correct_table'] or row['indisunique'] != unique or not row['unfiltered']
                    or expression != expected):
                raise ValueError('storage_index_definition_mismatch')
            if row['indisvalid'] and row['indisready']:
                continue
            # Only our exact, unfinished replacement is removable. The old PK
            # still protects the table when a concurrent build is interrupted.
            db.sql('DROP INDEX CONCURRENTLY public.' + name)
        db.progress('storage_index_build', table=table, index=name, concurrent=True)
        db.sql('CREATE ' + ('UNIQUE ' if unique else '') + 'INDEX CONCURRENTLY ' + name +
               ' ON public.' + table + ' (' + digest_sql(columns) + ')')
        db.progress('storage_index_ready', table=table, index=name)
    ensure_expression_statistics(db,INDEXES)
    # All replacement indexes are valid before acquiring table locks. A lock
    # timeout rolls back the complete cutover; a restart resumes at this point.
    with db.conn.transaction():
        db.sql('SET LOCAL lock_timeout=1000')
        for table, keys in KEYS.items():
            primary = db.one('''SELECT c.conname,ARRAY(SELECT a.attname FROM unnest(c.conkey)
                WITH ORDINALITY AS k(attnum,n) JOIN pg_catalog.pg_attribute a
                ON a.attrelid=c.conrelid AND a.attnum=k.attnum ORDER BY k.n) AS columns
                FROM pg_catalog.pg_constraint c WHERE c.conrelid=CAST(? AS regclass) AND c.contype='p' ''', (table,))
            if primary:
                if primary['conname'] != table + '_pkey' or tuple(primary['columns']) != keys:
                    raise ValueError('storage_primary_key_definition_mismatch')
                db.sql('ALTER TABLE public.' + table + ' DROP CONSTRAINT ' + table + '_pkey')
                # Keep the original non-null identity contract explicitly.
                for column in keys:
                    db.sql('ALTER TABLE public.' + table + ' ALTER COLUMN ' + column + ' SET NOT NULL')
        db.sql('''CREATE TABLE IF NOT EXISTS viewer_storage_layout(
            id INTEGER PRIMARY KEY CHECK(id=1),layout TEXT NOT NULL)''')
        db.sql("INSERT INTO viewer_storage_layout VALUES(1,'compact_evidence_keys_v1') ON CONFLICT(id) DO UPDATE SET layout=excluded.layout WHERE viewer_storage_layout.layout IS DISTINCT FROM excluded.layout")
    db.progress('storage_layout_ready', layout='compact_evidence_keys_v1', evidence_deleted=False)


def restore_original_keys(db):
    """Recreate original SQL conflict targets before a deliberate code downgrade.

    Evidence never moves. Keep compact indexes until the restored code is
    running; both sets can coexist safely during this explicit rollback.
    """
    if db.sqlite:
        return
    with _autocommit(db):
        db.sql('SELECT pg_advisory_lock(240026, 2)')
        try:
            for table, keys in KEYS.items():
                present = db.one("SELECT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=CAST(? AS regclass) AND contype='p') AS present", (table,))['present']
                if present:
                    continue
                name = table + '_restore_key_v1'
                status = db.one('''SELECT i.indisvalid,i.indisunique,
                    i.indrelid=CAST(? AS regclass) AND i.indexprs IS NULL AND i.indpred IS NULL
                      AND i.indnatts=i.indnkeyatts AS correct_table,
                    ARRAY(SELECT a.attname FROM unnest(i.indkey) WITH ORDINALITY AS k(attnum,n)
                      JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum ORDER BY k.n) AS columns
                    FROM pg_index i WHERE i.indexrelid=to_regclass(?)''', (table, 'public.' + name))
                if status and (not status['correct_table'] or not status['indisunique'] or tuple(status['columns']) != keys):
                    raise ValueError('storage_index_definition_mismatch')
                if status and not status['indisvalid']:
                    db.sql('DROP INDEX CONCURRENTLY public.' + name)
                    status = None
                if not status:
                    db.progress('storage_restore_index_build', table=table)
                    db.sql('CREATE UNIQUE INDEX CONCURRENTLY ' + name + ' ON public.' + table + '(' + ','.join(keys) + ')')
            with db.conn.transaction():
                db.sql('SET LOCAL lock_timeout=1000')
                for table in KEYS:
                    present = db.one("SELECT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=CAST(? AS regclass) AND contype='p') AS present", (table,))['present']
                    if not present:
                        db.sql('ALTER TABLE public.' + table + ' ADD CONSTRAINT ' + table +
                               '_pkey PRIMARY KEY USING INDEX ' + table + '_restore_key_v1')
                db.sql("UPDATE viewer_storage_layout SET layout='legacy_plus_compact_keys_v1' WHERE id=1")
        finally:
            db.sql('SELECT pg_advisory_unlock(240026, 2)')
