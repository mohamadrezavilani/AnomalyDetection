"""Finalize scoped derived rows before touching durable, indexed read models.

Raw events, capture receipts, version checks and the publisher transaction are
unchanged. Work tables are connection-local; only their final differences are
written to the existing permanent relations. No relation is replaced or renamed.
"""
from __future__ import annotations

from contextlib import contextmanager
import re
import time


REQUEST_TABLES = ('viewer_requests', 'viewer_actions', 'viewer_action_history')
CONTRACT_TABLES = ('viewer_contract_identifiers', 'viewer_contract_observations',
                   'viewer_contract_edges')
INDEXED_SCOPE_MAX_KEYS = 32_768
INDEXED_SCOPE_MIN_ROWS_PER_KEY = 20
# The other models can have multiple durable rows for each affected request.
INDEXED_SCOPE_TABLES = ('viewer_requests', 'viewer_actions')
TABLE_KEYS = {
    'viewer_requests': (('request_key',), 'request_key'),
    'viewer_actions': (('action_key',), 'action_key'),
    'viewer_action_history': (('action_key', 'origin_key', 'version_key', 'status'), 'action_key'),
    'viewer_contract_identifiers': (('origin_key', 'version_key', 'issuer', 'kind',
                                     'scope', 'field_path', 'identity_key'), 'request_key'),
    'viewer_contract_observations': (('origin_key', 'version_key', 'axis', 'value',
                                      'field_path'), 'request_key'),
    'viewer_contract_edges': (('edge_key',), 'request_key'),
}
# Match SQL identifiers, leaving quoted string literals untouched. Existing
# read-model statements use unquoted identifiers; customer values are bound.
_SQL_TOKEN = re.compile(r"'(?:''|[^'])*'|\b(?:" + '|'.join(TABLE_KEYS) + r')\b')


def route_projection_statement(statement, routes):
    if not routes:
        return statement
    return _SQL_TOKEN.sub(lambda match: routes.get(match.group(0), match.group(0)), statement)


class ProjectionWritesMixin:
    @contextmanager
    def finalized_projection(self, tables, *, use_indexed_scope=False):
        """Build affected rows locally and synchronize under the caller's lock.

        This context never commits. It restores routing even on cancellation;
        the publication caller rolls back evidence and projections together.
        """
        if getattr(self, '_projection_routes', None):
            raise RuntimeError('nested_projection_writer')
        routes = {}
        columns = {}
        for table in tables:
            if table not in TABLE_KEYS:
                raise ValueError('invalid_projection_table')
            stage = 'viewer_build_' + table.removeprefix('viewer_')
            if self.sqlite:
                schema = self.one("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,))['sql']
                ddl = re.sub(r'^CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?' + table + r'\b',
                             'CREATE TEMP TABLE ' + stage, schema, count=1, flags=re.I)
                self.sql('DROP TABLE IF EXISTS temp.' + stage)
                self.sql(ddl)
            else:
                self.sql('CREATE TEMP TABLE IF NOT EXISTS ' + stage + ' (LIKE ' + table +
                         ' INCLUDING DEFAULTS) ON COMMIT DROP')
                # The durable table retains every index. Private work tables
                # need only the same unique/not-null key, not UI indexes that
                # would be maintained again for every intermediate UPDATE.
                self.sql('CREATE UNIQUE INDEX IF NOT EXISTS ' + stage + '_key ON ' +
                         stage + ' (' + ','.join(TABLE_KEYS[table][0]) + ')')
                self.sql('TRUNCATE TABLE ' + stage)
            cursor = self.sql('SELECT * FROM ' + stage + ' LIMIT 0')
            columns[table] = [item[0] for item in cursor.description]
            routes[table] = stage
        self._projection_routes = routes
        try:
            yield
        finally:
            # Do not redirect the durable merge, or any subsequent reader.
            self._projection_routes = None
        scope_size = None
        if not self.sqlite:
            for stage in routes.values():
                self.sql('ANALYZE ' + stage)
            if use_indexed_scope:
                scope_size = self.one('SELECT COUNT(*) AS n FROM viewer_projection_scope')['n']
        for table in tables:
            self._publish_finalized_projection(table, routes[table], columns[table], scope_size=scope_size)

    def _publish_finalized_projection(self, table, stage, columns, *, scope_size=None):
        keys, scope_column = TABLE_KEYS[table]
        began = time.monotonic()
        self.progress('projection_publish', table=table)
        match = ' AND '.join('s.' + key + '=d.' + key for key in keys)
        scope_test = ' IN (SELECT request_key FROM viewer_projection_scope)'
        strategy = 'subquery'
        if (not self.sqlite and table in INDEXED_SCOPE_TABLES
                and scope_size and scope_size <= INDEXED_SCOPE_MAX_KEYS):
            estimate = self.one(
                'SELECT reltuples AS rows FROM pg_catalog.pg_class WHERE oid=CAST(? AS regclass)', (table,))
            if estimate and estimate['rows'] >= scope_size * INDEXED_SCOPE_MIN_ROWS_PER_KEY:
                # The initplan array exposes a scalar-array index condition on
                # the existing scope column. A semijoin can scan all history
                # even when this publication touches a small fraction of it.
                scope_test = ' = ANY (ARRAY(SELECT request_key FROM viewer_projection_scope))'
                strategy = 'array'
        removed = self.sql('DELETE FROM ' + table + ' AS d WHERE d.' + scope_column +
            scope_test + ' AND NOT EXISTS '
            '(SELECT 1 FROM ' + stage + ' s WHERE ' + match + ')').rowcount
        delete_seconds = time.monotonic() - began
        updates = [name for name in columns if name not in keys]
        changed = ' OR '.join('target.' + name + ' IS DISTINCT FROM excluded.' + name for name in updates)
        conflict = (' DO UPDATE SET ' + ','.join(name + '=excluded.' + name for name in updates) +
                    ' WHERE ' + changed) if updates else ' DO NOTHING'
        written = self.sql('INSERT INTO ' + table + ' AS target (' + ','.join(columns) +
            ') SELECT ' + ','.join(columns) + ' FROM ' + stage + ' WHERE 1=1 ORDER BY ' +
            ','.join(keys) + ' ON CONFLICT (' + ','.join(keys) + ')' + conflict).rowcount
        self.progress('projection_publish_complete', table=table, deleted_rows=removed,
                      written_rows=written, seconds=round(time.monotonic() - began, 3),
                      delete_seconds=round(delete_seconds, 3), delete_scope_strategy=strategy)
