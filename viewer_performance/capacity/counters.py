"""PostgreSQL 18 backend counters, never cluster counters labelled as writer I/O."""
from __future__ import annotations

from decimal import Decimal


IDENTITY = """SELECT pid,backend_start,datname FROM pg_stat_activity
    WHERE pid=pg_backend_pid()"""


def snapshot(raw):
    identity = dict(raw.execute(IDENTITY).fetchone())
    io = [dict(row) for row in raw.execute('SELECT * FROM pg_stat_get_backend_io(pg_backend_pid())').fetchall()]
    wal = dict(raw.execute('SELECT * FROM pg_stat_get_backend_wal(pg_backend_pid())').fetchone())
    return dict(identity=identity, io=io, wal=wal,
        scope='one_backend', statistics_may_lag_until_backend_flush=True)


def delta(before, after):
    if before['identity'] != after['identity']:
        return dict(status='BACKEND_CHANGED')
    def difference(a, b):
        if a.get('stats_reset') != b.get('stats_reset'):
            return dict(status='COUNTERS_RESET')
        values={k: b[k]-v for k,v in a.items()
            if isinstance(v, (int,float,Decimal)) and not isinstance(v,bool)
            and isinstance(b.get(k), (int,float,Decimal))}
        if any(v < 0 for v in values.values()):
            return dict(status='COUNTERS_REGRESSED')
        values={k:(int(v) if v==v.to_integral_value() else float(v))
            if isinstance(v,Decimal) else v for k,v in values.items()}
        return dict(status='DELTA',values=values)
    old={(r['object'],r['context']):r for r in before['io']}
    io=[]
    for row in after['io']:
        key=(row['object'],row['context'])
        io.append(dict(object=key[0],context=key[1],
            **(difference(old[key],row) if key in old else dict(status='COUNTERS_UNAVAILABLE'))))
    return dict(status='OBSERVED_BACKEND_DELTA',io=io,wal=difference(before['wal'],after['wal']),
        scope='one_backend', includes_background_writer_or_other_sessions=False,
        pg_reads_can_be_served_from_os_cache=True,statistics_may_lag=True,
        exact_window_attribution=False,
        limitation='Asynchronous flush can include earlier activity of the same backend; use own transaction counters for exact transaction scope.')


def transaction(raw):
    """Own current-transaction mutations, including work tables, before commit.

    Block fetch/hit functions describe logical buffer accesses and kernel read
    requests, not distinct pages or physical device reads.
    """
    rows=[dict(row) for row in raw.execute("""SELECT relname,n_tup_ins,n_tup_upd,n_tup_del
        FROM pg_stat_xact_user_tables WHERE relname LIKE 'viewer_%' ORDER BY relname""").fetchall()]
    blocks=[dict(row) for row in raw.execute("""SELECT c.relname,c.relkind,
        pg_stat_get_xact_blocks_fetched(c.oid) AS buffer_fetches,
        pg_stat_get_xact_blocks_hit(c.oid) AS buffer_hits
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE c.relname LIKE 'viewer_%' AND c.relkind IN ('r','i','t')
          AND (n.nspname='public' OR n.oid=pg_my_temp_schema()) ORDER BY c.relname""").fetchall()]
    return dict(scope='writer_current_transaction_before_commit',row_mutations=rows,blocks=blocks,
        mutations_are_not_unique_evidence_or_logical_requests=True,
        blocks_are_not_unique_working_set_pages=True)
