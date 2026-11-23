"""Recent event-time service observations on small, revision-fenced window counters."""
import time

from compact_behavior import FIVE, FEATURES
from compact_ad import MODEL

WINDOWS = 288
COUNTS = ('requests', 'public_success', 'public_error', 'unattributed_success', 'cache', 'success', 'error', 'uncertain')
TIMES = ('last_cache', 'last_success', 'last_error', 'last_uncertain')


def report(db, cfg, stream, *, now_ns=None):
    end = (now_ns if now_ns is not None else time.time_ns()) // FIVE * FIVE
    begin = end - WINDOWS * FIVE
    base = dict(from_ns=begin, end_ns=end, expected=WINDOWS, covered=0,
                **dict.fromkeys(COUNTS, 0), **dict.fromkeys(TIMES, None))
    a, s = cfg.ad_schema, cfg.source_schema
    # The web process can start before the AD process upgrades this nullable column.
    installed = db.execute("""SELECT EXISTS(SELECT 1 FROM pg_attribute
        WHERE attrelid=to_regclass(%s) AND attname='postal_health' AND NOT attisdropped) AS ok""",
        (a + '.window_results',)).fetchone()['ok']
    if not installed:
        return dict(base, state='WARMING_UP')
    rows = db.execute(f"""SELECT r.postal_health FROM {a}.window_results r
        JOIN {s}.windows w USING(stream_id,start_ns)
        WHERE r.stream_id=%s AND r.start_ns >= %s AND r.start_ns < %s
        AND r.postal_health IS NOT NULL AND r.source_published_ns=w.published_at_ns
        AND r.timing_confirmed_revision=r.revision AND r.feature_version=%s AND r.model_version=%s
        AND NOT EXISTS(SELECT 1 FROM {s}.dirty_windows d WHERE d.stream_id=r.stream_id
            AND d.start_ns=r.start_ns AND d.session_id='@all' AND d.processed_version<d.version)
        AND NOT EXISTS(SELECT 1 FROM {a}.reanalysis j WHERE j.stream_id=r.stream_id
            AND j.start_ns=r.start_ns AND j.processed_version<j.version)
        ORDER BY r.start_ns DESC LIMIT %s""", (stream, begin, end, FEATURES, MODEL, WINDOWS)).fetchall()
    for row in rows:
        window = row['postal_health']
        base['covered'] += 1
        for key in COUNTS:
            base[key] += window.get(key, 0)
        for key in TIMES:
            if window.get(key) is not None:
                base[key] = max(base[key] or 0, window[key])
    return dict(base, state=evidence_state(base))


def evidence_state(value):
    events = {k: value['last_' + k] for k in ('success', 'error', 'uncertain')
              if value['last_' + k] is not None}
    if events:
        most_recent = max(events.values())
        latest = [k for k, at in events.items() if at == most_recent]
        return latest[0].upper() if len(latest) == 1 else 'MIXED'
    if value['cache']:
        return 'CACHE_OBSERVED'
    if not value['covered']:
        return 'WARMING_UP'
    return 'NO_DIRECT_EVIDENCE'
