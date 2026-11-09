"""One bounded, atomic upgrade of already captured correlation RequestIDs."""
from __future__ import annotations
from datetime import datetime, timezone
from .payment_correlation import EMITTERS


def sync_payment_correlations(db, since_ns, *, max_requests=50_000, fault=None):
    if type(since_ns) is not int or since_ns < 0 or type(max_requests) is not int or not 1 <= max_requests <= 50_000:
        raise ValueError('invalid_correlation_since')
    previous_callback = getattr(db, 'progress_callback', None)
    counts = dict(written=0, deleted=0)

    def progress(event):
        if event.get('stage') == 'projection_publish_complete':
            counts['written'] += event['written_rows']
            counts['deleted'] += event['deleted_rows']
        if previous_callback:
            previous_callback(event)

    db.progress_callback = progress
    try:
        db.write_lock()
        live = db.one('SELECT * FROM viewer_live_state WHERE id=1')
        semantic = db.semantic_checkpoint()
        if not semantic or semantic['state'] != 'ready':
            raise ValueError('existing_semantic_index_required')
        if live and live['keys_fingerprint'] != db.keys.fingerprint:
            raise ValueError('existing_keys_fingerprint_mismatch')
        emitters = sorted({x for values in EMITTERS.values() for x in values})
        condition = ' OR '.join('(callpath=? OR callpath LIKE ?)' for _ in emitters)
        args = [since_ns] + [value for caller in emitters for value in (caller, caller + ' Line:%')]
        rows = db.all('''SELECT DISTINCT request_key FROM viewer_events
            WHERE request_key IS NOT NULL AND at_ns>=? AND (''' + condition +
            ') ORDER BY request_key LIMIT ?', args + [max_requests + 1])
        if len(rows) > max_requests:
            raise ValueError('correlation_sync_scope_too_large')
        keys = [row['request_key'] for row in rows]
        before = dict(next_ns=live['next_ns'], generation=live['generation']) if live else None
        if not keys:
            db.conn.rollback()
            return dict(status='NO_CAPTURED_CANDIDATES', request_ids=0, checkpoint=before,
                        raw_written=False, roles_written=False, future_capture='normal_worker_indexes_new_messages')
        db.sql('CREATE TEMP TABLE IF NOT EXISTS viewer_projection_scope(request_key TEXT PRIMARY KEY)')
        db.sql('DELETE FROM viewer_projection_scope')
        db.many('INSERT INTO viewer_projection_scope VALUES (?)', [(key,) for key in keys])
        if not db.sqlite:
            db.sql('ANALYZE viewer_projection_scope')
        roles_before=db.all('SELECT * FROM viewer_service_roles ORDER BY service_path')
        result = db.rebuild_payment_contract(request_keys=keys, commit=False)
        # The contract now also carries dispatcher service/OTP context. Keep
        # its action and semantic anchor changes inside this same transaction.
        semantic_changes=db.reconcile_semantic_requests(keys,commit=False)['changed']
        roles_written=roles_before!=db.all('SELECT * FROM viewer_service_roles ORDER BY service_path')
        changed = bool(counts['written'] or counts['deleted'] or semantic_changes or roles_written)
        generation = max(semantic['generation'], live['generation'] if live else 0)
        if changed:
            generation += 1
            db.sql('UPDATE viewer_semantic_checkpoint SET generation=?,updated_at=? WHERE id=1',
                   (generation, datetime.now(timezone.utc).isoformat()))
            if live:
                db.sql('UPDATE viewer_live_state SET generation=? WHERE id=1', (generation,))
        if fault:
            fault('before_commit')
        if changed:
            db.conn.commit()
        else:
            db.conn.rollback()
        after = db.one('SELECT next_ns,generation FROM viewer_live_state WHERE id=1') if live else None
        if live and after['next_ns'] != before['next_ns']:
            raise RuntimeError('correlation_sync_cursor_changed')
        return dict(status='UPDATED' if changed else 'NO_CHANGE', request_ids=len(keys),
                    projection_rows_written=counts['written'], projection_rows_deleted=counts['deleted'],
                    checkpoint_before=before, checkpoint_after=after, generation=generation,
                    raw_written=False, roles_written=roles_written, behavior_anchors_written=bool(semantic_changes),
                    projection=result)
    except BaseException:
        db.conn.rollback()
        raise
    finally:
        db.progress_callback = previous_callback
