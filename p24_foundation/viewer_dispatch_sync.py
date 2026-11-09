"""Atomic, bounded repair of captured dispatcher requests; no capture or seek."""
import hashlib
import json
from datetime import datetime,timezone


def _hash_rows(rows):
    values=sorted(json.dumps(r,sort_keys=True,default=lambda b:bytes(b).hex()) for r in rows)
    return hashlib.sha256(json.dumps(values).encode()).hexdigest()


def repair_captured_dispatches(db,request_keys,*,fault=None):
    keys=sorted(set(request_keys))
    if not keys or len(keys)>32 or any(len(k)!=64 for k in keys):raise ValueError('invalid_bounded_dispatch_scope')
    marks=','.join('?' for _ in keys)
    original_roles=set()
    def protected():
        return dict(events=_hash_rows(db.all('SELECT * FROM viewer_events WHERE request_key IN ('+marks+')',keys)),
            raw=_hash_rows(db.all('''SELECT b.* FROM viewer_raw_events b JOIN viewer_events e
                ON e.origin_key=b.origin_key AND e.version_key=b.version_key WHERE e.request_key IN ('''+marks+')',keys)),
            links=_hash_rows(db.all('SELECT * FROM viewer_links WHERE request_key IN ('+marks+')',keys)),
            existing_roles=_hash_rows([r for r in db.all('SELECT * FROM viewer_service_roles') if r['service_path'] in original_roles]),
            role_history=_hash_rows(db.all('SELECT * FROM viewer_service_role_history')))
    def projection():
        return {t:_hash_rows(db.all('SELECT * FROM '+t+' WHERE '+col+' IN ('+marks+')',keys)) for t,col in
            (('viewer_requests','request_key'),('viewer_actions','action_key'),('viewer_action_history','action_key'),
             ('viewer_contract_identifiers','request_key'),('viewer_contract_observations','request_key'),
             ('viewer_contract_edges','request_key'),('viewer_semantic_occurrences','request_key'))}
    try:
        db.write_lock()
        original_roles.update(r['service_path'] for r in db.all('SELECT * FROM viewer_service_roles')
            if not (r['role']=='unknown' and not r['reviewed'] and r['source']=='unclassified'))
        live=db.one('SELECT * FROM viewer_live_state WHERE id=1')
        semantic=db.semantic_checkpoint()
        if not semantic or semantic['state']!='ready':raise ValueError('existing_ready_semantic_index_required')
        if live and live['keys_fingerprint']!=db.keys.fingerprint:raise ValueError('existing_keys_fingerprint_mismatch')
        existing=db.all('SELECT request_key FROM viewer_requests WHERE request_key IN ('+marks+')',keys)
        if len(existing)!=len(keys):raise ValueError('requested_dispatches_not_all_captured')
        safe=protected();before=projection();before_live=dict(next_ns=live['next_ns'],generation=live['generation']) if live else None
        db.rebuild(request_keys=keys,commit=False)
        db.rebuild_payment_contract(request_keys=keys,commit=False)
        db.reconcile_semantic_requests(keys,commit=False)
        if protected()!=safe:raise RuntimeError('dispatch_repair_preservation_failed')
        if live and db.one('SELECT next_ns FROM viewer_live_state WHERE id=1')['next_ns']!=live['next_ns']:
            raise RuntimeError('dispatch_repair_moved_cursor')
        changed=projection()!=before
        if changed:
            generation=max(live['generation'] if live else 0,db.semantic_checkpoint()['generation'])+1
            db.sql('UPDATE viewer_semantic_checkpoint SET generation=?,updated_at=? WHERE id=1',
                   (generation,datetime.now(timezone.utc).isoformat()))
            if live:db.sql('UPDATE viewer_live_state SET generation=? WHERE id=1',(generation,))
        if fault:fault('before_commit')
        if changed:db.conn.commit()
        else:db.conn.rollback()
        return dict(status='UPDATED' if changed else 'NO_CHANGE',request_ids=len(keys),
            checkpoint_before=before_live,
            checkpoint_after=db.one('SELECT next_ns,generation FROM viewer_live_state WHERE id=1') if live else None,
            raw_events_links_and_manual_roles_preserved=True,checkpoint_advanced=False,
            captures_started=False,other_requests_rebuilt=False)
    except BaseException:
        db.conn.rollback();raise
