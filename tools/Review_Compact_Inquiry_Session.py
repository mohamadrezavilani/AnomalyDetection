"""Resolve one retained witness locally and recount one session, service and five-minute window."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re

from compact_behavior import FEATURES, FIVE, inquiry
from compact_behavior.extract import iso, materialize
from compact_behavior.store import Store
from compact_product.config import load
from compact_product.search import source_ids


def covered(features, service, axis, end):
    at = features.get('input_asof_ns')
    if (features.get('version') == FEATURES and features.get('service_key') == service
            and features.get('session_eligible') is True and features.get('service_rate_eligible') is True
            and features.get('input_feature_eligibility', {}).get('targets') is True
            and type(at) is int and at < end):
        token = (features.get(inquiry.POLICY) or {}).get(axis)
        if isinstance(token, str) and re.fullmatch('[0-9a-f]{64}', token):
            return token
    return None


def review(db, stream, witness, service, axis):
    s = db.schema
    if (not re.fullmatch('[0-9a-f]{64}', witness)
            or axis not in {k for k,_ in inquiry.ROUTES.get(service, ())}):
        raise ValueError('reviewed_service_and_field_required')
    with db.conn.transaction():
        db.conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        db.conn.execute("SET LOCAL statement_timeout='12s'")
        anchor = db.conn.execute(f"""SELECT b.session_id,b.observed_at_ns,b.features->>'service_key' AS service,
            p.state->'raw_session_ids' AS originals FROM {s}.behaviors b
            LEFT JOIN {s}.behavior_payloads p USING(behavior_id) WHERE b.stream_id=%s AND b.behavior_id=%s""",
            (stream,witness)).fetchone()
        if not anchor or not anchor['session_id'] or anchor['service'] != service or anchor['observed_at_ns'] is None:
            raise ValueError('witness_session_or_service_unavailable')
        start = anchor['observed_at_ns'] // FIVE * FIVE
        end = start + FIVE
        session = anchor['session_id']
        originals = set(source_ids({'ids':anchor['originals']}, session, 'ids'))
        # Cap the number of payload lookups; a named cursor holds one payload at a time.
        selected = db.conn.execute(f"""SELECT behavior_id FROM {s}.behaviors WHERE stream_id=%s
            AND session_id=%s AND observed_at_ns>=%s AND observed_at_ns<%s
            AND features->>'service_key'=%s ORDER BY observed_at_ns,behavior_id LIMIT 301""",
            (stream,session,start,end,service)).fetchall()
        complete = len(selected) <= 300
        stored, rebuilt, results, missing = Counter(), Counter(), Counter(), Counter()
        ids = [r['behavior_id'] for r in selected[:300]]
        with db.conn.cursor(name='read_session_inputs') as cur:
            cur.itersize = 1
            cur.execute(f"""SELECT b.behavior_id,b.features,b.result_code,p.state FROM {s}.behaviors b
                LEFT JOIN {s}.behavior_payloads p USING(behavior_id) WHERE b.stream_id=%s AND b.behavior_id=ANY(%s)""",
                (stream,ids))
            for row in cur:
                results[row['result_code'] or '<missing>'] += 1
                old = covered(row['features'], service, axis, end)
                if old:
                    stored[old] += 1
                state = row['state']
                if not state:
                    missing['no_retained_payload'] += 1
                    continue
                originals.update(source_ids(state,session,'raw_session_ids'))
                body = materialize(stream,state)
                if (not body or body['behavior_id'] != row['behavior_id'] or body['session_id'] != session
                        or body['service_key'] != service or body['observed_at_ns'] is None
                        or not start <= body['observed_at_ns'] < end):
                    missing['identity_or_binding_changed'] += 1
                    continue
                verified = covered(body['features'], service, axis, end)
                if verified and (not old or old == verified):
                    rebuilt[verified] += 1
                elif old and verified:
                    missing['projection_disagrees'] += 1
                else:
                    missing['no_eligible_input_at_window_end'] += 1

    def counts(counter):
        n = sum(counter.values())
        return dict(covered=n, distinct=len(counter) if n else None,
                    most_frequent_count=max(counter.values(), default=None),
                    distinct_is_exact=complete and n == len(ids) and n > 0)
    summary = dict(status='READ_ONLY_INQUIRY_SESSION_REVIEW', service=service, field=axis,
        from_utc=iso(start), until_utc=iso(end), requests_checked=len(ids), window_complete=complete,
        result_codes=dict(results), stored=counts(stored), retained_reconstruction=counts(rebuilt),
        unavailable=dict(missing), database_modified=False, source_contacted=False)
    kql = None
    if originals:
        terms = ' or '.join('Session: ' + json.dumps(x,ensure_ascii=False) for x in sorted(originals))
        kql = f'({terms}) and @timestamp >= "{iso(start)}" and @timestamp < "{iso(end)}"'
    return summary, kql


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project',type=Path,required=True)
    p.add_argument('--witness',required=True)
    p.add_argument('--service',required=True)
    p.add_argument('--axis',required=True)
    p.add_argument('--show-kql', action='store_true', help='Print source-spelled session filter on this terminal only')
    args = p.parse_args()
    cfg, source, stream = load(args.project)
    db = Store(source['DATABASE'],schema=cfg.source_schema,application='inquiry-session-review')
    try:
        result, kql = review(db,stream,args.witness,args.service,args.axis)
        print(json.dumps(result), flush=True)
        if args.show_kql:
            print(kql or 'SOURCE_SPELLING_UNAVAILABLE', flush=True)
    finally:
        db.close()


if __name__ == '__main__':
    main()
