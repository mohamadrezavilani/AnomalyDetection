"""Export the operator case list and bounded independent behavior evidence, read only."""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import time

from compact_behavior import FEATURES, FIVE, inquiry
from compact_behavior.store import Store
from compact_behavior.services import operation_role
from compact_product import case_selection, cases
from compact_product.config import load

# Result fields are an allowlist. No free-text feedback, source payload, literal
# target, raw session, request ID, network address or user-agent is exported.
METRICS = """
observed baseline threshold observed_is_lower_bound reason status reference_windows
reference_from_ns reference_cutoff_ns reference_policy reference_signature model_version
feature_version model_id numeric_path subject_policy measurement_unit baseline_family
validation_samples validation_log_mae calibration_rows calibration_windows training_rows
calibration_tail_rank single_signal_review_eligible rare_transition_fraction comparison
inquiry_pattern_policy covered_requests distinct_targets most_frequent_count repeated_requests successful_requests
peer_mean_requests peer_p95_requests same_hour_windows same_hour_actor_p95_median peer_count peer_max adjusted_tail_rank comparisons peer_basis active_days requests
rare_cross_services timing_services horizon_days period_start_ns period_end_ns duration_valid duration_missing behavior_stage
""".split()
COLUMNS = """behavior_id, observed_at_ns, session_id, api, kind, result_code,
    reported_duration, revision, quality, features->>'service_key' AS service,
    features->>'service_binding' AS binding, features->>'version' AS feature_version,
    features->'input_asof_ns' AS input_asof_ns,
    features->'input_feature_eligibility'->'targets' AS input_eligible,
    features->'session_eligible' AS session_eligible,
    features->'service_rate_eligible' AS rate_eligible,
    features->'rejected_attempt'->>'service' AS rejected_service,
    features->'rejected_attempt'->'eligible' AS rejection_eligible,
    features->'access_denied_attempt'->>'service' AS denied_service,
    features->'access_denied_attempt'->'verified' AS denial_verified,
    features->'""" + inquiry.POLICY + """' AS subjects"""


def label(secret, *parts):
    if any(p is None for p in parts):
        return None
    return hmac.new(secret, json.dumps(parts).encode(), hashlib.sha256).hexdigest()[:24]


def evidence(row, secret):
    at = row['observed_at_ns']
    end = (at // FIVE + 1) * FIVE if at is not None else None
    role = operation_role(row['api'], row['service'], row['binding'])
    in_actor = bool(role in ('business', 'user_management') and row['kind'] != 'automatic_support'
                    and row['feature_version'] == FEATURES and row['rate_eligible']
                    and row['session_eligible'] and row['session_id'])
    eligible = (in_actor and row['service'] in inquiry.ROUTES and row['input_eligible'] is True
                and type(row['input_asof_ns']) is int and end is not None and row['input_asof_ns'] < end)
    targets = {k: label(secret, row['service'], k, v) for k, v in (row['subjects'] or {}).items()
               if eligible and isinstance(v, str)}
    return dict(at_ns=at, revision=row['revision'], session=label(secret, 'session', row['session_id']),
                api=row['api'], service=row['service'], binding=row['binding'], role=role,
                result_code=row['result_code'], duration_ms=row['reported_duration'], quality=row['quality'],
                rejected_service=(row['rejected_service'] if row['rejection_eligible'] and row['result_code']=='GR0004'
                                  else row['denied_service'] if row['denial_verified'] and row['result_code']=='G00010' else None),
                actor_eligible=in_actor, inquiry_targets=targets)


def collect(conn, cfg, stream, date, days, *, budget_seconds=90):
    day, start, end = case_selection.bounds(date, days)
    selected, signal_count, truncated = case_selection.select(conn, cfg, stream, start, end)
    secret = secrets.token_bytes(32)
    clock_end = time.monotonic() + budget_seconds
    result = dict(date_tehran=day, days=days, start_ns=start, end_exclusive_ns=end,
                  policy=cases.POLICY, visible_cases=len(selected), eligible_signals=signal_count,
                  ui_candidate_limit_reached=truncated, cases=[], witnesses={}, session_windows=[])
    witness_groups = []
    contexts = []
    for case in selected:
        public = {k:case[k] for k in ('case_id','domain','services','methods','reasons','first_ns','last_ns')}
        public['session'] = label(secret, 'session', case['session_id'])
        public['findings'] = []
        grouped_ids = []
        case_windows = []
        for row in case['findings']:
            r = row['result']
            ids = list(dict.fromkeys(r.get('evidence') or []))
            public['findings'].append(dict(finding_id=row['finding_id'], revision=row['revision'],
                window_start_ns=row['start_ns'], method=row['method'], service=row['service'],
                verdict=row['verdict'], metrics={k:r[k] for k in METRICS if k in r}, witness_ids=ids))
            grouped_ids.extend(ids)
            if case['session_id'] and row['method'] != 'long_target_enumeration':
                case_windows.append((case['session_id'], row['start_ns']))
        result['cases'].append(public)
        witness_groups.append(list(dict.fromkeys(grouped_ids)))
        contexts.append(list(dict.fromkeys(case_windows)))

    def round_robin(groups, limit):
        # Give each case evidence before giving abundant cases additional rows.
        from collections import deque
        queue = deque(iter(items) for items in groups if items)
        selected_items = {}
        while queue and len(selected_items) < limit:
            group = queue.popleft()
            item = next(group, None)
            if item is not None:
                selected_items[item] = None
                queue.append(group)
        return list(selected_items)

    ids = round_robin(witness_groups, 6000)
    checked = 0
    for pos in range(0, len(ids), 256):
        if time.monotonic() >= clock_end:
            break
        batch = ids[pos:pos+256]
        rows = conn.execute(f'SELECT {COLUMNS} FROM {cfg.source_schema}.behaviors '
                            'WHERE stream_id=%s AND behavior_id=ANY(%s)', (stream,batch)).fetchall()
        result['witnesses'].update({row['behavior_id']:evidence(row,secret) for row in rows})
        checked += len(batch)
    result['witness_coverage'] = dict(referenced=len(set().union(*map(set,witness_groups))) if witness_groups else 0,
                                      looked_up=checked, found=len(result['witnesses']))
    for session, at in round_robin(contexts, 48):
        if time.monotonic() >= clock_end:
            break
        rows = conn.execute(f'''SELECT {COLUMNS} FROM {cfg.source_schema}.behaviors
            WHERE stream_id=%s AND session_id=%s AND observed_at_ns>=%s AND observed_at_ns<%s
            ORDER BY observed_at_ns,behavior_id LIMIT 301''',(stream,session,at,at+FIVE)).fetchall()
        events = [evidence(row,secret) for row in rows[:300]]
        counts = {}
        for ev in events:
            service = ev['rejected_service'] or ev['service'] or ev['api']
            key = service, bool(ev['rejected_service']), ev['actor_eligible']
            counts.setdefault(key, []).append(ev)
        summary = []
        for (service, rejected, eligible), group in counts.items():
            axes = defaultdict(Counter)
            for ev in group:
                for axis, token in ev['inquiry_targets'].items():
                    axes[axis][token] += 1
            summary.append(dict(service=service, rejected=rejected, actor_eligible=eligible, requests=len(group),
                result_codes=dict(Counter(ev['result_code'] or '<unknown>' for ev in group)),
                targets={k:dict(covered=sum(v.values()), distinct=len(v), max_repeats=max(v.values()))
                         for k,v in axes.items()}))
        result['session_windows'].append(dict(session=label(secret,'session',session), start_ns=at,
            complete=len(rows)<=300, behaviors_examined=len(events), by_service=summary))
    result['session_windows_requested'] = sum(map(len,contexts))
    result['evidence_notes'] = [
        'Case selection and revision-specific verdicts match /incidents at this snapshot. Case IDs open operator details.',
        'Witnesses are selected examples. Equal inquiry aliases identify the same reviewed input field and value in this export.',
        'Session window counts use independent behavior reads including rejected attempts. Missing target coverage is unknown.',
        'At most 6000 witness reads and 48 short session windows, 300 behaviors per window. Check coverage before inference.',
        'Long-period counts are detector metrics. Witnesses do not independently recount every request in that period.']
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--date', help='Last Tehran calendar date, YYYY-MM-DD')
    parser.add_argument('--days', type=int, default=30, choices=range(1,31), metavar='1..30')
    args = parser.parse_args()
    now = datetime.now(timezone.utc)
    output = args.project / 'AnomalyDetection/reports' / f"Compact_Case_Review_{now:%Y%m%d_%H%M%S}_{secrets.token_hex(3)}.json"
    report = dict(snapshot_opened_utc=now.isoformat(), database_modified=False, workers_restarted=False, source_contacted=False)
    db = None
    try:
        cfg, source, stream = load(args.project)
        db = Store(source['DATABASE'], schema=cfg.source_schema, application='case-evidence-review')
        print(json.dumps(dict(status='READING_CURRENT_OPERATOR_CASES')), flush=True)
        with db.conn.transaction():
            db.conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            db.conn.execute("SET LOCAL statement_timeout='30s'")
            db.conn.execute("SET LOCAL lock_timeout='2s'")
            report.update(collect(db.conn, cfg, stream, args.date, args.days))
        report['status'] = 'READ_ONLY_CASE_REVIEW_COMPLETE'
    except Exception as exc:
        report.update(status='READ_ONLY_CASE_REVIEW_INCOMPLETE', failure_type=type(exc).__name__,
                      sqlstate=getattr(exc,'sqlstate',None))
    finally:
        if db:
            db.close()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report,ensure_ascii=False,indent=2), encoding='utf-8')
    print(json.dumps(dict(status=report['status'], output=str(output), cases=report.get('visible_cases'),
                          ui_truncated=report.get('ui_candidate_limit_reached'), failure_type=report.get('failure_type'),
                          sqlstate=report.get('sqlstate'), database_modified=False)), flush=True)
    return int(report['status'].endswith('INCOMPLETE')) * 2


if __name__ == '__main__':
    raise SystemExit(main())
