"""Trace one rate-limited request into stored features and analysis publication."""
from compact_behavior import FIVE,FEATURES
from compact_behavior.extract import identity,behavior_id,materialize
from compact_behavior.store import ALL
from compact_ad import MODEL
from compact_ad.seasonality import HORIZON


def inspect(store, ad_schema, stream, request_id):
    key=identity(request_id)
    if key is None:raise ValueError('valid_request_id_required')
    s=store.schema
    row=store.conn.execute(f'''SELECT b.*,p.state FROM {s}.behaviors b
        JOIN {s}.behavior_payloads p USING(behavior_id)
        WHERE b.stream_id=%s AND b.behavior_id=%s''',(stream,behavior_id(stream,key))).fetchone()
    if not row:raise ValueError('request_not_stored')
    body=materialize(stream,row['state']);expected=(body or {}).get('features',{}).get('rejected_attempt')
    stored=row['features'].get('rejected_attempt')
    valid=bool(expected and expected.get('eligible') and row['result_code']=='GR0004')
    start=row['observed_at_ns']//FIVE*FIVE
    service=(expected or {}).get('service')
    count=store.conn.execute(f'''SELECT count(*) AS n FROM {s}.behaviors
        WHERE stream_id=%s AND session_id=%s AND observed_at_ns>=%s AND observed_at_ns<%s
        AND result_code='GR0004' AND features->>'version'=%s
        AND features->'rejected_attempt'->>'service'=%s
        AND features->'rejected_attempt'->'eligible'='true'::jsonb''',
        (stream,row['session_id'],start,start+FIVE,FEATURES,service)).fetchone()['n']
    window=store.conn.execute(f'''SELECT r.model_version,r.feature_version,r.revision,
        r.timing_confirmed_revision,r.source_published_ns,w.published_at_ns,
        r.summary->'services'->%s->'rejected_count' AS all_sessions_rejected_count,
        r.readiness->'rate_limit_rejections' AS method_readiness
        FROM {s}.windows w LEFT JOIN {ad_schema}.window_results r USING(stream_id,start_ns)
        WHERE w.stream_id=%s AND w.start_ns=%s''',(service,stream,start)).fetchone()
    pending=store.conn.execute(f'''SELECT
        EXISTS(SELECT 1 FROM {s}.dirty_windows WHERE stream_id=%s AND session_id=%s
            AND start_ns BETWEEN %s AND %s AND processed_version<version
            AND (start_ns>=%s OR (start_ns/{FIVE})%%12=(%s/{FIVE})%%12)) OR
        EXISTS(SELECT 1 FROM {ad_schema}.reanalysis WHERE stream_id=%s
            AND start_ns BETWEEN %s AND %s AND processed_version<version
            AND (start_ns>=%s OR (start_ns/{FIVE})%%12=(%s/{FIVE})%%12)) AS pending''',
        (stream,ALL,start-HORIZON*FIVE,start,start-288*FIVE,start,
         stream,start-HORIZON*FIVE,start,start-288*FIVE,start)).fetchone()['pending']
    current=bool(window and window['model_version']==MODEL and window['feature_version']==FEATURES
        and window['source_published_ns']==window['published_at_ns']
        and window['revision']==window['timing_confirmed_revision'] and not pending)
    return dict(request_id=key,original_request_ids=row['state'].get('raw_request_ids',[]),
        session_id=row['session_id'],requested_service=service,start_ns=start,
        observed_rate_limited_attempt=valid,stored_attempt_feature=stored,
        needs_feature_repair=valid and stored!=expected,
        this_request_counted_in_stored_attempts=valid and stored==expected and bool(row['session_id']),
        stored_session_rejections_in_window=count,analysis_current=current,
        analysis_window=window,reference_work_pending=pending,
        target_values_available=bool(row['features'].get('input_feature_eligibility',{}).get('targets')
                                     and row['features'].get('input',{}).get('targets')))


class AttemptWindowWriter:
    def __init__(self,store,ad_schema,request_id):
        self.store=store;self.ad_schema=ad_schema;self.request_id=identity(request_id);self.limits=store.limits

    def publish(self,stream,start,end,states,count):
        from tools.Repair_Compact_Sample_Roles import republish
        with self.store.conn.transaction():
            result=republish(self.store,stream,start,end,states,count,[self.request_id])
            check=inspect(self.store,self.ad_schema,stream,self.request_id)
            if not check['this_request_counted_in_stored_attempts']:
                raise ValueError('attempt_feature_repair_not_applied')
        return result
