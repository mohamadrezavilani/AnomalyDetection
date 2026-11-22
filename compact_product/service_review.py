"""Bounded read-only service timing and session-count evidence, not new alerts."""
from datetime import datetime
from zoneinfo import ZoneInfo
from compact_behavior import FIVE,FEATURES
from compact_ad import MODEL


def collect(db,schema,ad_schema,stream,service,start,*,windows=12):
    if not service or len(service)>160 or not 1<=windows<=12:raise ValueError('bounded_service_review_required')
    output=[]
    for at in range(start-(windows-1)*FIVE,start+1,FIVE):
        # Time-indexed single-window reads. No raw payloads or session IDs leave DB.
        predicate="stream_id=%s AND observed_at_ns>=%s AND observed_at_ns<%s AND features->>'service_key'=%s AND features->>'version'=%s AND features->'service_rate_eligible'='true'::jsonb"
        args=(stream,at,at+FIVE,service,FEATURES)
        durations=db.execute(f'''SELECT result_code,count(*) AS requests,
            count(reported_duration) AS valid_durations,
            percentile_cont(ARRAY[0.5,0.95]) WITHIN GROUP(ORDER BY reported_duration) AS p50_p95_ms,
            min(reported_duration) AS min_ms,max(reported_duration) AS max_ms,
            count(*) FILTER(WHERE reported_duration>250) AS over_250ms,
            count(*) FILTER(WHERE reported_duration>1000) AS over_1000ms,
            count(*) FILTER(WHERE reported_duration>2000) AS over_2000ms,
            count(*) FILTER(WHERE reported_duration>5000) AS over_5000ms
            FROM {schema}.behaviors WHERE {predicate} GROUP BY result_code ORDER BY result_code''',args).fetchall()
        peers=db.execute(f'''WITH counts AS (SELECT session_id,count(*) AS n
            FROM {schema}.behaviors WHERE {predicate}
            AND session_id IS NOT NULL AND features->'session_eligible'='true'::jsonb GROUP BY session_id)
            SELECT count(*) AS active_sessions,sum(n) AS requests_with_valid_session,
            avg(n) AS mean_requests_per_active_session,
            percentile_cont(ARRAY[0.5,0.95]) WITHIN GROUP(ORDER BY n) AS median_p95_requests,
            min(n) AS min_requests,max(n) AS max_requests FROM counts''',args).fetchone()
        findings=db.execute(f'''SELECT method,status,result,revision FROM {ad_schema}.findings
            WHERE stream_id=%s AND start_ns=%s AND service=%s AND session_id IS NULL
            AND method IN ('service_latency','service_rate','reported_result') ORDER BY method''',
            (stream,at,service)).fetchall()
        output.append(dict(start_ns=at,durations_by_reported_code=durations,active_session_peers=peers,findings=findings))
    # At most twelve same-hour observations per day for 28 days. Absence is not zero.
    hour=datetime.fromtimestamp(start/1e9,ZoneInfo('Asia/Tehran')).hour
    references=db.execute(f'''SELECT r.start_ns,r.model_version,r.feature_version,
        r.summary->'services'->%s->'duration_n' AS duration_n,
        r.summary->'services'->%s->'duration_p95' AS duration_p95_ms,
        r.summary->'services'->%s->'duration_invalid' AS duration_invalid,
        r.summary->'services'->%s->'actor_p95' AS actor_p95,
        r.source_published_ns=w.published_at_ns AND r.timing_confirmed_revision=r.revision
            AND NOT EXISTS(SELECT 1 FROM {schema}.dirty_windows d WHERE d.stream_id=r.stream_id
                AND d.start_ns=r.start_ns AND d.session_id='@all' AND d.processed_version<d.version)
            AND NOT EXISTS(SELECT 1 FROM {ad_schema}.reanalysis j WHERE j.stream_id=r.stream_id
                AND j.start_ns=r.start_ns AND j.processed_version<j.version) AS own_window_ready
        FROM {ad_schema}.window_results r JOIN {schema}.windows w USING(stream_id,start_ns)
        WHERE r.stream_id=%s AND r.start_ns>=%s AND r.start_ns<%s
        AND EXTRACT(HOUR FROM to_timestamp(r.start_ns/1000000000.0) AT TIME ZONE 'Asia/Tehran')=%s
        ORDER BY r.start_ns LIMIT 336''',(service,service,service,service,stream,start-28*288*FIVE,start,hour)).fetchall()
    return dict(service=service,focus_start_ns=start,model_version=MODEL,windows=output,
        same_tehran_hour_references=references,
        limitations=['Duration bins are diagnostics, not service thresholds.',
            'Session is the analysis identity; unique people cannot be inferred.',
            'Cache hits/misses are not observed here; do not infer cache hit from missing provider evidence.',
            'A previous finding can be stale; own_window_ready does not validate every reference dependency.',
            'Current-window peer counts are descriptive, not a trained comparable-user model.',
            'Same-hour reference rows are diagnostic candidates, not validated model training data.'])
