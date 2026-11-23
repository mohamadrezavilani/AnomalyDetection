"""One selection query for the operator UI and read-only case review."""
from compact_ad import MODEL, long_store, longitudinal
from compact_ad.seasonality import HORIZON
from compact_behavior import FIVE, FEATURES, inquiry
from . import cases


def publishable(config):
    # Snapshot-local eligibility, including changed reference windows.
    return f"""f.status='ANOMALY' AND ({long_store.eligible_sql(config.source_schema,config.ad_schema)} OR (f.result->>'model_version'=%s
        AND f.result->>'feature_version'=%s
        AND EXISTS(SELECT 1 FROM {config.ad_schema}.window_results r
            JOIN {config.source_schema}.windows w USING(stream_id,start_ns)
            WHERE r.stream_id=f.stream_id AND r.start_ns=f.start_ns
            AND r.model_version=%s AND r.feature_version=%s
            AND r.source_published_ns=w.published_at_ns
            AND r.timing_confirmed_revision=r.revision)
        AND (f.method NOT IN ('repeated_target','target_diversity')
             OR f.result->>'subject_policy'=%s)
        AND NOT EXISTS(SELECT 1 FROM {config.source_schema}.dirty_windows d
            WHERE d.stream_id=f.stream_id AND d.session_id='@all'
            AND d.start_ns BETWEEN f.start_ns-{HORIZON * FIVE} AND f.start_ns
            AND (d.start_ns>=f.start_ns-{288 * FIVE} OR (d.start_ns/{FIVE})%%12=(f.start_ns/{FIVE})%%12)
            AND d.processed_version<d.version)
        AND NOT EXISTS(SELECT 1 FROM {config.ad_schema}.reanalysis j
            WHERE j.stream_id=f.stream_id
            AND j.start_ns BETWEEN f.start_ns-{HORIZON * FIVE} AND f.start_ns
            AND (j.start_ns>=f.start_ns-{288 * FIVE} OR (j.start_ns/{FIVE})%%12=(f.start_ns/{FIVE})%%12)
            AND j.processed_version<j.version)))
        AND COALESCE((SELECT v.verdict FROM {config.ad_schema}.feedback v
            WHERE v.finding_id=f.finding_id AND v.finding_revision=f.revision
            ORDER BY v.feedback_id DESC LIMIT 1),'UNSURE')<>'FALSE_POSITIVE'"""

def eligible_args():
    return [MODEL, FEATURES, MODEL, FEATURES, inquiry.POLICY]


def bounds(date, days):
    day, start, end = cases.day_bounds(date)
    if not 1 <= days <= 30:
        raise ValueError('invalid_range')
    return day, start - (days - 1) * longitudinal.DAY, end


def select(db, config, stream, start, end):
    # Keep legacy forest flags out of the priority slice. The existing partial
    # index still covers the positive predicate for writers on both versions.
    priority = "(method='long_target_enumeration' OR (method IN ('target_diversity','repeated_target') AND COALESCE(result->>'single_signal_review_eligible','false')='true'))"
    rows=db.execute(f'''WITH strong_candidates AS MATERIALIZED (
        SELECT * FROM {config.ad_schema}.findings
        WHERE stream_id=%s AND status='ANOMALY' AND start_ns>=%s AND start_ns<%s
        AND (method='long_target_enumeration' OR result->>'single_signal_review_eligible'='true')
        AND {priority}
        ORDER BY start_ns DESC,finding_id DESC LIMIT 1001
    ), ordinary_candidates AS MATERIALIZED (
        SELECT * FROM {config.ad_schema}.findings
        WHERE stream_id=%s AND status='ANOMALY' AND start_ns>=%s AND start_ns<%s
        AND NOT {priority}
        ORDER BY start_ns DESC,finding_id DESC LIMIT {cases.LIMIT+1}
    ), candidates AS MATERIALIZED (
        SELECT * FROM strong_candidates UNION ALL SELECT * FROM ordinary_candidates
    ), eligible AS (
        SELECT f.*,COALESCE((SELECT v.verdict FROM {config.ad_schema}.feedback v
            WHERE v.finding_id=f.finding_id AND v.finding_revision=f.revision
            ORDER BY v.feedback_id DESC LIMIT 1),'UNSURE') AS verdict
        FROM candidates f WHERE {publishable(config)}
    ) SELECT e.*,c.n AS candidate_count,c.strong_count FROM
        (SELECT count(*) AS n,(SELECT count(*) FROM strong_candidates) AS strong_count FROM candidates) c
        LEFT JOIN eligible e ON true ORDER BY
        (e.method='long_target_enumeration' OR (e.method IN ('target_diversity','repeated_target') AND COALESCE(e.result->>'single_signal_review_eligible','false')='true')) DESC,
        e.start_ns DESC,e.finding_id DESC''',
        [stream,start,end,stream,start,end,*eligible_args()]).fetchall()
    truncated=bool(rows and (rows[0]['candidate_count']>cases.LIMIT or rows[0]['strong_count']>1000))
    eligible=[r for r in rows if r.get('finding_id')][:cases.LIMIT]
    selected=cases.select_cases(eligible)
    return selected, len(eligible), truncated
