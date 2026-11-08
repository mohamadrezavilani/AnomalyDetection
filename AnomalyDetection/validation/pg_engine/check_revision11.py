"""Rare rates, evidence-to-review queue, retention skip and exact diagnostics.

Disposable PostgreSQL/WASM only. No owner connection or native accuracy claim.
"""
import json
from pathlib import Path
from types import SimpleNamespace

from transport import Engine
from check_revision10 import packet,metadata,TARGET,SESSION,SERVICES
from anomaly_detection import BUILD_ID,FIVE_NS
from anomaly_detection.product_store import ProductStore
from anomaly_detection.product_pipeline import apply_window,read_window,owned_context
from anomaly_detection.product_engine import evaluate_job
from anomaly_detection.product_priority import next_evidence_job,warm,refresh
from anomaly_detection.product_diagnostics import read_queue
from anomaly_detection.snapshot import canonical,digest

ROOT=Path(__file__).resolve().parents[2]


def evaluate(store,session,at):
    job=dict(store.raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(session,at)).fetchone())
    context=store.save_context(job,owned_context(store,job));job['version']=context['job_version']
    return evaluate_job(store,job,context,TARGET+50*FIVE_NS)


def audit(store,at,limit=None,*,session=SESSION):
    rows=store.raw.execute('SELECT request_key,body FROM anomaly_detection.adp_facts WHERE session_key=%s '
        'AND at_ns>=%s AND at_ns<%s AND last_audit_ns=0 ORDER BY request_key LIMIT %s',
        (session,at,at+FIVE_NS,10000 if limit is None else limit)).fetchall()
    facts=[]
    for row in rows:
        event=json.loads(row['body']);service=event['root_call']
        facts.append({'request_key':row['request_key'],'source_present':True,'semantic':event,
            'quality':{'evidence_available':True,'identity_state':'assigned','conflicted':False},
            'transport':{'root_call':service},'observations':[],'identifiers':[],'relations':[],
            'evidence':[{'origin_key':digest(['origin',row['request_key']]),'version_key':digest(['version',row['request_key']]),
                'callpath':service,'at_ns':event['anchor_ns'],'qualified':True,'raw_available':True}]})
    snap=SimpleNamespace(keys=[r['request_key'] for r in rows],source=dict(metadata(at),captured_at_ns=TARGET+40*FIVE_NS),
        facts=lambda:facts,requests={r['request_key']:{'session_key':session} for r in rows})
    return store.apply_audit(snap)


def main():
    engine=Engine();checks={}
    try:
        raw=engine.connect();raw.execute('CREATE SCHEMA anomaly_detection');store=ProductStore(raw);store.initialize()
        # Qualified synthetic history for four services, not owner calibration.
        values=[]
        maxima={SERVICES[0]:3,SERVICES[1]:8,SERVICES[2]:34,SERVICES[3]:24}
        for service in SERVICES:
            for i in range(1200):
                value=maxima[service] if i==0 else 20 if service==SERVICES[3] and i==1 else 1
                values.append((service,'service_execution',f'{i+10000:064x}',TARGET-(i+1)*2*FIVE_NS,value,True))
        with raw.cursor() as cursor:cursor.executemany('INSERT INTO anomaly_detection.adp_service_reference_points VALUES(%s,%s,%s,%s,%s,%s)',values)
        apply_window(store,packet(TARGET,{SERVICES[2]:100,SERVICES[3]:20}))
        result=evaluate(store,SESSION,TARGET)
        pooled=[d for d in result['decisions'] if d['family']=='peer_service_rate_5m']
        assert len(pooled)==2 and all(d['status']=='CANDIDATE' for d in pooled),pooled
        assert all(d['comparison_count']==2 for d in pooled)
        assert raw.execute('SELECT state FROM anomaly_detection.adp_incidents WHERE session_key=%s AND target_ns=%s',(SESSION,TARGET)).fetchone()['state']=='HOLD'
        checks['water_100_and_electric_20_can_be_rare_without_exceeding_three_times_maximum']='PASS_SYNTHETIC_REFERENCE'
        checks['statistical_screen_without_request_evidence_never_promotes_review']='PASS'
        audit(store,TARGET,64)
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_evidence_ready').fetchone()['n']==0
        evaluate(store,SESSION,TARGET)
        assert raw.execute('SELECT state FROM anomaly_detection.adp_incidents').fetchone()['state']=='HOLD'
        audit(store,TARGET)
        ready=next_evidence_job(store,TARGET+50*FIVE_NS);assert ready['target_ns']==TARGET
        evaluate(store,SESSION,TARGET)
        assert raw.execute('SELECT state FROM anomaly_detection.adp_incidents').fetchone()['state']=='NEEDS_REVIEW'
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_evidence_ready').fetchone()['n']==0
        checks['partial_audit_waits_then_complete_audit_gets_a_reserved_turn_and_review']='PASS'
        # Same mechanism for currency and gold, with no service-specific rule.
        second=TARGET+FIVE_NS
        apply_window(store,packet(second,{SERVICES[0]:16,SERVICES[1]:22},offset=200000))
        audit(store,second);evaluate(store,SESSION,second)
        active=raw.execute("SELECT body FROM anomaly_detection.adp_findings WHERE target_ns=%s AND state='ACTIVE'",(second,)).fetchall()
        assert {json.loads(r['body'])['service_path'] for r in active}=={SERVICES[0],SERVICES[1]}
        checks['currency_and_gold_share_the_same_rank_and_evidence_policy']='PASS_SYNTHETIC_REFERENCE'
        # Small, already-audited targets survive leaving the live time band.
        old=TARGET-30*FIVE_NS;other='c'*64
        apply_window(store,packet(old,{SERVICES[0]:4},session=other,offset=300000));audit(store,old,session=other)
        ready=next_evidence_job(store,TARGET+50*FIVE_NS);assert ready['session_key']==other and ready['target_ns']==old
        # Backfill existing audited facts after an upgrade in a frozen pass.
        raw.execute('DELETE FROM anomaly_detection.adp_evidence_ready')
        for _ in range(10):
            progress=warm(store,TARGET+50*FIVE_NS,limit=32)
            if progress['done']:break
        assert progress['done'] and next_evidence_job(store,TARGET+50*FIVE_NS)['target_ns']==old
        checks['old_small_audited_job_is_reachable_without_a_volume_threshold']='PASS'
        assert warm(store,TARGET+60*FIVE_NS,limit=32)==progress
        checks['upgrade_evidence_backfill_is_finite_and_idempotent']='PASS'
        # Metadata is never accepted as proof after a semantic change.
        row=dict(raw.execute('SELECT body FROM anomaly_detection.adp_facts WHERE session_key=%s LIMIT 1',(other,)).fetchone())
        changed=json.loads(row['body']);changed['revision']+=1
        store.apply_rows([changed],metadata(old))
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_evidence_ready WHERE session_key=%s AND target_ns=%s',(other,old)).fetchone()['n']==0
        refresh(store,[(None,old),(other,old)],TARGET+50*FIVE_NS)
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_evidence_ready WHERE session_key=%s AND target_ns=%s',(other,old)).fetchone()['n']==0
        checks['stale_revision_and_missing_identity_cannot_claim_evidence_readiness']='PASS'
        # Dirty high-volume jobs still get a turn after one earlier evaluation.
        raw.execute('UPDATE anomaly_detection.adp_jobs SET dirty=TRUE,due_ns=0 WHERE session_key=%s AND target_ns=%s',(SESSION,TARGET))
        assert store.next_backlog_job(TARGET+50*FIVE_NS)['target_ns']==TARGET
        checks['previously_evaluated_busy_target_is_not_excluded_from_backlog_lane']='PASS'
        # Exact tracking is SELECT-only; a queue sample is not acceptance.
        queries=[]
        class ReadOnly:
            def execute(self,sql,args=()):
                assert sql.startswith('SELECT ');queries.append(sql);return raw.execute(sql,args)
        before=raw.execute('SELECT version,dirty FROM anomaly_detection.adp_jobs ORDER BY target_ns').fetchall()
        report=read_queue(ReadOnly(),TARGET+50*FIVE_NS,[(SESSION,TARGET),(SESSION,second),(other,old)])
        assert len(report['tracked_tests'])==3
        assert report['tracked_tests'][0]['fact_quality_counts']['matching_qualified_facts']==120
        assert report['tracked_tests'][0]['evaluation_current'] is False
        assert any(d.get('adjusted_empirical_tail_rank') is not None for d in report['tracked_tests'][1]['decisions'])
        assert raw.execute('SELECT version,dirty FROM anomaly_detection.adp_jobs ORDER BY target_ns').fetchall()==before
        checks['tracked_cases_report_currentness_counts_evidence_and_rank_without_evaluation']='PASS_SELECT_ONLY'
        # General retention script preserves old live-window markers. Range
        # readers must jump the advertised cutoff instead of retrying each one.
        from contextlib import contextmanager
        class Source:
            page_size=64
            @contextmanager
            def snapshot(self):yield self.query
            def metadata(self,q):return dict(metadata(TARGET),retention_cutoff_ns=TARGET)
            def query(self,sql,args=(),**kwargs):
                if 'viewer_live_windows' in sql:
                    assert args[0]>=TARGET,args
                    return [{'start_ns':TARGET,'end_ns':TARGET+FIVE_NS,'generation':1,'last_publish_ns':1}]
                return []
        retained=read_window(Source(),{'next_ns':TARGET-10000*FIVE_NS})
        assert retained['target_ns']==TARGET and retained['available'] is True
        checks['range_cursor_jumps_known_pruned_history_without_a_zero_or_replay']='PASS'
        # Explicit missing target remains unavailable; learned rows survive a
        # known retention boundary rather than becoming fake zero training data.
        original=raw.execute('SELECT body FROM anomaly_detection.adp_windows WHERE session_key=%s AND start_ns=%s',(other,old)).fetchone()['body']
        apply_window(store,{'source':dict(metadata(old),retention_cutoff_ns=TARGET),'target_ns':old,'available':False,'rows':[]})
        assert raw.execute('SELECT body FROM anomaly_detection.adp_windows WHERE session_key=%s AND start_ns=%s',(other,old)).fetchone()['body']==original
        assert not raw.execute('SELECT complete FROM anomaly_detection.adp_source_windows WHERE start_ns=%s',(old,)).fetchone()['complete']
        checks['explicit_pruned_target_remains_unavailable_and_old_summary_is_not_zeroed']='PASS'
        # Existing pooled decisions migrate once, preserving models/feedback.
        raw.execute("DELETE FROM anomaly_detection.adp_state WHERE name='reference_rank_policy_v3'")
        models=raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_models').fetchone()['n']
        ver=raw.execute('SELECT version FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(SESSION,second)).fetchone()['version']
        store.initialize();store.initialize()
        job=raw.execute('SELECT version,dirty FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(SESSION,second)).fetchone()
        assert job['version']==ver+1 and job['dirty']
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_models').fetchone()['n']==models
        checks['rank_policy_upgrade_rechecks_old_decisions_once_without_resetting_history']='PASS'
        report={'build_id':BUILD_ID,'status':'PASS_ISOLATED_POSTGRESQL_WASM','checks':checks,
            'owner_database_or_viewer_modified':False,'native_windows':'NOT_RUN',
            'reported_owner_cases_on_release11':'NOT_RUN_BEFORE_OWNER_INSTALL','precision_recall_and_capacity':'NOT_EVALUATED'}
        (ROOT/'validation/PRODUCT_revision11.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
    finally:engine.close()


if __name__=='__main__':main()
