"""Synthetic reproductions of dispatcher knowledge and historical queue churn."""
from copy import deepcopy
import json
import os
import unittest
from compact_behavior import FIVE, dispatch_evidence
from compact_behavior.extract import materialize, iso, digest
from compact_ad import references
from compact_ad.engine import summarize, evaluate
from compact_product import case_selection
from tests.test_compact_extract import row, extract, T
from tests import test_compact_product_pg as product_tests
from tests.test_compact_audit35 import inquiry_rows


def export_rows():
    return [row(path=dispatch_evidence.API, message='POST https://example.test/api HTTP/1.1 (GR0010 | ServiceUnavailable)'),
            row(path=dispatch_evidence.SQL, message='(SQL Parameters: @queryParameters={"FixedLineNumber":"synthetic-line","Cycle":null,"Final":true})'),
            row(path=dispatch_evidence.PATH, message='Input:[{"FixedLineNumber":"synthetic-line","MidTerm":false,"TraceNumber":"synthetic-trace"}] Output:[{"Status":{"Code":"G00001"},"Parameters":null}]')]


def variants():
    good=extract(export_rows())['req-1']
    yield 'valid',good,True
    no_code=deepcopy(good);no_code['roots'][0]['code']=None
    yield 'unknown_public_outcome',no_code,True
    for name in ('wrong_number','wrong_term','wrong_cycle','missing_sql','missing_output','late','undated','conflicting_action','competing_provider','multiple_sessions','refusal','malformed','provider_object','query_extra'):
        state=deepcopy(good)
        q=next(v for v in state['inputs'] if v['path']==dispatch_evidence.SQL)
        p=next(v for v in state['inputs'] if v['path']==dispatch_evidence.PATH)
        o=state['outputs'][0]
        if name=='wrong_number':p['value'][0]['FixedLineNumber']='another-line'
        if name=='wrong_term':p['value'][0]['MidTerm']=True
        if name=='wrong_cycle':p['value'][0]['Cycle']='another-cycle'
        if name=='missing_sql':state['inputs'].remove(q)
        if name=='missing_output':state['outputs']=[]
        if name=='late':p['observed_at_ns']=o['observed_at_ns']=T+FIVE
        if name=='undated':p['observed_at_ns']=o['observed_at_ns']=None
        if name=='conflicting_action':state['dispatch']=[dict(kind='action',value='Services.v1/WaterBills')]
        if name=='competing_provider':state['inputs'].append(dict(p,path='ClientAyanCoInquiry.WaterBillInquiry'))
        if name=='multiple_sessions':state['sessions'].append('another-session')
        if name=='refusal':state['roots'][0]['code']='G00010'
        if name=='malformed':state['parse_errors'].append(dict(path=dispatch_evidence.PATH,direction='outputs'))
        if name=='provider_object':p['value']=p['value'][0]
        if name=='query_extra':q['value']['AnotherRouteField']='unreviewed'
        yield name,state,False


class Contracts(unittest.TestCase):
    def test_exact_composite_proof_and_negative_boundaries(self):
        for name,state,expected in variants():
            with self.subTest(name=name):
                self.assertEqual(dispatch_evidence.verified(state),expected)
        body=materialize('test',extract(export_rows())['req-1'])
        self.assertEqual(body['service_key'],dispatch_evidence.SERVICE)
        self.assertEqual(body['operation_role'],'business')
        self.assertTrue(body['features']['service_rate_eligible'])
        self.assertNotIn('unresolved_dispatch',body['quality'])

    def test_diagnostics_do_not_change_reference_measurements(self):
        body=materialize('test',extract([row()])['req-1'])
        original=summarize([body])[0]
        changed=deepcopy(original)
        changed['feature_bytes']+=99999
        changed['analysis_policy']='older-policy'
        changed['inquiry_policy']='older-inquiry-policy'
        self.assertEqual(references.hashes(original),references.hashes(changed))


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'native PostgreSQL required')
class Postgres(unittest.TestCase):
    setUp=product_tests.CompactProductPostgresTests.setUp
    tearDown=product_tests.CompactProductPostgresTests.tearDown

    def publish(self,start,records):
        return self.db.publish('test',start,start+FIVE,extract(records),len(records))

    def analyze(self,start):
        w=self.db.snapshot('test',start)
        return self.db.commit_analysis(w,evaluate(start,w['summary'],w['services'],w['actors'],w['references'],
            temporal_references=w['temporal_references'],previous_inquiries=w['previous_inquiries']),.01)

    def test_sql_proof_matches_extractor_on_positive_and_negative_evidence(self):
        from psycopg.types.json import Jsonb
        for name,state,expected in variants():
            with self.subTest(name=name):
                v=self.db.conn.execute(f'SELECT ({dispatch_evidence.proof_sql()}) AS valid FROM (SELECT %s::jsonb AS state) p',
                                       (Jsonb(state),)).fetchone()['valid']
                self.assertEqual(bool(v),expected)

    def test_legacy_known_export_leaves_unknowns_without_source_replay_or_row_rewrite(self):
        from tools.Review_Compact_Unknowns import inventory
        from compact_product.web import create_app
        self.publish(T,export_rows());s=self.config.source_schema
        self.db.conn.execute(f'''UPDATE {s}.behaviors SET features=(features||jsonb_build_object(
            'service_key',NULL,'service_binding','UNRESOLVED_DISPATCH','operation_role','unknown')),
            quality='["unresolved_dispatch","output_binding_unconfirmed"]'::jsonb''')
        before=self.db.conn.execute(f'SELECT * FROM {s}.behaviors').fetchone();cursor=self.db.cursor('test')
        report=inventory(self.db.conn,s,'test')
        self.assertEqual(report['remaining_unknown'],0)
        self.assertEqual(report['classified_provider_dispatches'],1)
        from compact_product.provider_contracts import initialize
        initialize(self.db.conn,s)
        client=create_app(self.config,self.database,'test').test_client();url='/behaviors/'+before['behavior_id']
        self.assertNotIn(url,client.get('/?scope=unknown').get_data(as_text=True))
        self.assertIn(url,client.get('/?scope=meaningful').get_data(as_text=True))
        response=client.get(url);self.assertEqual(response.status_code,200)
        page=response.get_data(as_text=True)
        self.assertIn(dispatch_evidence.SERVICE,page)
        self.assertNotIn('نقش مشخص نشده',page)
        work=self.db.snapshot('test',T)
        self.assertEqual(work['summary']['services'][dispatch_evidence.SERVICE]['count'],1)
        self.assertEqual(self.db.cursor('test'),cursor)
        self.assertEqual(self.db.conn.execute(f'SELECT * FROM {s}.behaviors').fetchone(),before)
        from tools.Review_Compact_Requests import inspect
        report=inspect(self.db,self.config,'test',['req-1'])
        self.assertEqual(report['requests'][0]['current_service'],dispatch_evidence.SERVICE)
        self.assertNotIn('synthetic-line',json.dumps(report))

    def test_policy_only_migration_does_not_expand_existing_history_queue(self):
        for i in range(36):
            at=T+i*FIVE
            self.publish(at,[row(str(i),at=iso(at+10**9))]);self.analyze(at)
        a=self.config.ad_schema
        self.db.conn.execute(f'''UPDATE {a}.window_results SET summary=(summary-'analysis_policy')||'{{"feature_bytes":999999}}'::jsonb''')
        self.db.security_migration_cursor.clear()
        for i in range(36):
            self.assertEqual(self.db.select_work('test'),T+i*FIVE)
            self.analyze(T+i*FIVE)
            pending=self.db.conn.execute(f'SELECT count(*) AS n FROM {a}.reanalysis WHERE processed_version<version').fetchone()['n']
            self.assertEqual(pending,0)
        self.assertIsNone(self.db.select_work('test'))

    def test_shape_change_does_not_requeue_distant_rate_models_but_rate_change_does(self):
        a,s=self.config.ad_schema,self.config.source_schema
        for at in (T,T+FIVE):
            self.publish(at,[row(str(at),at=iso(at+10**9))]);self.analyze(at)
        far=T+2*288*FIVE
        self.db.conn.execute(f"UPDATE {s}.streams SET next_ns=%s WHERE stream_id='test'",(far,))
        self.publish(far,[row('far',at=iso(far+10**9))]);self.analyze(far)
        w=self.db.snapshot('test',T)
        w['summary']['services']['Services.v1/WaterBills']['shapes']['changed-shape']=1
        self.db.commit_analysis(w,[],.01)
        jobs=self.db.conn.execute(f'SELECT start_ns FROM {a}.reanalysis WHERE processed_version<version').fetchall()
        self.assertEqual([r['start_ns'] for r in jobs],[T+FIVE])
        w=self.db.snapshot('test',T)
        w['summary']['services']['Services.v1/WaterBills']['count']+=1
        self.db.commit_analysis(w,[],.01)
        jobs=self.db.conn.execute(f'SELECT start_ns FROM {a}.reanalysis WHERE processed_version<version ORDER BY start_ns').fetchall()
        self.assertEqual([r['start_ns'] for r in jobs],[T+FIVE,far])

    def test_current_reference_summary_survives_reference_only_reanalysis_and_case_can_be_reviewed(self):
        self.publish(T,[row('baseline')]);self.analyze(T)
        records=[dict(r,**{'@timestamp':iso(T+FIVE+10**9+i*1000000)}) for i,r in enumerate(inquiry_rows())]
        self.publish(T+FIVE,records);self.analyze(T+FIVE)
        a,s=self.config.ad_schema,self.config.source_schema
        selected=lambda:case_selection.select(self.db.conn,self.config,'test',T,T+2*FIVE)[0]
        self.assertTrue(selected())
        self.db.conn.execute(f"INSERT INTO {a}.reanalysis(stream_id,start_ns) VALUES('test',%s)",(T,))
        self.assertEqual(len(self.db.snapshot('test',T+FIVE)['references']),1)
        self.assertTrue(selected())
        # A real changed source still fences the case immediately, before analysis.
        self.publish(T,[row('late-evidence')])
        self.assertFalse(selected())
        self.assertFalse(self.db.snapshot('test',T+FIVE)['references'])
        self.analyze(T)
        self.assertFalse(selected())
        self.analyze(T+FIVE)
        self.assertTrue(selected())

    def test_direct_case_gets_bounded_priority_and_keeps_feedback_and_cursors(self):
        self.publish(T,[row('baseline')]);self.analyze(T)
        records=[dict(r,**{'@timestamp':iso(T+FIVE+10**9+i*1000000)}) for i,r in enumerate(inquiry_rows())]
        self.publish(T+FIVE,records);self.analyze(T+FIVE)
        a=self.config.ad_schema;cursor=self.db.cursor('test')
        self.db.conn.execute(f"UPDATE {a}.window_results SET summary=summary-'analysis_policy'")
        self.db.conn.execute(f"INSERT INTO {a}.reanalysis(stream_id,start_ns) SELECT stream_id,start_ns FROM {a}.window_results")
        self.db.iteration=4
        self.assertEqual(self.db.select_work('test'),T+FIVE)
        self.analyze(T+FIVE)
        cases=case_selection.select(self.db.conn,self.config,'test',T,T+2*FIVE)[0]
        self.assertTrue(cases)
        finding=cases[0]['findings'][0]
        self.db.conn.execute(f"INSERT INTO {a}.feedback(finding_id,finding_revision,verdict,note,recorded_at_ns) VALUES(%s,%s,'FALSE_POSITIVE','synthetic review',1)",(finding['finding_id'],finding['revision']))
        self.assertFalse(case_selection.select(self.db.conn,self.config,'test',T,T+2*FIVE)[0])
        self.assertEqual(self.db.cursor('test'),cursor)

    def test_policy_migration_keeps_legacy_reference_token_and_human_revision(self):
        from psycopg.types.json import Jsonb
        self.publish(T,[row('baseline')]);self.analyze(T)
        a=self.config.ad_schema
        saved=self.db.conn.execute(f'SELECT summary FROM {a}.window_results WHERE start_ns=%s',(T,)).fetchone()['summary']
        legacy=digest(dict(references.base(saved),feature_bytes=saved['feature_bytes']))
        saved['security']['base_summary_hash']=legacy
        self.db.conn.execute(f'UPDATE {a}.window_results SET summary=%s,summary_hash=%s WHERE start_ns=%s',
                             (Jsonb(saved),digest(saved),T))
        records=[dict(r,**{'@timestamp':iso(T+FIVE+10**9+i*1000000)}) for i,r in enumerate(inquiry_rows())]
        self.publish(T+FIVE,records);self.analyze(T+FIVE)
        finding=self.db.conn.execute(f"SELECT * FROM {a}.findings WHERE method='target_diversity' AND status='ANOMALY'").fetchone()
        self.db.conn.execute(f"INSERT INTO {a}.feedback(finding_id,finding_revision,verdict,note,recorded_at_ns) VALUES(%s,%s,'FALSE_POSITIVE','human decision',1)",
                             (finding['finding_id'],finding['revision']))
        self.db.conn.execute(f"UPDATE {a}.window_results SET summary=(summary-'analysis_policy')||'{{\"feature_bytes\":999999}}'::jsonb")
        self.analyze(T);self.analyze(T+FIVE)
        current=self.db.conn.execute(f'SELECT * FROM {a}.findings WHERE finding_id=%s',(finding['finding_id'],)).fetchone()
        self.assertEqual(current['revision'],finding['revision'])
        self.assertFalse(case_selection.select(self.db.conn,self.config,'test',T,T+2*FIVE)[0])
        self.assertEqual(self.db.conn.execute(f"SELECT summary->'security'->>'base_summary_hash' AS token FROM {a}.window_results WHERE start_ns=%s",(T,)).fetchone()['token'],legacy)

    def test_explicit_review_request_has_indexed_priority_outside_latest_case_slice(self):
        self.publish(T,[row('requested')]);self.analyze(T)
        self.publish(T+FIVE,[row('ordinary',at=iso(T+FIVE+10**9))]);self.analyze(T+FIVE)
        a=self.config.ad_schema
        self.db.conn.execute(f"INSERT INTO {a}.reanalysis(stream_id,start_ns,priority) VALUES('test',%s,false),('test',%s,true)",(T,T+FIVE))
        self.db.iteration=4
        self.assertEqual(self.db.select_work('test'),T+FIVE)
        self.analyze(T+FIVE)
        self.assertFalse(self.db.conn.execute(f'SELECT priority FROM {a}.reanalysis WHERE start_ns=%s',(T+FIVE,)).fetchone()['priority'])
        self.assertEqual(self.db.select_work('test'),T)
