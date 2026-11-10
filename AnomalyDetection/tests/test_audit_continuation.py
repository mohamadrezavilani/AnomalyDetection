"""Independent source-pin and request-profile regression controls.

Temporary source files and scripted I/O only. No live DB, installer, Worker or
Viewer initializer is used. Native SQL/concurrency qualification is separate.
"""
from contextlib import contextmanager,nullcontext
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import json,sys,tempfile,types,unittest
from unittest.mock import patch
from anomaly_detection.snapshot import ContractError,canonical,digest
from anomaly_detection.product_source import ProductSource
from anomaly_detection import pg_source
from audit.request_sample_fixture import FAMILIES,run_sample,make_profile,T,S,Result
from audit.continuous_fixture import run_continuous


@contextmanager
def source_fixture():
    with tempfile.TemporaryDirectory(prefix='p24-pin-test-') as tmp:
        root=Path(tmp);member=root/'p24_foundation/fixture.py';member.parent.mkdir()
        member.write_bytes(b'# fixture version 1\n')
        h=sha256();h.update(b'p24_foundation/fixture.py\0');h.update(sha256(member.read_bytes()).digest())
        pin=h.hexdigest();(root/'RELEASE_MANIFEST.json').write_text(json.dumps({'runtime_source_sha256':pin}))
        connections=[]
        class FakeConnection:
            def __init__(self):self.closed=False;self.rolled_back=False
            def execute(self,sql):
                if sql!='SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY':raise AssertionError(sql)
            def rollback(self):self.rolled_back=True
            def close(self):self.closed=True
        def connect(**kwargs):
            c=FakeConnection();connections.append(c);return c
        pg=types.ModuleType('psycopg');rows=types.ModuleType('psycopg.rows');pg.connect=connect;rows.dict_row=object()
        with patch.object(pg_source,'SOURCE_SHA',pin),patch.object(pg_source,'SUPPORTED_RUNTIMES',frozenset((pin,))),patch('anomaly_detection.native_pg.source_parameters',return_value={'dbname':'p24_design_viewer'}), \
             patch.dict(sys.modules,{'psycopg':pg,'psycopg.rows':rows}):
            source=ProductSource(root)
            yield source,member,connections


class SourcePinControls(unittest.TestCase):
    def test_unchanged_source_allows_readonly_snapshot(self):
        with source_fixture() as (source,member,connections):
            with source.snapshot():pass
            self.assertEqual(len(connections),1)
            self.assertTrue(connections[0].closed and connections[0].rolled_back)

    def test_cold_constructor_rejects_changed_runtime(self):
        with source_fixture() as (source,member,connections):
            member.write_bytes(b'# fixture version 2\n')
            with self.assertRaises(ContractError):ProductSource(source.project)
            self.assertEqual(connections,[])

    def test_cached_source_must_reject_runtime_changed_before_read(self):
        with source_fixture() as (source,member,connections):
            member.write_bytes(b'# fixture version 2\n')
            with self.assertRaises(ContractError):
                with source.snapshot():pass

    def test_runtime_changed_during_read_must_not_escape_as_valid_packet(self):
        with source_fixture() as (source,member,connections):
            with self.assertRaises(ContractError):
                with source.snapshot():member.write_bytes(b'# fixture version 2\n')
            self.assertTrue(connections[0].closed and connections[0].rolled_back)


class ProfileCurrentnessControls(unittest.TestCase):
    def test_matching_authoritative_profiles_trigger_five_real_dispatchers(self):
        for family in FAMILIES:
            with self.subTest(family=family):
                item,status,pub,store=run_sample(family)
                self.assertEqual(status,'APPLIED');self.assertEqual(item['status'],'CANDIDATE')
                self.assertTrue(item['evidence_verified'])

    def test_changed_revision_is_unknown_for_all_five_dispatchers(self):
        results={f:run_sample(f,'stale_revision')[0]['status'] for f in FAMILIES}
        self.assertEqual(results,{f:'INSUFFICIENT_DATA' for f in FAMILIES})

    def test_withdrawn_fact_is_unknown_for_all_five_dispatchers(self):
        results={f:run_sample(f,'withdrawn_fact')[0]['status'] for f in FAMILIES}
        self.assertEqual(results,{f:'INSUFFICIENT_DATA' for f in FAMILIES})

    def test_absent_source_is_unknown_for_all_five_dispatchers(self):
        results={f:run_sample(f,'source_absent')[0]['status'] for f in FAMILIES}
        self.assertEqual(results,{f:'INSUFFICIENT_DATA' for f in FAMILIES})

    def test_missing_fact_cannot_certify_a_canonical_profile(self):
        results={f:run_sample(f,'missing_fact')[0]['status'] for f in FAMILIES}
        self.assertEqual(results,{f:'INSUFFICIENT_DATA' for f in FAMILIES})

    def test_pending_refresh_cannot_republish_a_stale_profile(self):
        results={f:run_sample(f,'refresh_pending')[0]['status'] for f in FAMILIES}
        self.assertEqual(results,{f:'INSUFFICIENT_DATA' for f in FAMILIES})

    def test_direct_technical_profiles_without_canonical_fact_remain_supported(self):
        for family in FAMILIES:
            with self.subTest(family=family):
                self.assertEqual(run_sample(family,'technical_without_fact')[0]['status'],'CANDIDATE')

    def test_actor_cached_profile_is_unknown_while_refresh_is_pending(self):
        from anomaly_detection.scenario_store import scope_profiles
        p=make_profile(10,T+1,'a'*64)
        scope=dict(request_keys=canonical([p['request_key']]),available=True,independent=True)
        row=dict(request_key=p['request_key'],body=canonical(p),revision=1,anchor_key=p['anchor_key'],source_present=True,state='active',refresh_pending=True)
        data,complete,_=scope_profiles(object(),'a'*64,S,T,({('a'*64,S,T):scope},{p['request_key']:row}))
        self.assertFalse(complete);self.assertFalse(data[0]['qualified'])

    def test_unchanged_profile_refresh_ack_requeues_dependent_scenarios(self):
        from anomaly_detection.scenario_store import save_profile
        p=make_profile(10,T+1,'a'*64);calls=[]
        class Store:
            history_floor_ns=0
            raw=None
            def transaction(self):return nullcontext()
            def bind(self,source):pass
            def execute(self,sql,params=()):
                calls.append(sql)
                if sql.startswith('SELECT ') and 'adp_profiles' in sql:
                    return Result([dict(request_key=p['request_key'],body=canonical(p),content_digest=digest(p),service_path=S,at_ns=p['at_ns'],refresh_pending=True)])
                if sql.startswith(('UPDATE ','DELETE ','INSERT ')):return Result()
                raise AssertionError(sql[:100])
        store=Store();store.raw=store
        save_profile(store,{'request_key':p['request_key'],'profile':p,'source':{}},T+100)
        self.assertTrue(any(sql.startswith('UPDATE anomaly_detection.adp_scenario_jobs') for sql in calls))


class AdditionalCriterionControls(unittest.TestCase):
    def test_isolation_forest_has_an_executable_positive_at_evaluator_level(self):
        from audit.run_independent_audit import behavior_context,pm
        context,history=behavior_context(current=1_000_000,n=180)
        for r in history:r['counts']={next(iter(context['windows'][0]['counts'])):10}
        history[0]['counts']={next(iter(context['windows'][0]['counts'])):1000}
        decision=next(d for d in pm.evaluate(context,history) if d['family']=='isolation_forest')
        self.assertEqual(decision['status'],'CANDIDATE');self.assertGreater(decision['score'],decision['upper'])

    def test_continuous_evaluator_runs_all_four_horizons_and_excludes_self(self):
        decisions,inputs,store=run_continuous()
        self.assertEqual(len(decisions),4)
        self.assertEqual({d['status'] for d in decisions},{'CANDIDATE'})
        self.assertEqual({d['observed'] for d in decisions},{20})
        self.assertEqual({d['other_session_epochs'] for d in decisions},{400})
        self.assertTrue(all(d['span_evidence_verified'] for d in decisions))
        self.assertTrue(any(d['begin_ns']<T for d in decisions))

    def test_continuous_ordinary_rate_does_not_trigger(self):
        # Same exact two-event burst as every actor in the reference cohort.
        from audit.continuous_fixture import Store,ACTOR
        from anomaly_detection.continuous import evaluate
        normal=Store(n=2,offset=0)
        ds,_=evaluate(normal,{'session_key':ACTOR,'target_ns':T},{'windows':[{'start_ns':T,'counts':{S:2}}]})
        self.assertEqual({d['status'] for d in ds},{'NO_DEVIATION_OBSERVED'})

    def test_continuous_source_gap_remains_unknown(self):
        decisions,_,_=run_continuous(missing=True)
        self.assertEqual({d['status'] for d in decisions},{'INSUFFICIENT_DATA'})

    def test_continuous_stale_revision_cannot_certify_span(self):
        decisions,_,_=run_continuous(stale=True)
        self.assertFalse(any(d.get('span_evidence_verified') for d in decisions))


if __name__=='__main__':unittest.main()
