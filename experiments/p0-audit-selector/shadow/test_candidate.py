"""Independent *offline* tests for the P0 candidate, not production qualification."""
import importlib.util
import os
import random
import sys
import unittest
from pathlib import Path

HERE=Path(__file__).resolve().parent
SOURCE_PROJECT=Path(os.environ.get('P24_AD_TEST_ROOT',HERE.parents[2])).resolve()
sys.path.insert(0,str(SOURCE_PROJECT/'AnomalyDetection'))
spec=importlib.util.spec_from_file_location('anomaly_detection.audit_scope_candidate',HERE/'audit_scope_candidate.py')
candidate=importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)

class Rows:
    def __init__(self,items):self.items=items
    def fetchall(self):return self.items

class FakeRaw:
    def __init__(self,store):self.store=store
    def execute(self,sql,args=()):
        if sql.startswith('SELECT DISTINCT s.job_session,s.target_ns'):
            assert 'adp_source_windows sw' in sql and 's.source_kind' in sql and 's.state' in sql
            assert 'adp_facts' not in sql, 'fact lookup leaked back into candidate selection'
            assert sql.count('%s')==len(args),(sql.count('%s'),args)
            limit=args[-1]
            assertions=[]
            if 'AND (s.target_ns,s.job_session)<(%s,%s)' in sql:
                assertions=[(args[i],args[i+1]) for i in range(0,len(args)-1,2)]
            scopes=sorted(set(self.store.eligible),reverse=True)
            for cursor in assertions:scopes=[s for s in scopes if s<cursor]
            return Rows([{'target_ns':n,'job_session':s} for n,s in scopes[:limit]])
        if sql.startswith('SELECT f.request_key'):
            assert sql.count('%s')==len(args)
            key=(args[1],args[0]);due=key in self.store.due
            return Rows([{'request_key':'private_key'}] if due else [])
        raise AssertionError('Unexpected SQL: '+sql[:100])

class FakeStore:
    def __init__(self,eligible,due,primary=None):
        self.eligible=eligible;self.due=set(due)
        self.states={candidate.STATE:primary or {}}
        self.raw=FakeRaw(self)
        self.saved=[]
    def state(self,n):return self.states.get(n,{})
    def save_state(self,n,v):
        self.states[n]=dict(v)
        self.saved.append((n,dict(v)))

class CandidateTests(unittest.TestCase):
    def _cycle(self,store,clock=3000000000000000000,limit=1):
        for n in range(100):
            result=candidate.keys(store,clock,limit=limit)
            if result:return (n,result)
            if not store.state(candidate.WALK_STATE):return (n,[])
        self.fail('no result after 100 cycles')

    def test_source_sql_structure_exact_matching(self):
        # Source shape equivalence is checked before any on-server qualification.
        sys.path.insert(0,str(HERE))
        from P24_AD_P0_Split_Qualification import source_sql,split_statement
        ad=SOURCE_PROJECT/'AnomalyDetection'
        sql=source_sql(ad,{'session_key':'cursor','target_ns':1794045600000000000},now=1794120000000000000)
        for uid,src,args in sql:
            normal,params=split_statement(src,args)
            if not params:self.assertEqual(normal,candidate.SCOPE_SELECT)
            else:
                self.assertEqual(normal,candidate.SCOPE_SELECT.replace(candidate.SCOPE_ORDER,
                    'AND (s.target_ns,s.job_session)<(%s,%s) '+candidate.SCOPE_ORDER))
        self.assertEqual(len(sql),2)

    def test_complete_keyset_beyond_page(self):
        scopes=[(100000-i,f's{i:04d}') for i in range(250)]
        target=scopes[231]
        s=FakeStore(scopes+[scopes[8]]*3,{target})
        turns,out=self._cycle(s)
        self.assertEqual(out,['private_key'])
        self.assertEqual(s.state(candidate.STATE)['session_key'],target[1])
        self.assertEqual(s.state(candidate.STATE)['target_ns'],target[0])
        self.assertGreater(turns,5)
        self.assertEqual(s.state(candidate.WALK_STATE),{})

    def test_original_cursor_priority_before_wrap(self):
        scopes=[(10000-i,f's{i:04d}') for i in range(160)]
        after=scopes[30]
        below_due=scopes[105];above_due=scopes[5]
        s=FakeStore(scopes,{below_due,above_due},dict(target_ns=after[0],session_key=after[1],visit_until_ns=0))
        _,out=self._cycle(s)
        self.assertTrue(out)
        self.assertEqual(s.state(candidate.STATE)['target_ns'],below_due[0])
        self.assertEqual(s.state(candidate.STATE)['session_key'],below_due[1])

    def test_wrap_only_after_exhausted_lower_branch(self):
        scopes=[(10000-i,f's{i:04d}') for i in range(170)]
        after=scopes[30];due=scopes[5]
        s=FakeStore(scopes,{due},dict(target_ns=after[0],session_key=after[1],visit_until_ns=0))
        _,out=self._cycle(s)
        self.assertTrue(out)
        self.assertEqual(s.state(candidate.STATE)['target_ns'],due[0])

    def test_live_existing_visit_takes_priority(self):
        scopes=[(10000-i,f's{i:04d}') for i in range(70)]
        after=scopes[30]
        s=FakeStore(scopes,{after},dict(target_ns=after[0],session_key=after[1],visit_until_ns=9999999999999999999))
        before=len(s.saved)
        self.assertEqual(candidate.keys(s,1000000),['private_key'])
        self.assertEqual(len(s.saved),before)

    def test_no_due_exhausts_both_and_resets_cursor(self):
        scopes=[(10000-i,f's{i:04d}') for i in range(120)]
        after=scopes[15]
        s=FakeStore(scopes,set(),dict(target_ns=after[0],session_key=after[1],visit_until_ns=0))
        turns,result=self._cycle(s)
        self.assertFalse(result)
        self.assertGreater(turns,1)
        self.assertEqual(s.state(candidate.STATE),{})
        self.assertEqual(s.state(candidate.WALK_STATE),{})

    def test_partial_scan_does_not_clear_primary_cursor(self):
        scopes=[(10000-i,f's{i:04d}') for i in range(110)]
        after=scopes[5]
        original=dict(target_ns=after[0],session_key=after[1],visit_until_ns=0)
        s=FakeStore(scopes,set(),original)
        self.assertEqual(candidate.keys(s,3000000000000000000),[])
        self.assertEqual(s.state(candidate.STATE),original)
        self.assertNotEqual(s.state(candidate.WALK_STATE),{})

    def test_new_due_in_previously_visited_scope_revisited_after_lap(self):
        scopes=[(10000-i,f's{i:04d}') for i in range(60)]
        s=FakeStore(scopes,set())
        candidate.keys(s,3000000000000000000)
        # late evidence arrives at a scope already scanned by first call
        s.due.add(scopes[5])
        # Completing the current lap cannot retroactively revisit an earlier
        # scope. It must re-scan it on the NEXT lap (no permanent omission).
        turns,result=self._cycle(s,3000000000000000001)
        self.assertFalse(result)
        self.assertEqual(s.state(candidate.WALK_STATE),{})
        _,result=self._cycle(s,3000000000000000002)
        self.assertTrue(result)
        self.assertEqual(s.state(candidate.STATE)['target_ns'],scopes[5][0])
        self.assertGreaterEqual(turns,1)

    def test_changed_rotation_anchor_resets_continuation(self):
        scopes=[(10000-i,f's{i:04d}') for i in range(75)]
        s=FakeStore(scopes,set())
        candidate.keys(s,3000000000000000000)
        s.due.add(scopes[0])
        s.save_state(candidate.STATE,dict(target_ns=scopes[35][0],session_key=scopes[35][1],visit_until_ns=0))
        # New primary rotation differs from continuation: restart from it.
        _,res=self._cycle(s,3000000000000000001)
        self.assertTrue(res)
        self.assertEqual(s.state(candidate.STATE)['target_ns'],scopes[0][0])

    def test_timeout_does_not_advance_persistent_cursor(self):
        scopes=[(10000-i,f's{i:04d}') for i in range(45)]
        s=FakeStore(scopes,set())
        original=s.raw.execute
        def boom(sql,args=()):
            if sql.startswith('SELECT f.request_key'):raise TimeoutError('simulated statement timeout')
            return original(sql,args)
        s.raw.execute=boom
        with self.assertRaises(TimeoutError):candidate.keys(s,3000000000000000000)
        self.assertEqual(s.state(candidate.STATE),{})
        self.assertEqual(s.state(candidate.WALK_STATE),{})

    def test_many_random_exhaustive_oracle(self):
        rng=random.Random(20261108)
        for i in range(500):
            scopes=list({(rng.randrange(1000,11000),f's{rng.randrange(60):03d}') for _ in range(rng.randrange(1,100))})
            scopes.sort(reverse=True)
            due=set(rng.sample(scopes,rng.randrange(min(10,len(scopes))+1)))
            cursor=(rng.choice(scopes) if rng.choice((True,False)) else None)
            state=dict(target_ns=cursor[0],session_key=cursor[1],visit_until_ns=0) if cursor else {}
            s=FakeStore(scopes+scopes[:2],due,state)
            if cursor:
                ordered=[k for k in scopes if k<cursor]+scopes
            else:ordered=scopes
            expected=next((key for key in ordered if key in due),None)
            _,result=self._cycle(s)
            self.assertEqual(bool(result),expected is not None)
            if expected:
                self.assertEqual((s.state(candidate.STATE)['target_ns'],s.state(candidate.STATE)['session_key']),expected)
            else:
                self.assertFalse(s.state(candidate.STATE))

if __name__=='__main__':unittest.main(verbosity=2)
