"""Source-pinned scope variants in newly allocated qualification databases.

B1 removes payment reconstruction/outcomes but retains closure; B2 also removes
payment-group closure. C preserves canonical requests, execution semantics and
all typed payment relations while deferring materialized action/outcome views.
D retains ordinary version-aware evidence/metadata/provenance admission only.
"""
import ast
import inspect
import textwrap
import time
import types
from contextlib import contextmanager

from p24_foundation import viewer_online
from p24_foundation.viewer_data import ViewerDB as CanonicalDB,service_path
from viewer_performance.fast_writer import FastWriterDB,verify_sources
from .contracts import coverage,consumer_gate
from .identity import source_identity


def request_prefix():
    original=CanonicalDB._rebuild_requests
    tree=ast.parse(textwrap.dedent(inspect.getsource(original)));node=tree.body[0]
    positions=[i for i,s in enumerate(node.body) if isinstance(s,ast.Expr)
        and isinstance(s.value,ast.Call) and isinstance(s.value.func,ast.Attribute)
        and s.value.func.attr=='progress' and s.value.args
        and isinstance(s.value.args[0],ast.Constant) and s.value.args[0].value=='rebuild_payment_index']
    if len(positions)!=1:raise ValueError('screen_request_prefix_source_changed')
    node.body=node.body[:positions[0]]+ast.parse('''
self._screen_roles(catalog,sql_requests)
if not scoped and self.semantic_checkpoint():
    self.sql("UPDATE viewer_semantic_checkpoint SET state='stale' WHERE id=1")
self._active_projection_scope=False
if commit:self.conn.commit()
return {'recomputed_requests':len(set(request_keys)) if scoped else len(sql_requests)}
''').body
    namespace=dict(original.__globals__)
    exec(compile(ast.fix_missing_locations(tree),'<verified-financial-request-prefix>','exec'),namespace)
    return namespace[node.name]


def role_reader(method):
    original=inspect.unwrap(method);tree=ast.parse(textwrap.dedent(inspect.getsource(original)))
    class Replace(ast.NodeTransformer):
        count=0
        def visit_Constant(self,node):
            if isinstance(node.value,str) and 'viewer_actions' in node.value:
                self.count+=node.value.count('viewer_actions');node.value=node.value.replace('viewer_actions','fs_semantic_roles')
            return node
    change=Replace();tree=change.visit(tree)
    if change.count!=1:raise ValueError('screen_semantic_reader_source_changed')
    namespace=dict(original.__globals__)
    exec(compile(ast.fix_missing_locations(tree),'<verified-financial-role-reader>','exec'),namespace)
    return namespace[tree.body[0].name]


class ScreenDB(FastWriterDB):
    def __init__(self,*,mode='A',**kwargs):
        name=str((kwargs.get('config') or {}).get('dbname',''))
        if not (name.startswith('p24_design_capacity_fs_') and name.endswith('_qualification')):
            raise ValueError('financial_screen_requires_new_owned_database')
        verify_sources();self.mode=mode;self.output_contract=coverage(mode);self.scope_identity=source_identity()
        self.screen_counts=dict(closure_calls=0,closure_input_requests=0,closure_output_requests=0,
            rebuilt_requests=0,request_rebuild_calls=0,omitted_link_rows=0,minimal_role_rows=0,
            contract_bodies_read=0,contract_batches=0)
        self.closure_seconds=0.
        self._prefix=request_prefix() if mode=='C' else None
        self._role_batch=role_reader(CanonicalDB._read_semantic_batch) if mode=='C' else None
        self._role_bootstrap=role_reader(CanonicalDB._semantic_bootstrap_batches) if mode=='C' else None
        super().__init__(**kwargs)
        self.sql("SELECT set_config('application_name',?,false)",('P24.FinancialScreen.'+mode,))

    def before_commit(self):
        if source_identity()!=self.scope_identity:raise ValueError('financial_screen_source_changed')
        return super().before_commit()

    def init(self):
        super().init()
        self.sql('CREATE TABLE IF NOT EXISTS fs_output_contract(feature TEXT PRIMARY KEY,state TEXT NOT NULL)')
        for feature,state in self.output_contract.items():
            self.sql('INSERT INTO fs_output_contract VALUES(?,?) ON CONFLICT(feature) DO UPDATE SET state=excluded.state',(feature,state))
        self.conn.commit()

    def require_output(self,feature):consumer_gate(self.output_contract,feature)

    def _ingest_insert(self,table,values):
        if self.mode=='D' and table=='viewer_links':self.screen_counts['omitted_link_rows']+=1;return
        return super()._ingest_insert(table,values)

    def _screen_roles(self,catalog,rows):
        self.sql('CREATE TEMP TABLE IF NOT EXISTS fs_semantic_roles(action_key TEXT PRIMARY KEY,category TEXT,initiation TEXT) ON COMMIT DROP')
        self.sql('TRUNCATE fs_semantic_roles')
        values=[(r['request_key'],catalog[service_path(r['root_call'])]['role'],catalog[service_path(r['root_call'])]['initiation'])
            for r in rows if not r['conflicted']]
        self.many('INSERT INTO fs_semantic_roles VALUES(?,?,?)',values)
        self.screen_counts['minimal_role_rows']+=len(values)

    def _rebuild_requests(self,*,request_keys=None,commit=True):
        if self.mode=='D':return dict(status='NOT_EVALUATED',recomputed_requests=0)
        self.screen_counts['request_rebuild_calls']+=1
        result=(self._prefix(self,request_keys=request_keys,commit=commit) if self.mode=='C'
            else super()._rebuild_requests(request_keys=request_keys,commit=commit))
        self.screen_counts['rebuilt_requests']+=(len(set(request_keys)) if request_keys is not None
            else self.one('SELECT COUNT(*) AS n FROM viewer_requests')['n'])
        return result

    @contextmanager
    def contract_event_batches(self,**kwargs):
        with super().contract_event_batches(**kwargs) as batches:
            def counted():
                for batch in batches:
                    self.screen_counts['contract_batches']+=1
                    self.screen_counts['contract_bodies_read']+=len(batch)
                    yield batch
            yield counted()

    def rebuild_payment_contract(self,**kwargs):
        if self.mode in ('B1','B2','D'):return dict(status='NOT_EVALUATED')
        return super().rebuild_payment_contract(**kwargs)

    def _reconcile_payment_outcomes(self):
        if self.mode in ('B1','B2','C','D'):return
        return super()._reconcile_payment_outcomes()

    def build_semantic_index(self,**kwargs):
        if self.mode=='D':
            self.init_semantic_index(commit=False)
            self.sql("INSERT INTO viewer_semantic_checkpoint VALUES(1,0,?,0,'screen_disabled') ON CONFLICT(id) DO UPDATE SET state='screen_disabled'",(viewer_online.iso(viewer_online.now_ns()),))
            return dict(status='NOT_EVALUATED')
        return super().build_semantic_index(**kwargs)

    def reconcile_semantic_requests(self,*args,**kwargs):
        if self.mode=='D':return dict(status='NOT_EVALUATED')
        return super().reconcile_semantic_requests(*args,**kwargs)

    def _read_semantic_batch(self,*args,**kwargs):
        return self._role_batch(self,*args,**kwargs) if self.mode=='C' else super()._read_semantic_batch(*args,**kwargs)

    def _semantic_bootstrap_batches(self,*args,**kwargs):
        return self._role_bootstrap(self,*args,**kwargs) if self.mode=='C' else super()._semantic_bootstrap_batches(*args,**kwargs)

    def payment_contract_card(self,*args,**kwargs):
        self.require_output('typed_payment_graph');return super().payment_contract_card(*args,**kwargs)


def publisher(db,trace=None):
    original=viewer_online.publish_capture
    def closure(database,keys):
        began=time.perf_counter();count=len(set(keys));database.screen_counts['closure_calls']+=1
        database.screen_counts['closure_input_requests']+=count
        try:
            result=set(keys) if database.mode in ('B2','D') else viewer_online.affected_closure(database,keys)
            database.screen_counts['closure_output_requests']+=len(result);return result
        finally:database.closure_seconds+=time.perf_counter()-began
    def traced_closure(database,keys):
        if trace:
            with trace.span('method:dependency_closure'):return closure(database,keys)
        return closure(database,keys)
    def verified(*args,**kwargs):
        if trace:
            with trace.span('capture:verify_and_decode'):return viewer_online._read_verified_capture(*args,**kwargs)
        return viewer_online._read_verified_capture(*args,**kwargs)
    namespace=dict(original.__globals__,affected_closure=traced_closure,_read_verified_capture=verified)
    function=types.FunctionType(original.__code__,namespace,original.__name__,original.__defaults__,original.__closure__)
    function.__kwdefaults__=original.__kwdefaults__
    def publish(path,start,end,*,mode='forward',fault=None):
        def mark(stage):
            if stage=='before_commit':
                db.sql("UPDATE viewer_live_state SET worker_status='SCOPE_SCREEN_ONLY' WHERE id=1")
            if fault:fault(stage)
        result=function(db,path,start,end,mode=mode,fault=mark)
        result.update(status='SCREEN_REFERENCE_COMMITTED' if db.mode=='A' else 'SCREEN_DIAGNOSTIC_COMMITTED',
            scope_mode=db.mode,output_contract=db.output_contract,full_analysis_ready=False,
            financial_detectors_executed=False)
        return result
    return publish
