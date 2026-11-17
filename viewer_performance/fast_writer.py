"""Opt-in C2/C3 writer with an independently verified implementation identity.

The canonical Viewer source contract is unchanged. This entrypoint uses the
reviewed one-body-read and exact TEMP-key implementations; no membership
filter, read-ahead, time limit or evidence omission is enabled.
"""
from contextlib import contextmanager
import hashlib
import importlib
import json
from pathlib import Path
import time

from p24_foundation.viewer_data import ViewerDB as CanonicalDB
from p24_foundation.viewer_runtime import runtime_source_digest
from viewer_performance.capacity.local_projection_keys import LocalProjectionKeysDB

BUILD = 'VIEWER-20261117-C2C3-OBSERVED'
BASE_RUNTIME = 'b7273437ea42c1aea7d0183c3020be133c84dba5735c68a01a6fd81a4b56d7c8'
ROOT = Path(__file__).resolve().parents[1]
MANIFEST = 'viewer_performance/FAST_WRITER_MANIFEST.json'


class FastWriterHalt(SystemExit):
    """Stop reconnect loops when the verified implementation changes."""
    def __init__(self):
        super().__init__(2)


def verify_sources(root=ROOT):
    root = Path(root).resolve()
    manifest = json.loads((root / MANIFEST).read_text(encoding='utf-8'))
    if manifest.get('build_id') != BUILD or manifest.get('base_runtime_source_sha256') != BASE_RUNTIME:
        raise ValueError('fast_writer_wrong_manifest')
    entries = manifest.get('files_sha256', {})
    required = {'viewer_performance/fast_writer.py', 'viewer_performance/Run_Viewer_Fast.py',
                'viewer_performance/Qualify_Viewer_Fast.py',
                'tests/test_viewer_fast_writer.py',
                'viewer_performance/writer_identity.py',
                'viewer_performance/Observe_Viewer_Fast.py',
                'tests/test_viewer_writer_identity.py',
                'viewer_performance/Run_Viewer_Index_Probe_UTF8.py',
                'AnomalyDetection/validation/observe_viewer_live.py',
                *(f'viewer_performance/{name}.py' for name in ('Run_Viewer_Catchup',
                    'Run_Viewer_Memory','Run_Viewer_Web','history_replay','Qualify_Capacity_Candidate')),
                *(path.relative_to(root).as_posix() for path in
                    (root/'viewer_performance/capacity').glob('*.py'))}
    if required != entries.keys():
        raise ValueError('fast_writer_incomplete_manifest')
    digest = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if digest != manifest.get('source_sha256'):
        raise ValueError('fast_writer_manifest_digest_mismatch')
    for name, expected in entries.items():
        path = (root / name).resolve()
        if not path.is_relative_to(root) or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('fast_writer_source_changed')
    if runtime_source_digest(root) != BASE_RUNTIME:
        raise ValueError('fast_writer_base_runtime_changed')
    return digest


class FencedConnection:
    """Verify the exact implementation before acknowledging any commit."""
    def __init__(self, connection, verify, report_commit=lambda seconds:None):
        object.__setattr__(self, '_connection', connection)
        object.__setattr__(self, '_verify', verify)
        object.__setattr__(self, '_report_commit', report_commit)

    def __getattr__(self, name):
        return getattr(self._connection, name)

    def __setattr__(self, name, value):
        setattr(self._connection, name, value)

    def commit(self):
        began=time.perf_counter()
        try:
            self._verify()
            return self._connection.commit()
        finally:self._report_commit(time.perf_counter()-began)

    @contextmanager
    def transaction(self, *args, **kwargs):
        with self._connection.transaction(*args, **kwargs) as transaction:
            yield transaction
            self._verify()


class FastWriterDB(LocalProjectionKeysDB):
    """Same data contract; explicitly selected only by the trial launcher."""
    def __init__(self, *, sqlite_path=None, config=None, keys_path):
        if sqlite_path is not None:
            raise ValueError('fast_writer_requires_native_postgresql')
        config = dict(config or {})
        name = str(config.get('dbname', ''))
        qualification = name.startswith('p24_design_capacity_') and name.endswith('_qualification')
        if name != 'p24_design_viewer' and not qualification:
            raise ValueError('fast_writer_database_not_allowed')
        if str(config.get('host', 'localhost')).lower() not in ('localhost', '127.0.0.1', '::1'):
            raise ValueError('fast_writer_requires_local_server')
        try:
            self.fast_source_sha256 = verify_sources()
        except (OSError, ValueError):
            raise FastWriterHalt() from None
        # The candidate superclass constructor deliberately permits only its
        # disposable databases. This explicit product entrypoint initializes
        # the canonical connection, then reuses its unchanged reviewed methods.
        from viewer_performance.writer_identity import WriterIdentity
        self.writer_identity=WriterIdentity(ROOT,build=BUILD,source=self.fast_source_sha256,runtime=BASE_RUNTIME,
            enabled=not qualification)
        config['application_name']=self.writer_identity.app
        CanonicalDB.__init__(self, config=config, keys_path=keys_path)
        self.fetch_once_stats = dict(scoped_calls=0, metadata_rows=0, body_pair_lookups=0,
            returned_bodies=0, missing_bodies=0, nonunique_bodies=0)
        self.local_key_queries = 0
        self._capacity_writes={}
        self._capacity_commit_seconds=0.
        self.conn = FencedConnection(self.conn, self.before_commit,self.record_commit)

    def record_commit(self,seconds):
        self._capacity_commit_seconds+=seconds

    def before_commit(self):
        self.verify_implementation()
        self.writer_identity.bind_if_owner(self.conn._connection)

    def _measure_write(self,table,operation):
        began=time.perf_counter()
        try:return operation()
        finally:
            item=self._capacity_writes.setdefault(table,dict(calls=0,seconds=0.))
            item['calls']+=1;item['seconds']+=time.perf_counter()-began

    def _copy_ingest_stage_into_table(self,stage,table,columns,order):
        return self._measure_write(table,lambda:super(FastWriterDB,self)._copy_ingest_stage_into_table(stage,table,columns,order))

    def _insert_ingest_stage_into_table(self,stage,table,columns,order,conflict=''):
        return self._measure_write(table,lambda:super(FastWriterDB,self)._insert_ingest_stage_into_table(stage,table,columns,order,conflict))

    def verify_implementation(self):
        try:
            if verify_sources() != self.fast_source_sha256:
                raise ValueError('fast_writer_release_changed')
        except (OSError, ValueError):
            raise FastWriterHalt() from None

    def prepare_candidate(self):
        self.verify_implementation()
        return dict(status='READY', no_build_or_migration=True,
            implementation_build=BUILD, implementation_source_sha256=self.fast_source_sha256,
            canonical_runtime_source_sha256=BASE_RUNTIME)

    def candidate_report(self):
        report = super().candidate_report()
        report.update(production_enabled=True, production_accepted=False,
            implementation_build=BUILD, implementation_source_sha256=self.fast_source_sha256,
            canonical_runtime_source_sha256=BASE_RUNTIME, schema_migration=False,
            between_commit_cache=False, parallel_readers=0)
        return report


@contextmanager
def activate():
    """Replace the DB factory only inside this explicitly invoked process.

    Existing web/AD processes are independent. history_replay imports the
    factory inside run(); the standard live runner may already be imported.
    Both orders are covered and every original binding is restored on exit.
    """
    verify_sources()
    data = importlib.import_module('p24_foundation.viewer_data')
    runner = importlib.import_module('tools.run_behavior_viewer')
    online = importlib.import_module('p24_foundation.viewer_online')
    history = importlib.import_module('viewer_performance.history_replay')
    from viewer_performance.writer_identity import measured_publication
    publication=online.publish_capture
    historical_publication=history.publish_capture
    modules = (data, runner)
    previous = [(module, module.ViewerDB) for module in modules]
    if any(factory is not CanonicalDB for _, factory in previous):
        raise ValueError('fast_writer_factory_already_changed')
    try:
        for module, _ in previous:
            module.ViewerDB = FastWriterDB
        online.publish_capture=measured_publication(publication)
        history.publish_capture=online.publish_capture
        yield
    finally:
        for module, original in previous:
            module.ViewerDB = original
        online.publish_capture=publication
        history.publish_capture=historical_publication
