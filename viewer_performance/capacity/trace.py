"""Instance-local wall/CPU attribution, including fetch, COPY and commit.

Unlike the V5 execute-only trace, nested spans have exclusive as well as
inclusive times. Do not add inclusive method times to SQL/COPY child times.
Only fingerprints and fixed structural classifications leave the process.
"""
from __future__ import annotations

from collections import defaultdict
from contextlib import contextmanager
from functools import lru_cache, wraps
import hashlib
import re
import time


METHODS = ('ingest', '_merge_ingest_stages', '_prepare_projection_events',
    '_prepare_projection_inputs', 'rebuild', 'rebuild_payment_contract',
    'reconcile_semantic_requests', '_publish_projection_delta',
    '_publish_finalized_projection')
LITERALS = re.compile(r"'(?:''|[^'])*'|\b\d+(?:\.\d+)?\b")
RELATIONS = re.compile(r'\bviewer_[a-z][a-z0-9_]*\b', re.I)
OPERATIONS = re.compile(r'^\s*(SELECT|INSERT|UPDATE|DELETE|WITH|COPY|CREATE|ALTER|DROP|ANALYZE|TRUNCATE|SET)\b', re.I)


@lru_cache(maxsize=1024)
def signature(statement):
    normalized = ' '.join(LITERALS.sub('?', str(statement)).split()).lower()
    operation = OPERATIONS.match(normalized)
    return (hashlib.sha256(normalized.encode()).hexdigest()[:16],
        operation[1].upper() if operation else 'OTHER',
        tuple(sorted(set(RELATIONS.findall(normalized))))[:8])


class Trace:
    def __init__(self, *, clock=time.perf_counter_ns, cpu=time.process_time_ns):
        self.clock = clock
        self.cpu = cpu
        self.stack = []
        self.spans = defaultdict(lambda: dict(calls=0, inclusive_ns=0, exclusive_ns=0,
            client_cpu_ns=0, failures=0, max_ns=0))
        self.sql = {}
        self.db = None
        self.before_commit = None

    @contextmanager
    def span(self, name, statement=None):
        frame = dict(start=self.clock(), cpu=self.cpu(), children=0)
        self.stack.append(frame)
        failed = False
        try:
            yield
        except BaseException:
            failed = True
            raise
        finally:
            elapsed = self.clock() - frame['start']
            cpu = self.cpu() - frame['cpu']
            self.stack.pop()
            if self.stack:
                self.stack[-1]['children'] += elapsed
            entry = self.spans[name]
            entry['calls'] += 1
            entry['inclusive_ns'] += elapsed
            entry['exclusive_ns'] += max(0, elapsed - frame['children'])
            entry['client_cpu_ns'] += cpu
            entry['failures'] += int(failed)
            entry['max_ns'] = max(entry['max_ns'], elapsed)
            if statement is not None:
                fp, operation, relations = signature(statement)
                # Bounded diagnostics even if the driver sees variable SQL shapes.
                key = (name, fp) if len(self.sql) < 2048 or (name, fp) in self.sql else (name, 'overflow')
                row = self.sql.setdefault(key, dict(operation=operation if key[1] != 'overflow' else 'OTHER',
                    relations=list(relations) if key[1] != 'overflow' else [], calls=0, ns=0, failures=0))
                row['calls'] += 1
                row['ns'] += elapsed
                row['failures'] += int(failed)

    def attach(self, db):
        if self.db is not None:
            raise ValueError('trace_already_attached')
        if not db.sqlite:
            name = db.conn.info.dbname
            if not (name.startswith('p24_design_capacity_') and name.endswith('_qualification')):
                raise ValueError('capacity_trace_requires_own_qualification_database')
        self.db = db
        self.original_conn = db.conn
        self.originals = {}
        db.conn = Connection(self.original_conn, self)
        for name in METHODS:
            original = getattr(db, name, None)
            if original is None:
                continue
            self.originals[name] = (name in db.__dict__, original)
            def wrap(method, label):
                @wraps(method)
                def run(*args, **kwargs):
                    with self.span('method:' + label):
                        return method(*args, **kwargs)
                return run
            setattr(db, name, wrap(original, name))
        return self

    def detach(self):
        if self.db is None:
            return
        self.db.conn = self.original_conn
        for name, (was_instance, original) in self.originals.items():
            if was_instance:
                setattr(self.db, name, original)
            else:
                delattr(self.db, name)
        self.db = None

    def report(self):
        rows = {name: {**{k: v for k, v in entry.items() if not k.endswith('_ns')},
            **{k.removesuffix('_ns') + '_seconds': round(v / 1e9, 6)
               for k, v in entry.items() if k.endswith('_ns')}} for name, entry in self.spans.items()}
        return dict(spans=rows, sql=sorted([dict(kind=kind, fingerprint=fp,
            **{k:v for k,v in entry.items() if k != 'ns'}, seconds=round(entry['ns'] / 1e9, 6))
            for (kind, fp), entry in self.sql.items()], key=lambda x: -x['seconds']),
            exclusive_times_are_additive=True, inclusive_times_are_not_additive=True,
            client_cpu_is_not_postgresql_cpu=True,
            sql_rowcounts_are_not_committed_logical_request_counts=True,
            limitations=['Instrumentation overhead is included; compare uninstrumented trials separately.',
                'COPY includes driver serialization, streaming and final acknowledgement.',
                'Fetch timings include driver decoding; client CPU is measured separately.',
                'This trace does not measure Elasticsearch download or actual AD evaluation.'])


class Connection:
    def __init__(self, raw, trace):
        self.raw = raw
        self.trace = trace

    def __getattr__(self, name):
        return getattr(self.raw, name)

    def execute(self, statement, *args, **kwargs):
        with self.trace.span('driver:execute', statement):
            cursor = self.raw.execute(statement, *args, **kwargs)
        return Cursor(cursor, self.trace)

    def cursor(self, *args, **kwargs):
        return Cursor(self.raw.cursor(*args, **kwargs), self.trace)

    def commit(self):
        if self.trace.before_commit:
            with self.trace.span('measurement:counters'):
                self.trace.before_commit(self.raw)
        with self.trace.span('driver:commit'):
            return self.raw.commit()

    def rollback(self):
        with self.trace.span('driver:rollback'):
            return self.raw.rollback()


class Cursor:
    def __init__(self, raw, trace):
        self.raw = raw
        self.trace = trace

    def __getattr__(self, name):
        return getattr(self.raw, name)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.raw.close()

    def execute(self, statement, *args, **kwargs):
        with self.trace.span('driver:execute', statement):
            self.raw.execute(statement, *args, **kwargs)
        return self

    def executemany(self, statement, *args, **kwargs):
        with self.trace.span('driver:executemany', statement):
            self.raw.executemany(statement, *args, **kwargs)
        return self

    def fetchone(self):
        with self.trace.span('driver:fetch'):
            return self.raw.fetchone()

    def fetchall(self):
        with self.trace.span('driver:fetch'):
            return self.raw.fetchall()

    def fetchmany(self, *args, **kwargs):
        with self.trace.span('driver:fetch'):
            return self.raw.fetchmany(*args, **kwargs)

    def __iter__(self):
        iterator = iter(self.raw)
        while True:
            with self.trace.span('driver:fetch'):
                try:
                    row = next(iterator)
                except StopIteration:
                    return
            yield row

    @contextmanager
    def copy(self, statement, *args, **kwargs):
        with self.trace.span('driver:copy', statement):
            with self.raw.copy(statement, *args, **kwargs) as copy:
                yield copy
