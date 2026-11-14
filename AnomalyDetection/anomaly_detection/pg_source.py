"""One bounded PostgreSQL projection read. No Viewer DB initialization, DDL or worker."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import time
from contextlib import contextmanager
from contextvars import ContextVar

from . import SOURCE_SHA, CATALOG_SHA, SEMANTIC_SCHEMA, CONTRACT
from .snapshot import Snapshot, ContractError, api_path, require, MAX_ROWS
from .source_profiles import SUPPORTED_RUNTIMES,r31_overlay_allowed,r32_release_allowed,r33_release_allowed,r34_release_allowed,r35_release_allowed,r36_release_allowed,r37_release_allowed

DEFAULT_SAMPLE = 32
MAX_SAMPLE = 64
READ_OPTIONS = ("-c default_transaction_read_only=on -c statement_timeout=3000 "
                "-c lock_timeout=750 -c idle_in_transaction_session_timeout=5000")
APP_NAME = "AnomalyDetection.A1.snapshot"
_READ_POLICY=ContextVar('anomaly_source_read_policy',default=None)


@contextmanager
def online_read_budget():
    token=_READ_POLICY.set({'statement_ms':500,'total_seconds':1,'actor_page_limit':128})
    try: yield
    finally: _READ_POLICY.reset(token)


@contextmanager
def product_read_budget():
    token=_READ_POLICY.set({'statement_ms':1000,'total_seconds':3,'actor_page_limit':128})
    try:yield
    finally:_READ_POLICY.reset(token)


def read_limits():
    return _READ_POLICY.get() or {'statement_ms':3000,'total_seconds':8,'actor_page_limit':32}


def installed_source_identity(project):
    """Same byte-digest definition as the accepted Viewer, without importing it."""
    project = Path(project).resolve()
    manifest = json.loads((project / "RELEASE_MANIFEST.json").read_text(encoding="utf-8-sig"))
    declared=manifest.get("runtime_source_sha256")
    require(declared in SUPPORTED_RUNTIMES, "SOURCE_MANIFEST_VERSION_MISMATCH")
    value = hashlib.sha256()
    count = 0
    for folder in ("p24_foundation", "tools", "review_ui", "catalogs"):
        for path in sorted((project / folder).rglob("*")):
            if path.is_file() and path.suffix in (".py", ".html", ".css", ".js", ".json", ".csv") and "__pycache__" not in path.parts:
                require(path.resolve().is_relative_to(project), "SOURCE_MEMBER_OUTSIDE_PROJECT")
                value.update(path.relative_to(project).as_posix().encode() + b"\0")
                value.update(hashlib.sha256(path.read_bytes()).digest())
                count += 1
    actual=value.hexdigest();viewer=project/'p24_foundation/viewer_data.py'
    overlay=r31_overlay_allowed(declared,actual,count,hashlib.sha256(viewer.read_bytes()).hexdigest() if viewer.is_file() else None)
    require(count > 0 and (declared==SOURCE_SHA and actual==SOURCE_SHA or overlay or
        r32_release_allowed(declared,actual,count) or r33_release_allowed(declared,actual,count) or r34_release_allowed(declared,actual,count) or r35_release_allowed(declared,actual,count) or r36_release_allowed(declared,actual,count) or r37_release_allowed(declared,actual,count)), "SOURCE_INSTALLED_BYTES_MISMATCH")
    return {"runtime_sha256": value.hexdigest(), "checked_runtime_files": count}


def read_database_config(path):
    """Read data assignments only; never execute the private configuration file.

    Supports literal dictionaries, preceding literal constants, and dict(...).
    Unsupported executable config is reported without exposing its contents.
    """
    try:
        tree = ast.parse(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, SyntaxError, UnicodeError) as exc:
        raise ContractError("CONFIG_UNREADABLE") from exc
    constants = {}

    def evaluate(node):
        if isinstance(node, ast.Name) and node.id in constants:
            return constants[node.id]
        if isinstance(node, ast.Dict):
            require(all(key is not None for key in node.keys), "CONFIG_UNSUPPORTED_EXPRESSION")
            return {evaluate(key): evaluate(value) for key, value in zip(node.keys, node.values)}
        if isinstance(node, (ast.List, ast.Tuple)):
            return [evaluate(item) for item in node.elts]
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dict" and not node.args:
            require(all(item.arg for item in node.keywords), "CONFIG_UNSUPPORTED_EXPRESSION")
            return {item.arg: evaluate(item.value) for item in node.keywords}
        return ast.literal_eval(node)

    for statement in tree.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        for target in targets:
            if not isinstance(target, ast.Name) or statement.value is None:
                continue
            try:
                constants[target.id] = evaluate(statement.value)
            except (ValueError, TypeError, ContractError):
                if target.id == "DATABASE":
                    raise ContractError("CONFIG_DATABASE_MUST_BE_DATA_ASSIGNMENT") from None
    database = constants.get("DATABASE")
    require(isinstance(database, dict) and all(isinstance(key, str) for key in database), "CONFIG_DATABASE_MISSING")
    require(database.get("dbname") == "p24_design_viewer", "ONLY_P24_DESIGN_VIEWER_ALLOWED")
    return database


def connection_parameters(database):
    result = dict(database)
    require(result.get("dbname") == "p24_design_viewer", "ONLY_P24_DESIGN_VIEWER_ALLOWED")
    for key in ("autocommit", "row_factory", "options", "application_name"):
        result.pop(key, None)
    options=READ_OPTIONS
    if _READ_POLICY.get():
        policy=read_limits()
        options=(f"-c default_transaction_read_only=on -c statement_timeout={policy['statement_ms']} -c lock_timeout=100 "
            f"-c idle_in_transaction_session_timeout={int(policy['total_seconds']*1000)} -c max_parallel_workers_per_gather=0 "
            '-c work_mem=2MB -c jit=off')
    result.update(connect_timeout=3, options=options, application_name=APP_NAME)
    return result


class BudgetQuery:
    def __init__(self, connection, *, budget_seconds=None, project=None):
        self.connection = connection
        self.project = Path(project).resolve() if project is not None else None
        self._origin_module = None
        self._binary_origin_keys = None
        policy=read_limits()
        self.statement_ms=policy['statement_ms']
        self.deadline = time.monotonic() + (policy['total_seconds'] if budget_seconds is None else min(policy['total_seconds'],budget_seconds))
        self.metrics = []

    def origin_keys_active(self):
        if self._binary_origin_keys is not None:return self._binary_origin_keys
        self._binary_origin_keys=False
        if self.project is None or not (self.project/'p24_foundation/viewer_origin_storage.py').is_file():return False
        import sys
        from types import SimpleNamespace
        if str(self.project) not in sys.path:sys.path.insert(0,str(self.project))
        from p24_foundation import viewer_origin_storage as origin
        require(Path(origin.__file__).resolve().is_relative_to(self.project),'VIEWER_READMODEL_FROM_DIFFERENT_INSTALLATION')
        def one(sql):
            remaining=int((self.deadline-time.monotonic())*1000)
            require(remaining>0,'SOURCE_TOTAL_READ_BUDGET_EXCEEDED')
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT set_config('statement_timeout', %s, true)",(str(min(self.statement_ms,remaining)),))
                cursor.execute(sql)
                return cursor.fetchone()
        self._binary_origin_keys=origin.active(SimpleNamespace(sqlite=False,one=one))
        self._origin_module=origin
        return self._binary_origin_keys

    def __call__(self, sql, parameters=(), *, cap=MAX_ROWS):
        require(sql.lstrip().upper().startswith("SELECT "), "NON_SELECT_QUERY_REJECTED")
        if self.project is not None and self.origin_keys_active() and self._origin_module.needs_qualification(sql):
            sql=self._origin_module.qualify(sql)
        remaining_ms = int((self.deadline - time.monotonic()) * 1000)
        require(remaining_ms > 0, "SOURCE_TOTAL_READ_BUDGET_EXCEEDED")
        started = time.monotonic()
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT set_config('statement_timeout', %s, true)", (str(min(self.statement_ms, remaining_ms)),))
                cursor.execute(sql + " LIMIT %s", (*parameters, cap + 1))
                rows = [dict(row) for row in cursor.fetchall()]
        except Exception as exc:
            self.metrics.append({'query':len(self.metrics)+1,'rows':None,'failed':True,
                'elapsed_seconds':round(time.monotonic()-started,4),'sqlstate':getattr(exc,'sqlstate',None)})
            raise
        require(len(rows) <= cap, "SOURCE_ROW_BUDGET_EXCEEDED")
        self.metrics.append({"query": len(self.metrics) + 1, "rows": len(rows),
                             "elapsed_seconds": round(time.monotonic() - started, 4)})
        return rows


def collect_sample(query, *, runtime_sha256, sample_limit=DEFAULT_SAMPLE, captured_at_ns=None,request_keys=None,coverage_window_ns=None):
    """All queries must share one short REPEATABLE READ / READ ONLY transaction."""
    require(type(sample_limit) is int and 1 <= sample_limit <= MAX_SAMPLE, "INVALID_SAMPLE_LIMIT")
    guard = query("SELECT current_database() AS database, current_setting('transaction_read_only') AS read_only, "
                  "current_setting('transaction_isolation') AS isolation", cap=1)
    require(len(guard) == 1 and guard[0]["database"] == "p24_design_viewer" and
            guard[0]["read_only"] == "on" and guard[0]["isolation"] == "repeatable read", "SOURCE_TRANSACTION_NOT_READ_ONLY_REPEATABLE_READ")
    live = query("SELECT generation,stream_key,keys_fingerprint,next_ns FROM public.viewer_live_state WHERE id=1", cap=1)
    semantic = query("SELECT generation,state FROM public.viewer_semantic_checkpoint WHERE id=1", cap=1)
    catalog = query("SELECT fingerprint FROM public.viewer_service_catalog_state WHERE id=1", cap=1)
    require(bool(live and semantic and catalog), "SOURCE_METADATA_MISSING")
    require(semantic[0]["state"] == "ready", "SOURCE_SEMANTIC_NOT_READY")
    require(catalog[0]["fingerprint"] == CATALOG_SHA, "SOURCE_CATALOG_UPDATE_PENDING")
    if request_keys is None:
        selected = query("SELECT request_key FROM (SELECT request_key FROM public.viewer_semantic_occurrences "
                         "WHERE state='active' AND anchor_ns>0 AND anchor_ns<%s "
                         "ORDER BY anchor_ns DESC,request_key DESC LIMIT %s) AS selected_sample",
                         (live[0]["next_ns"], sample_limit), cap=sample_limit)
    else:
        from .snapshot import KEY
        require(isinstance(request_keys,list) and 1<=len(request_keys)<=sample_limit and request_keys==sorted(set(request_keys)) and
            all(isinstance(key,str) and KEY.fullmatch(key) for key in request_keys),"INVALID_EXPLICIT_REQUEST_SCOPE")
        selected=[{"request_key":key} for key in request_keys]
    # Selecting exactly the requested number is a sample, not truncation of a
    # claimed complete population. BudgetQuery fetches cap+1 to detect truncation;
    # the selection itself therefore explicitly limits its inner query.
    keys = sorted(row["request_key"] for row in selected)
    require(bool(keys), "NO_ACTIVE_ANCHORS_IN_SAMPLE")

    def scoped(table, columns="*"):
        rows = []
        for begin in range(0, len(keys), 200):
            batch = keys[begin:begin + 200]
            rows.extend(query("SELECT " + columns + " FROM public." + table + " WHERE request_key IN (" +
                              ",".join("%s" for _ in batch) + ")", batch))
            require(len(rows) <= MAX_ROWS, "SOURCE_ROW_BUDGET_EXCEEDED")
        return rows

    tables = {name: scoped(name) for name in ("viewer_semantic_occurrences", "viewer_requests",
                                              "viewer_contract_observations", "viewer_contract_edges")}
    tables["viewer_contract_identifiers"] = scoped("viewer_contract_identifiers",
        "origin_key,version_key,request_key,issuer,kind,scope,field_path,identity_key")
    initial_events = scoped("viewer_events", "origin_key,version_key,request_key,at_ns,callpath")
    origins = {row["origin_key"] for row in initial_events}
    origins.update(row["origin_key"] for row in tables["viewer_contract_observations"])
    origins.update(row["origin_key"] for row in tables["viewer_contract_identifiers"])
    origins.update(row["evidence_origin"] for row in tables["viewer_contract_edges"])
    require(len(origins) <= MAX_ROWS, "SOURCE_ORIGIN_BUDGET_EXCEEDED")
    events = []
    ordered_origins = sorted(origins)
    for begin in range(0, len(ordered_origins), 200):
        batch = ordered_origins[begin:begin + 200]
        origin_column='e.origin_key';origin_parameter='%s'
        if getattr(query,'origin_keys_active',lambda:False)():
            origin_column=query._origin_module.key_sql(origin_column)
            origin_parameter=query._origin_module.key_sql(origin_parameter)
        events.extend(query("SELECT e.origin_key,e.version_key,e.request_key,e.at_ns,e.callpath, "
            "EXISTS(SELECT 1 FROM public.viewer_raw_events r WHERE r.origin_key=e.origin_key AND r.version_key=e.version_key) AS raw_available "
            "FROM public.viewer_events e WHERE "+origin_column+" IN (" + ",".join(origin_parameter for _ in batch) + ")", batch))
        require(len(events) <= MAX_ROWS, "SOURCE_VERSION_BUDGET_EXCEEDED")
    for row in events:
        row["raw_available"] = bool(row["raw_available"])
    tables["viewer_events"] = events
    services = sorted({path for row in tables["viewer_semantic_occurrences"] if (path:=api_path(row.get("root_call")))})
    tables["viewer_service_roles"] = query("SELECT service_path,role,initiation,source,reviewed,changed_at "
        "FROM public.viewer_service_roles WHERE service_path IN (" + ",".join("%s" for _ in services) + ")", services) if services else []
    if coverage_window_ns is None:
        windows = query("SELECT start_ns,end_ns FROM (SELECT start_ns,end_ns FROM public.viewer_live_windows "
                        "ORDER BY start_ns DESC LIMIT 2) AS recent ORDER BY start_ns", cap=2)
    else:
        from . import FIVE_NS
        require(type(coverage_window_ns) is int and coverage_window_ns>0 and coverage_window_ns%FIVE_NS==0,'INVALID_CASE_COVERAGE_WINDOW')
        windows=query('SELECT start_ns,end_ns FROM public.viewer_live_windows WHERE start_ns=%s',(coverage_window_ns,),cap=1)
    expected = query("SELECT anchor_key FROM public.viewer_semantic_occurrences WHERE state='active' AND request_key IN (" +
                     ",".join("%s" for _ in keys) + ")", keys, cap=sample_limit)
    stamp = time.time_ns() if captured_at_ns is None else captured_at_ns
    snapshot = Snapshot({"format": CONTRACT, "source": {
        "namespace": "viewer:" + live[0]["stream_key"], "stream_key": live[0]["stream_key"],
        "keys_fingerprint": live[0]["keys_fingerprint"], "runtime_sha256": runtime_sha256,
        "catalog_fingerprint": catalog[0]["fingerprint"], "catalog_status": "CURRENT",
        "semantic_schema": SEMANTIC_SCHEMA, "semantic_state": semantic[0]["state"],
        "maintenance": "CLEAR", "evidence_mode": "postgresql_readonly_snapshot",
        "source_finality": "not_established", "sequence": 1,
        "generation": live[0]["generation"], "semantic_generation": semantic[0]["generation"],
        "captured_at_ns": stamp, "consistent_snapshot": True, "global_origin_versions_complete": True},
        "scope": {"id": "native-sample-" + str(stamp), "request_keys": keys, "complete": True,
                  "population_complete": False, "sampling": "latest_active_anchors_not_complete_sessions" if request_keys is None else "explicit_case_requests_not_complete_sessions",
                  "complete_intervals_ns": [[row["start_ns"], row["end_ns"]] for row in windows]}, "tables": tables})
    require(not snapshot.deferred_reasons, "SOURCE_SNAPSHOT_DEFERRED")
    expected_anchors = sorted(row["anchor_key"] for row in expected)
    require(snapshot.source_active_anchors == expected_anchors, "SOURCE_ANCHOR_SET_CHANGED_WITHIN_SNAPSHOT")
    return snapshot, {"expected_active_anchors": expected_anchors,
                      "source_transaction": guard[0], "sampled_requests": len(keys),
                      "population_complete": False, "raw_payload_exported": False,
                      "identifier_raw_values_exported": False,
                      "historical_gaps": "OWNER_REPORTED_PRESENT_COUNT_NOT_MEASURED"}


def read_native_sample(project, *, config_path=None, sample_limit=DEFAULT_SAMPLE):
    require(type(sample_limit) is int and 1 <= sample_limit <= MAX_SAMPLE, "INVALID_SAMPLE_LIMIT")
    identity = installed_source_identity(project)
    config_path = Path(config_path) if config_path else Path(project) / "viewer_config.local.py"
    database = read_database_config(config_path)
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError:
        raise ContractError("EXISTING_VIEWER_PSYCOPG_DEPENDENCY_NOT_AVAILABLE") from None
    connection = psycopg.connect(**connection_parameters(database), autocommit=False, row_factory=dict_row)
    try:
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        query = BudgetQuery(connection,project=project)
        snapshot, report = collect_sample(query, runtime_sha256=identity["runtime_sha256"], sample_limit=sample_limit)
        report.update(identity, query_metrics=query.metrics, driver_version=psycopg.__version__)
        return snapshot, report
    finally:
        try:
            connection.rollback()
        finally:
            connection.close()
