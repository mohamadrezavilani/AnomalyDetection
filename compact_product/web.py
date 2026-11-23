"""Small manual-refresh operator UI; bounded reads, no legacy projections."""

from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
import json
import secrets
import threading
import time
from zoneinfo import ZoneInfo
from flask import (
    Flask,
    render_template,
    request,
    abort,
    jsonify,
    redirect,
    url_for,
    session,
)
from compact_behavior.store import Store
from compact_behavior import FIVE, FEATURES, inquiry
from compact_behavior.extract import identity, materialize
from .health import health
from . import search
from . import cases, postal_health
from . import BUILD
from .error_catalog import definitions
from .presentation import ROLES, data_note
from .request_context import observed_context
from compact_ad.methods import METHODS
from compact_ad import MODEL
from compact_ad.seasonality import HORIZON
from compact_ad import long_store, longitudinal
from compact_behavior.services import meaningful_apis, operation_catalog, operation_label, operation_role


def create_app(config, database, stream, *, secret=None):
    app = Flask(__name__)
    app.secret_key = secret or secrets.token_hex(32)
    app.config.update(MAX_CONTENT_LENGTH=16384, SESSION_COOKIE_SAMESITE="Lax")

    @contextmanager
    def connection(write=False):
        db = Store(database, schema=config.source_schema, application="web")
        try:
            db.conn.execute("SET statement_timeout=3000")
            if not write:
                db.conn.execute("SET default_transaction_read_only=on")
            yield db.conn
        finally:
            db.close()

    @app.template_filter("tehran")
    def tehran(ns):
        return (
            datetime.fromtimestamp(ns / 1e9, ZoneInfo("Asia/Tehran")).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            if ns is not None
            else "—"
        )

    @app.template_filter("pretty")
    def pretty(value):
        return json.dumps(value, ensure_ascii=False, indent=2)

    @app.template_filter("method_label")
    def method_label(key):
        if key == longitudinal.METHOD:
            return 'تنوع تجمیعی شناسه‌های ورودی در چند روز'
        return METHODS.get(key, {}).get("label", key)

    @app.template_filter("status_label")
    def status_label(key):
        return {
            "NORMAL": "عادی",
            "ANOMALY": "غیرعادی، نیازمند بررسی",
            "INSUFFICIENT_DATA": "دادهٔ مرجع ناکافی",
            "INVALID_INPUT": "ورودی نامعتبر یا ناقص",
            "CONFIRMED": "تأیید مورد",
            "FALSE_POSITIVE": "مثبت کاذب",
            "UNSURE": "نیازمند بررسی",
        }.get(key, key)

    @app.template_filter("readiness_label")
    def readiness_label(value):
        return (
            " · ".join(str(n) + " " + status_label(k) for k, n in value.items())
            if isinstance(value, dict)
            else value
        )

    @app.template_filter("metric")
    def metric(value):
        return (
            "—"
            if value is None
            else f"{value:.3g}" if isinstance(value, (int, float)) else value
        )

    @app.context_processor
    def defaults():
        return dict(build=BUILD, model_version=MODEL, long_model_version=longitudinal.VERSION, scope_url=scope_url)

    def scope_url(value):
        allowed = (*search.FIELDS, 'q')
        params = {k:request.args[k] for k in allowed if request.args.get(k)}
        params['scope']=value
        return url_for('sessions' if request.path=='/sessions' else 'home', **params)

    app.add_template_filter(operation_label, "operation_label")
    app.add_template_filter(operation_role, "operation_role")
    app.add_template_filter(data_note, "data_note")
    app.add_template_filter(lambda role: ROLES.get(role, "نقش مشخص نشده"), "role_label")

    def behavior_scope():
        scope = request.args.get("scope", "all" if request.args.get("request_id") else "meaningful")
        if scope == "all":
            return scope, "", []
        # The generic dispatcher is meaningful only after exact same-request
        # service binding. Existing compact rows retain this binding as well.
        expression = "(api=ANY(%s) OR (api=%s AND features->>'service_binding'=%s AND features->>'service_key'=ANY(%s)))"
        dispatch = "Services.v1/InvoiceRegister"
        binding = "SAME_REQUEST_REVIEWED_DISPATCH"
        attempt = "(api='Services.v1/InvoiceRegister' AND result_code='GR0004')"
        access_attempt = "(api='Services.v1/InvoiceRegister' AND result_code='G00010' AND features->'access_denied_attempt'->>'verified'='true')"
        if scope == 'attempts':
            return scope, 'AND '+attempt, []
        attempt = "(" + attempt + " OR " + access_attempt + ")"
        if scope == "unknown":
            known = sorted(api for api, row in operation_catalog()["routes"].items() if row["role"] != "unknown" and api != dispatch)
            return scope, "AND NOT COALESCE(" + expression + " OR " + attempt + ",false)", [known, dispatch, binding, known]
        if scope != "meaningful":
            abort(400)
        allowed = meaningful_apis()
        return scope, "AND (" + expression + " OR " + attempt + ")", [allowed, dispatch, binding, allowed]

    @app.errorhandler(Exception)
    def failure(exc):
        from werkzeug.exceptions import HTTPException

        if isinstance(exc, HTTPException):
            return exc
        app.logger.error("web operation failed: %s", type(exc).__name__)
        return (
            render_template("error.html", title="دریافت اطلاعات موقتاً ممکن نیست"),
            503,
        )

    @app.get("/healthz")
    def live():
        return jsonify(status="ok", service="compact_product", build=BUILD)

    @app.get("/api/status")
    def api_status():
        with connection() as db:
            value = health(db, config, stream)
            value['postal_health'] = postal_health.report(db,config,stream)
        return jsonify(value)

    @app.get("/status")
    @app.get("/")
    def home():
        scope, clause, args = behavior_scope()
        try:
            values, filters_sql, filters_args = search.filters(request.args,stream)
        except ValueError as exc:
            abort(400,description=str(exc))
        cursor_sql=''; cursor_args=[]
        if request.args.get('before'):
            import re
            if not re.fullmatch(r'\d{1,20}',request.args['before']) or not re.fullmatch(r'[0-9a-f]{64}',request.args.get('id','')):
                abort(400,description='نشانگر صفحه معتبر نیست.')
            cursor_sql=' AND (b.observed_at_ns,b.behavior_id)<(%s,%s)'
            cursor_args=[int(request.args['before']),request.args['id']]
        with connection() as db:
            value=health(db,config,stream) if request.path=='/status' else None
            coverage=None;rows=[];code_definitions={}
            if request.path=='/status':
                value['postal_health'] = postal_health.report(db,config,stream)
                value['longitudinal']=long_store.status(db,config.source_schema,config.ad_schema,stream)
                coverage=db.execute(f"SELECT summary FROM {config.ad_schema}.window_results WHERE stream_id=%s AND start_ns=%s",
                    (stream,value['latest_analyzed_end_ns']-FIVE if value['latest_analyzed_end_ns'] is not None else None)).fetchone()
            else:
                join=''
                if values['ip']:
                    index=search.index_state(db,config.source_schema)
                    if not index or not index['indisvalid'] or not index['indisready']:
                        abort(503,description='جست‌وجوی IP هنوز آماده نیست؛ آماده‌سازی ایندکس جست‌وجو باید کامل شود.')
                    join=f' JOIN {config.source_schema}.request_context c USING(behavior_id)'
                rows=db.execute(f"""SELECT b.request_id,b.session_id,b.observed_at_ns,b.api,b.result_code,b.behavior_id,
                    b.features->>'service_key' AS service_key,b.features->'rejected_attempt' AS rejected_attempt,b.features->'access_denied_attempt' AS access_denied_attempt,b.quality
                    FROM {config.source_schema}.behaviors b {join} WHERE b.stream_id=%s {clause} {filters_sql} {cursor_sql}
                    ORDER BY b.observed_at_ns DESC,b.behavior_id DESC LIMIT 31""",
                    (stream,*args,*filters_args,*cursor_args)).fetchall()
                search.originals(db,config.source_schema,rows[:30])
                code_definitions=definitions(db,config.source_schema,[r['result_code'] for r in rows[:30]])
        nxt=None
        if len(rows)>30:
            nxt=url_for('home',**{k:v for k,v in values.items() if v},scope=scope,
                before=rows[29]['observed_at_ns'],id=rows[29]['behavior_id'])
        return render_template('status.html' if request.path=='/status' else 'home.html',
            title='وضعیت پردازش' if request.path=='/status' else 'رفتارهای مشاهده‌شده',
            health=value,code_definitions=code_definitions,rows=rows[:30],coverage=coverage['summary'] if coverage else {},
            scope=scope,filters=values,next_page=nxt)

    @app.get("/sessions")
    def sessions():
        key = identity(request.args.get("q", ""))
        scope, scope_clause, scope_args = behavior_scope()
        if not key:
            return render_template(
                "sessions.html", title="جست‌وجوی نشست", key="", rows=[], next_cursor=None, scope=scope
            )
        # Session identifiers are exact canonical IDs; no IP/name inference.
        with connection() as db:
            args = [stream, key, *scope_args]
            clause = ""
            if request.args.get("before"):
                try:
                    before = int(request.args["before"])
                    bid = request.args["id"]
                except (ValueError, KeyError):
                    abort(400)
                clause = "AND (observed_at_ns,behavior_id)<(%s,%s)"
                args.extend([before, bid])
            rows = db.execute(
                f"""SELECT behavior_id,request_id,session_id,observed_at_ns,api,result_code,quality,
                features->>'service_key' AS service_key,features->'rejected_attempt' AS rejected_attempt,features->'access_denied_attempt' AS access_denied_attempt FROM {config.source_schema}.behaviors
                WHERE stream_id=%s AND session_id=%s {scope_clause} {clause} ORDER BY observed_at_ns DESC,behavior_id DESC LIMIT 51""",
                args,
            ).fetchall()
            search.originals(db,config.source_schema,rows[:50])
            code_definitions = definitions(db, config.source_schema, [r["result_code"] for r in rows[:50]])
        nxt = rows[49] if len(rows) > 50 else None
        return render_template(
            "sessions.html",
            title="رفتارهای نشست",
            key=key,
            code_definitions=code_definitions,
            rows=rows[:50],
            next_cursor=nxt,
            scope=scope,
        )

    @app.get("/behaviors/<bid>")
    def behavior(bid):
        with connection() as db:
            row = db.execute(
                f"""SELECT b.*,p.state,c.context AS collected_context FROM {config.source_schema}.behaviors b
                JOIN {config.source_schema}.behavior_payloads p USING(behavior_id)
                LEFT JOIN {config.source_schema}.request_context c USING(behavior_id) WHERE b.stream_id=%s AND b.behavior_id=%s""",
                (stream, bid),
            ).fetchone()
            code_definitions = definitions(db, config.source_schema, [row["result_code"]]) if row else {}
        if not row:
            abort(404)
        body = materialize(stream, row["state"])
        row['rejected_attempt']=body['features'].get('rejected_attempt')
        row['access_denied_attempt']=body['features'].get('access_denied_attempt')
        search.decorate(row,row['state'])
        return render_template(
            "behavior.html", title="جزئیات رفتار", row=row, body=body, code_definitions=code_definitions, request_context=observed_context(row["state"], row.get("collected_context"))
        )

    def publishable():
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

    def case_rows():
        try:
            day,start,end=cases.day_bounds(request.args.get('date'))
            days=int(request.args.get('days','30'))
            if not 1<=days<=30:raise ValueError('invalid_range')
            start-=(days-1)*longitudinal.DAY
        except (ValueError,OverflowError):abort(400,description='تاریخ میلادی معتبر وارد کنید.')
        with connection() as db:
            rows=db.execute(f'''WITH strong_candidates AS MATERIALIZED (
                SELECT * FROM {config.ad_schema}.findings
                WHERE stream_id=%s AND status='ANOMALY' AND start_ns>=%s AND start_ns<%s
                AND (method='long_target_enumeration' OR result->>'single_signal_review_eligible'='true')
                ORDER BY start_ns DESC,finding_id DESC LIMIT 1001
            ), ordinary_candidates AS MATERIALIZED (
                SELECT * FROM {config.ad_schema}.findings
                WHERE stream_id=%s AND status='ANOMALY' AND start_ns>=%s AND start_ns<%s
                AND NOT (method='long_target_enumeration' OR COALESCE(result->>'single_signal_review_eligible','false')='true')
                ORDER BY start_ns DESC,finding_id DESC LIMIT {cases.LIMIT+1}
            ), candidates AS MATERIALIZED (
                SELECT * FROM strong_candidates UNION ALL SELECT * FROM ordinary_candidates
            ), eligible AS (
                SELECT f.*,COALESCE((SELECT v.verdict FROM {config.ad_schema}.feedback v
                    WHERE v.finding_id=f.finding_id AND v.finding_revision=f.revision
                    ORDER BY v.feedback_id DESC LIMIT 1),'UNSURE') AS verdict
                FROM candidates f WHERE {publishable()}
            ) SELECT e.*,c.n AS candidate_count,c.strong_count FROM
                (SELECT count(*) AS n,(SELECT count(*) FROM strong_candidates) AS strong_count FROM candidates) c
                LEFT JOIN eligible e ON true ORDER BY
                (e.method='long_target_enumeration' OR COALESCE(e.result->>'single_signal_review_eligible','false')='true') DESC,
                e.start_ns DESC,e.finding_id DESC''',
                [stream,start,end,stream,start,end,*eligible_args()]).fetchall()
        truncated=bool(rows and (rows[0]['candidate_count']>cases.LIMIT or rows[0]['strong_count']>1000))
        eligible=[r for r in rows if r.get('finding_id')][:cases.LIMIT]
        selected=cases.select_cases(eligible)
        service=request.args.get('service')
        if service:
            selected=[c for c in selected if service in c['services']]
        return day,days,selected,len(eligible),truncated

    @app.get('/incidents')
    def incidents():
        day,days,rows,signals,truncated=case_rows()
        tab=request.args.get('tab','services')
        if tab not in ('services','sessions','cases'):abort(400)
        all_count=len(rows)
        if tab=='sessions':rows=[c for c in rows if c['session_id']]
        services=cases.service_groups(rows) if tab=='services' else []
        items=services if tab=='services' else rows
        try:page=int(request.args.get('page','1'))
        except ValueError:abort(400)
        if not 1<=page<=1000:abort(400)
        return render_template('cases.html',title='آنومالی‌های دارای شواهد تقویتی',
            rows=rows[(page-1)*30:page*30],service_groups=services[(page-1)*30:page*30],
            date=day,days=days,tab=tab,page=page,has_next=len(items)>page*30,
            case_count=all_count,signal_count=signals,truncated=truncated,reasons=cases.REASONS,
            selected_service=request.args.get('service',''))

    @app.get('/cases/<cid>')
    def case_detail(cid):
        if not request.args.get('date'):abort(400)
        day,days,rows,signals,truncated=case_rows()
        selected=next((c for c in rows if c['case_id']==cid),None)
        ips=[]
        ip_range={}
        if selected:
            first=min(f['result'].get('period_start_ns',f['start_ns']) for f in selected['findings'])
            last=max(f['result'].get('period_end_ns',f['start_ns']+FIVE) for f in selected['findings'])
            ip_range={k:datetime.fromtimestamp(v/1e9,ZoneInfo('Asia/Tehran')).strftime('%Y-%m-%dT%H:%M:%S')
                      for k,v in [('from',first),('to',last)]}
            witnesses=list(dict.fromkeys(b for f in selected['findings'][:30] for b in f['result'].get('evidence',[])))[:36]
            with connection() as db:
                contexts=db.execute(f'''SELECT context FROM {config.source_schema}.request_context
                    WHERE behavior_id=ANY(%s) LIMIT 36''',(witnesses,)).fetchall()
            ips=sorted({v['value'] for c in contexts for v in c['context'].get('values',{}).get('ip',[])})[:8]
        return render_template('case.html',title='شواهد مورد',case=selected,date=day,days=days,ips=ips,ip_range=ip_range,
            truncated=truncated,reasons=cases.REASONS)

    @app.get("/signals")
    def signals():
        # One overview row per Tehran day and service; retain individual findings.
        # Group before pagination: never split a group across pages.
        before = request.args.get("before")
        args = [stream, *eligible_args()]
        clause = ""
        if before:
            try:
                args.extend([int(before), request.args["id"]])
            except (ValueError, KeyError):
                abort(400)
            clause = "WHERE (last_ns,group_id)<(%s,%s)"
        with connection() as db:
            rows = db.execute(f"""
                WITH eligible AS (
                    SELECT f.*,md5(jsonb_build_array(f.service,
                        (f.start_ns+12600000000000)/86400000000000)::text) AS group_id
                    FROM {config.ad_schema}.findings f
                    WHERE f.stream_id=%s AND {publishable()}
                ), grouped AS (
                    SELECT group_id,service,count(DISTINCT session_id) AS session_count, bool_or(session_id IS NULL) AS has_service_scope,array_agg(DISTINCT method) AS methods,min(start_ns) AS first_ns,
                        max(start_ns) AS last_ns,count(*) AS signal_count,
                        (array_agg(finding_id ORDER BY start_ns DESC,finding_id DESC))[1] AS finding_id,
                        (array_agg(result ORDER BY start_ns DESC,finding_id DESC))[1] AS result
                    FROM eligible GROUP BY group_id,service
                ) SELECT * FROM grouped {clause}
                ORDER BY last_ns DESC,group_id DESC LIMIT 31""", args).fetchall()
        return render_template("incidents.html", title="همهٔ سیگنال‌های آماری",
            rows=rows[:30],next_cursor=rows[29] if len(rows)>30 else None)

    @app.get("/incident-groups/<gid>")
    def incident_group(gid):
        if len(gid) != 32 or any(c not in "0123456789abcdef" for c in gid):
            abort(404)
        args = [stream,*eligible_args(),gid]
        clause = ""
        if request.args.get("before"):
            try:
                args.extend([int(request.args["before"]),request.args["id"]])
            except (ValueError,KeyError):
                abort(400)
            clause = "AND (f.start_ns,f.finding_id)<(%s,%s)"
        with connection() as db:
            rows = db.execute(f"""SELECT f.* FROM {config.ad_schema}.findings f
                WHERE f.stream_id=%s AND {publishable()}
                AND md5(jsonb_build_array(f.service,
                    (f.start_ns+12600000000000)/86400000000000)::text)=%s
                {clause} ORDER BY f.start_ns DESC,f.finding_id DESC LIMIT 51""",
                args).fetchall()
        return render_template("incident_group.html", title="هشدارهای خدمت", rows=rows[:50],gid=gid,
            next_cursor=rows[49] if len(rows)>50 else None)

    @app.get("/incidents/<fid>")
    def incident(fid):
        with connection() as db:
            finding = db.execute(
                f"SELECT * FROM {config.ad_schema}.findings WHERE stream_id=%s AND finding_id=%s",
                (stream, fid),
            ).fetchone()
            if not finding:
                abort(404)
            ready = db.execute(
                f"SELECT 1 FROM {config.ad_schema}.findings f WHERE f.stream_id=%s AND f.finding_id=%s AND {publishable()}",
                [stream, fid, *eligible_args()],
            ).fetchone() is not None
            feedback = db.execute(
                f"SELECT * FROM {config.ad_schema}.feedback WHERE finding_id=%s ORDER BY feedback_id DESC LIMIT 50",
                (fid,),
            ).fetchall()
            history = db.execute(
                f"SELECT * FROM {config.ad_schema}.finding_history WHERE finding_id=%s ORDER BY revision DESC LIMIT 30",
                (fid,),
            ).fetchall()
        session.setdefault("csrf", secrets.token_urlsafe(24))
        return render_template(
            "incident.html",
            title="بررسی مورد",
            finding=finding,
            ready=ready,
            feedback=feedback,
            history=history,
            csrf=session["csrf"],
        )

    @app.post("/incidents/<fid>/feedback")
    def feedback(fid):
        if not secrets.compare_digest(
            session.get("csrf", ""), request.form.get("csrf", "")
        ) or not session.get("csrf"):
            abort(400)
        verdict = request.form.get("verdict")
        note = request.form.get("note", "").strip()
        if verdict not in ("CONFIRMED", "FALSE_POSITIVE", "UNSURE") or len(note) > 2000:
            abort(400)
        try:
            reviewed_revision = int(request.form.get("revision", ""))
        except ValueError:
            abort(400)
        with connection(write=True) as db:
            finding = db.execute(
                f"SELECT revision FROM {config.ad_schema}.findings WHERE stream_id=%s AND finding_id=%s",
                (stream, fid),
            ).fetchone()
            if not finding:
                abort(404)
            reviewed = db.execute(
                f"SELECT 1 FROM {config.ad_schema}.finding_history WHERE finding_id=%s AND revision=%s",
                (fid, reviewed_revision),
            ).fetchone()
            if not reviewed:
                abort(409)
            db.execute(
                f"""INSERT INTO {config.ad_schema}.feedback(finding_id,finding_revision,verdict,note,recorded_at_ns)
                VALUES(%s,%s,%s,%s,%s)""",
                (fid, reviewed_revision, verdict, note, time.time_ns()),
            )
        return redirect(url_for("incident", fid=fid))

    return app


def serve(lease, source):
    from waitress import create_server, wasyncore

    cfg = lease.config
    secret_path = Path(lease.project) / "compact_runtime/web-secret.local.key"
    if not secret_path.exists():
        secret_path.write_text(secrets.token_hex(32), encoding="ascii")
    app = create_app(
        cfg,
        source["DATABASE"],
        lease.stream,
        secret=secret_path.read_text(encoding="ascii"),
    )
    server = create_server(
        app,
        listen=" ".join(f"{cfg.host}:{port}" for port in cfg.web_ports),
        threads=4,
        connection_limit=64,
        channel_timeout=30,
        cleanup_interval=5,
        max_request_body_size=16384,
        outbuf_high_watermark=1048576,
        asyncore_loop_timeout=0.5,
    )
    lease.update(state="WEB_LISTENING", ports=list(cfg.web_ports), bind_host=cfg.host)

    def shutdown():
        lease.stop.wait()
        server.task_dispatcher.shutdown(timeout=5)
        wasyncore.close_all(server._map if hasattr(server, "_map") else server.map)

    closer = threading.Thread(target=shutdown, daemon=True)
    closer.start()
    try:
        server.run()
    finally:
        lease.stop.set()
        closer.join(10)
