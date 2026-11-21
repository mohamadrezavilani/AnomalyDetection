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
from compact_behavior.extract import identity, materialize
from .health import health
from . import BUILD
from compact_ad.methods import METHODS


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
        return dict(build=BUILD)

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
        return jsonify(value)

    @app.get("/")
    def home():
        with connection() as db:
            value = health(db, config, stream)
            rows = db.execute(
                f"""SELECT request_id,session_id,observed_at_ns,api,result_code,behavior_id,features->>'service_key' AS service_key,
                quality FROM {config.source_schema}.behaviors WHERE stream_id=%s ORDER BY observed_at_ns DESC,behavior_id DESC LIMIT 30""",
                (stream,),
            ).fetchall()
            coverage = db.execute(
                f"""SELECT summary FROM {config.ad_schema}.window_results WHERE stream_id=%s ORDER BY start_ns DESC LIMIT 1""",
                (stream,),
            ).fetchone()
        return render_template(
            "home.html",
            title="رفتارهای مشاهده‌شده",
            health=value,
            rows=rows,
            coverage=coverage["summary"] if coverage else {},
        )

    @app.get("/sessions")
    def sessions():
        key = identity(request.args.get("q", ""))
        if not key:
            return render_template(
                "sessions.html", title="جست‌وجوی نشست", key="", rows=[], next_cursor=None
            )
        # Session identifiers are exact canonical IDs; no IP/name inference.
        with connection() as db:
            args = [stream, key]
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
                features->>'service_key' AS service_key FROM {config.source_schema}.behaviors
                WHERE stream_id=%s AND session_id=%s {clause} ORDER BY observed_at_ns DESC,behavior_id DESC LIMIT 51""",
                args,
            ).fetchall()
        nxt = rows[49] if len(rows) > 50 else None
        return render_template(
            "sessions.html",
            title="رفتارهای نشست",
            key=key,
            rows=rows[:50],
            next_cursor=nxt,
        )

    @app.get("/behaviors/<bid>")
    def behavior(bid):
        with connection() as db:
            row = db.execute(
                f"""SELECT b.*,p.state FROM {config.source_schema}.behaviors b
                JOIN {config.source_schema}.behavior_payloads p USING(behavior_id) WHERE b.stream_id=%s AND b.behavior_id=%s""",
                (stream, bid),
            ).fetchone()
        if not row:
            abort(404)
        body = materialize(stream, row["state"])
        return render_template(
            "behavior.html", title="جزئیات رفتار", row=row, body=body
        )

    @app.get("/incidents")
    def incidents():
        archive = request.args.get("archive") == "1"
        where = "status<>'ANOMALY'" if archive else "status='ANOMALY'"
        args = [stream]
        clause = ""
        if request.args.get("before"):
            try:
                before = int(request.args["before"])
                bid = request.args["id"]
            except (ValueError, KeyError):
                abort(400)
            clause = "AND (start_ns,finding_id)<(%s,%s)"
            args.extend([before, bid])
        with connection() as db:
            rows = db.execute(
                f"""SELECT * FROM {config.ad_schema}.findings WHERE stream_id=%s AND {where} {clause}
                ORDER BY start_ns DESC,finding_id DESC LIMIT 51""",
                args,
            ).fetchall()
        nxt = rows[49] if len(rows) > 50 else None
        return render_template(
            "incidents.html",
            title="موارد قابل بررسی",
            rows=rows[:50],
            archive=archive,
            next_cursor=nxt,
        )

    @app.get("/incidents/<fid>")
    def incident(fid):
        with connection() as db:
            finding = db.execute(
                f"SELECT * FROM {config.ad_schema}.findings WHERE stream_id=%s AND finding_id=%s",
                (stream, fid),
            ).fetchone()
            if not finding:
                abort(404)
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
