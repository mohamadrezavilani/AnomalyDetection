"""Private localhost Flask viewer for real imported Pishkhan24 evidence."""
from __future__ import annotations
import ipaddress
import hmac
from contextlib import contextmanager
from threading import BoundedSemaphore
from datetime import datetime
from zoneinfo import ZoneInfo
from flask import Flask, render_template, request, abort, redirect, url_for, jsonify, g
from werkzeug.exceptions import HTTPException,SecurityError
from pathlib import Path
from .viewer_data import ViewerDB,VIEWER_VERSION,tehran,SERVICE_ROLES,SERVICE_INITIATIONS
from .store import ROOT


def create_viewer_app(db_opts,*,lan_host=None):
    app=Flask(__name__,template_folder=str(ROOT/'review_ui/templates'),static_folder=str(ROOT/'review_ui/static'))
    from .viewer_display_time import tehran_time
    app.jinja_env.filters['tehran_time']=tehran_time
    trusted_hosts=['127.0.0.1','localhost','[::1]']
    allowed_networks=[ipaddress.ip_network('127.0.0.0/8'),ipaddress.ip_network('::1/128')]
    if lan_host is not None:
        address=ipaddress.ip_address(lan_host)
        private_lan=[ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')]
        if not any(address in network for network in private_lan):raise ValueError('viewer_lan_host_must_be_private_ipv4')
        trusted_hosts.append(str(address));allowed_networks+=private_lan
    app.config.update(TRUSTED_HOSTS=trusted_hosts)
    read_slots=BoundedSemaphore(2)
    @contextmanager
    def db(*,write=False):
        # Fast admission instead of accumulating browser refreshes behind I/O.
        if not read_slots.acquire(blocking=False):abort(503)
        d=None
        try:
            options=dict(db_opts)
            if 'config' in options:
                config=dict(options['config'])
                config['application_name']='P24.Viewer.web'
                config['options']=' '.join(filter(None,(config.get('options',''),
                    '-c statement_timeout=2000 -c lock_timeout=100 '
                    '-c idle_in_transaction_session_timeout=5000 -c max_parallel_workers_per_gather=0')))
                options['config']=config
            d=ViewerDB(**options)
            if not write:
                # Multiple queries composing a page see one publication.
                if d.sqlite:d.sql('BEGIN')
                else:d.sql('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
                from .viewer_online import live_history_coverage
                g.viewer_history_coverage=live_history_coverage(d)
            yield d
        finally:
            try:
                if d is not None:d.close()
            finally:read_slots.release()
    @app.context_processor
    def coverage_notice():
        return dict(viewer_history_coverage=getattr(g,'viewer_history_coverage',{}))
    @app.before_request
    def loopback():
        try:
            address=ipaddress.ip_address(request.remote_addr)
            if address.version==6 and address.ipv4_mapped:address=address.ipv4_mapped
            if not any(address in network for network in allowed_networks):abort(403)
        except (ValueError,TypeError):abort(403)
    @app.after_request
    def secure(resp):
        resp.headers.update({'Cache-Control':'no-store','Content-Security-Policy':"default-src 'none'; style-src 'self'; img-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",'Referrer-Policy':'no-referrer',
                             'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY'})
        return resp
    from .viewer_runtime import runtime_source_digest
    serving_sha=runtime_source_digest(ROOT)
    @app.get('/healthz')
    def health():
        return jsonify(status='ok',service='viewer',runtime_sha256=serving_sha)
    def pagination():
        try:
            page=int(request.args.get('page',1));limit=int(request.args.get('limit',25))
            if page<1 or limit<1 or limit>100 or page>10_000_000:raise ValueError
            return page,limit,(page-1)*limit
        except ValueError:abort(400)
    def validate_key(key):
        if len(key)!=64 or any(c not in '0123456789abcdef' for c in key):abort(404)
        return key
    @app.get('/')
    def home():
        page,limit,offset=pagination();search=request.args.get('session','').strip()
        ip=request.args.get('ip','').strip()
        start=request.args.get('from','').strip();end=request.args.get('to','').strip()
        if len(search)>256 or len(ip)>64:abort(400)
        if ip:
            try:ipaddress.ip_address(ip)
            except ValueError:abort(400)
        def parse_tehran(s):
            if not s:return None
            try:
                v=datetime.fromisoformat(s)
                if v.tzinfo is None:v=v.replace(tzinfo=ZoneInfo('Asia/Tehran'))
                return int(v.timestamp()*1_000_000_000)
            except (ValueError,OverflowError):abort(400)
        from_ns=parse_tehran(start);to_ns=parse_tehran(end)
        with db() as d:
            result=d.semantic_sessions(limit,offset,search,ip,from_ns,to_ns)
            from .viewer_online import live_status
            status=live_status(d)
        return render_template('viewer_home.html',result=result,page=page,limit=limit,search=search,
                               ip=ip,start=start,end=end,version=VIEWER_VERSION,live=status)
    @app.get('/live-status')
    def live_status_view():
        from .viewer_online import live_status
        with db() as d:result=live_status(d)
        return jsonify(result)
    @app.get('/requests')
    def requests_view():
        page,limit,offset=pagination()
        session=request.args.get('session','').strip()
        session_key=request.args.get('session_key','').strip()
        service_path_filter=request.args.get('service_path','').strip()
        request_id=request.args.get('request_id','').strip()
        target=request.args.get('target','').strip()
        service=request.args.get('service','').strip()
        role=request.args.get('role','')
        outcome=request.args.get('outcome','')
        start=request.args.get('from','').strip()
        end=request.args.get('to','').strip()
        internal=request.args.get('internal','')=='1'
        if (len(session)>256 or len(session_key)>64 or (session_key and (len(session_key)!=64 or any(c not in '0123456789abcdef' for c in session_key))) or len(service_path_filter)>240 or len(request_id)>256 or len(service)>160 or len(target)>160 or
            role not in ('',)+SERVICE_ROLES or
            outcome not in ('','success','failure','unknown','confirmed') or
            len(start)>50 or len(end)>50):abort(400)
        def local_ns(value):
            if not value:return None
            try:
                dt=datetime.fromisoformat(value)
                if dt.tzinfo is None:dt=dt.replace(tzinfo=ZoneInfo('Asia/Tehran'))
                return int(dt.timestamp()*1_000_000_000)
            except (ValueError,OverflowError):abort(400)
        from_ns=local_ns(start);to_ns=local_ns(end)
        if from_ns is not None and to_ns is not None and from_ns>=to_ns:abort(400)
        with db() as d:
            result=d.requests_page(limit,offset,session=session,session_key=session_key,request_id=request_id,
                service=service,service_path_filter=service_path_filter,role=role,outcome=outcome,target=target,from_ns=from_ns,
                to_ns=to_ns,include_internal=internal)
        return render_template('viewer_requests.html',result=result,page=page,limit=limit,
           session=session,session_key=session_key,request_id=request_id,target=target,service=service,service_path_filter=service_path_filter,role=role,
           outcome=outcome,start=start,end=end,internal=internal,version=VIEWER_VERSION)

    @app.get('/session/<key>')
    def session_view(key):
        """Preserve old deep links; the paged Requests screen replaces Timeline."""
        key=validate_key(key)
        page,limit,_=pagination()
        category=request.args.get('category','business')
        service=request.args.get('service','')
        outcome=request.args.get('outcome','')
        if category not in ('','main','business','user_management','support','system','unknown') or len(service)>160 or outcome not in ('','success','failure','unknown'):abort(400)
        with db() as d:
            if not d.one('SELECT 1 AS present FROM viewer_requests WHERE session_key=? LIMIT 1',(key,)):abort(404)
        return redirect(url_for('requests_view',session_key=key,
               role='business' if category=='main' else category,
               service=service,outcome=outcome,page=page,limit=limit),code=302)
    @app.get('/session/<key>/behavior')
    def session_behavior_view(key):
        key=validate_key(key)
        try:
            limit=int(request.args.get('limit',100))
            after_ns_raw=request.args.get('after_ns','')
            after_key=request.args.get('after_key','')
            after_ns=int(after_ns_raw) if after_ns_raw else None
            if not 1 <= limit <= 500:
                abort(400)
        except (ValueError,TypeError):
            abort(400)
        generation_raw=request.args.get('generation','')
        if generation_raw and (not generation_raw.isdigit() or len(generation_raw)>16):
            abort(400)
        with db() as d:
            if not d.one('SELECT 1 AS present FROM viewer_requests WHERE session_key=? LIMIT 1',(key,)):
                abort(404)
            try:
                result=d.indexed_session_behavior(key,after_ns=after_ns,
                    after_key=after_key or None,scan_limit=limit,
                    generation=int(generation_raw) if generation_raw else None)
            except ValueError as exc:
                if str(exc)=='stale_generation':
                    return render_template('viewer_error.html',code=409,
                                           version=VIEWER_VERSION,restart_url=url_for('session_behavior_view',key=key)),409
                abort(400)
        return render_template('viewer_session_behavior.html', result=result,
                               limit=limit,version=VIEWER_VERSION)

    @app.get('/services')
    def services_view():
        page,limit,offset=pagination()
        search=request.args.get('q','').strip()
        role=request.args.get('role','')
        if len(search)>120 or role not in ('',)+SERVICE_ROLES:abort(400)
        with db() as d:
            result=d.service_roles(limit,offset,search,role)
            for item in result['items']:
                item['csrf']=d.keys.token('p24-viewer-csrf.1','service_role',item['service_path']).split(':')[-1]
        return render_template('viewer_services.html',result=result,search=search,role=role,
                               page=page,limit=limit,version=VIEWER_VERSION)

    @app.post('/services/update')
    def services_update():
        path=request.form.get('service_path','')
        role=request.form.get('role','')
        initiation=request.form.get('initiation','')
        note=request.form.get('note','')
        csrf=request.form.get('csrf','')
        if any(len(v)>mx for v,mx in ((path,240),(role,32),(initiation,32),(note,240),(csrf,128))):abort(400)
        with db(write=True) as d:
            expected=d.keys.token('p24-viewer-csrf.1','service_role',path).split(':')[-1]
            if not hmac.compare_digest(expected,csrf):abort(403)
            try:d.update_service_role(path,role,initiation,note)
            except ValueError:abort(400)
        # No unvalidated redirect URL; return to service catalog after saving.
        return redirect(url_for('services_view',q=path))

    @app.get('/action/<key>')
    def action_view(key):
        key=validate_key(key)
        with db() as d:action=d.action(key)
        if not action:abort(404)
        return render_template('viewer_action.html',action=action,version=VIEWER_VERSION)
    @app.get('/request/<key>')
    def request_view(key):
        key=validate_key(key);page,limit,offset=pagination()
        with db() as d:
            card=d.request(key)
            if not card:abort(404)
            evidence=d.evidence(key,limit,offset)
            from .viewer_execution_detail import execution_detail
            execution=execution_detail(d,card)
        return render_template('viewer_request.html',card=card,evidence=evidence,execution=execution,
                               page=page,limit=limit,version=VIEWER_VERSION)
    @app.get('/evidence/<origin>/<version>')
    def raw_evidence(origin,version):
        origin=validate_key(origin);version=validate_key(version)
        with db() as d: raw=d.get_raw(origin,version)
        if raw is None:abort(404)
        import json
        # Jinja escapes HTML in original JSON to prevent markup/script execution.
        return render_template('viewer_evidence.html',observed_time=tehran_time(raw.get('@timestamp')),
                               raw=json.dumps(raw,ensure_ascii=False,indent=2),
                               version=VIEWER_VERSION)

    @app.get('/find-request')
    def find_request():
        raw=request.args.get('request_id','').strip()
        if len(raw)>256:abort(400)
        with db() as d:item=d.lookup_request(raw) if raw else None
        if item:return redirect(url_for('request_view',key=item['request_key']))
        return render_template('viewer_find.html',version=VIEWER_VERSION,search=raw,not_found=bool(raw)),(404 if raw else 200)
    @app.errorhandler(Exception)
    def error(error):
        if isinstance(error,SecurityError):return error.get_response()
        if isinstance(error,HTTPException):
            return render_template('viewer_error.html',code=error.code,version=VIEWER_VERSION),error.code,({'Retry-After':'2'} if error.code==503 else {})
        if getattr(error,'sqlstate',None) in ('57014','55P03','25P03'):
            return render_template('viewer_error.html',code=503,version=VIEWER_VERSION),503,{'Retry-After':'2'}
        app.logger.exception('Viewer error (sensitive raw data withheld)')
        return render_template('viewer_error.html',code=500,version=VIEWER_VERSION),500
    return app
