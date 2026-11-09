"""Isolated Persian review app; server-side credentials and no collector startup."""
import ipaddress
import hmac
import hashlib
import json
import secrets
import uuid
from decimal import Decimal,InvalidOperation
from contextlib import contextmanager,nullcontext
from datetime import datetime,timedelta,timezone
from zoneinfo import ZoneInfo

from flask import Flask,render_template,request,session,redirect,url_for
from werkzeug.exceptions import HTTPException

from .errors import FoundationError
from .store import ROOT

UI_VERSION='p24-review-ui.2x.3'
OUTCOMES_FA={'success':'موفق','failure':'ناموفق','unknown':'نامشخص','conflicting':'متعارض'}
ROLES_FA={'client_http':'کلاینت HTTP','sql':'SQL','provider':'سرویس‌دهنده','internal':'فراخوانی داخلی','cache':'کش','unknown':'نامشخص'}
INTERPRETATIONS_FA={'reviewed_sample_binding':'اتصال بررسی‌شده در نمونهٔ مرجع',
    'literal_log_label':'برچسب صریح همان لاگ','candidate_only':'تعریف پیشنهادی؛ اتصال به عملیات بررسی نشده',
    'undocumented':'تعریف مستند در منابع موجود پیدا نشد','conflicting_rules':'تعارض در قواعد تفسیر',
    'binding_source_unavailable':'مرجع قاعده در نسخهٔ موجود در دسترس نیست',
    'legacy_unscoped':'تفسیر ذخیره‌شده با قواعد پیشین'}
LIFECYCLE_FA={'session_creation_procedure_observed':'رویهٔ ایجاد Session مشاهده شد',
    'otp_generation_procedure_observed':'رویهٔ تولید رمز مشاهده شد',
    'verification_sql_chain_observed':'رویه‌های بررسی، مصرف رمز و تأیید Session مشاهده شد',
    'generation_and_verification_co_observed':'تولید و بررسی رمز در شواهد یک درخواست مشاهده شد',
    'partial_security_observations':'شواهد مراحل ورود کامل نیست',
    'conflicting_session_identity':'هویت Session در شواهد متعارض است',
    'conflicting_source_observations':'نسخه‌های متعارض منبع نیازمند بررسی است',
    'no_reviewed_lifecycle_marker':'رویهٔ شناخته‌شده‌ای برای این مرحله مشاهده نشد'}


def tehran_time(value):
    if value is None:return 'ثبت نشده'
    try:
        sec,ns=divmod(int(value),1_000_000_000)
        dt=(datetime(1970,1,1,tzinfo=timezone.utc)+timedelta(seconds=sec)).astimezone(ZoneInfo('Asia/Tehran'))
        fraction='.'+str(ns).zfill(9).rstrip('0') if ns else ''
        return dt.strftime('%Y-%m-%d  %H:%M:%S')+fraction
    except (ValueError,TypeError,OverflowError):return 'زمان نامشخص'


def create_app(provider_factory=None,*,initial_publication=None,mode='demo'):
    if mode not in {'demo','live'}:raise FoundationError('invalid_review_mode')
    if provider_factory is None:
        if mode!='demo':raise FoundationError('review_provider_required')
        from .review_demo import DemoReviewProvider
        demo=DemoReviewProvider();provider_factory=lambda:nullcontext(demo);initial_publication=demo.publication_id
    app=Flask(__name__,template_folder=str(ROOT/'review_ui/templates'),static_folder=str(ROOT/'review_ui/static'))
    app.secret_key=secrets.token_bytes(32)
    app.config.update(SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Strict',TRUSTED_HOSTS=['127.0.0.1','localhost','[::1]'],MAX_CONTENT_LENGTH=4096)
    def elapsed_seconds(value):
        try:return format(Decimal(value)/Decimal(1_000_000_000),'f')
        except (InvalidOperation,ValueError,TypeError):return 'نامشخص'
    app.jinja_env.filters['elapsed_seconds']=elapsed_seconds
    app.jinja_env.filters['tehran_time']=tehran_time
    app.jinja_env.filters['fa_number']=lambda v:'—' if v is None else str(v).translate(str.maketrans('0123456789','۰۱۲۳۴۵۶۷۸۹'))
    app.jinja_env.globals.update(outcomes_fa=OUTCOMES_FA,roles_fa=ROLES_FA,mode=mode,ui_version=UI_VERSION,
                                interpretations_fa=INTERPRETATIONS_FA,lifecycle_fa=LIFECYCLE_FA)

    @app.before_request
    def local_only():
        try:allowed=ipaddress.ip_address(request.remote_addr or '').is_loopback
        except ValueError:allowed=False
        if not allowed:raise FoundationError('review_requires_loopback')

    @app.after_request
    def headers(response):
        response.headers.update({'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY',
            'Content-Security-Policy':"default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"})
        return response

    def parameters():
        publication=request.args.get('publication',initial_publication)
        try:publication=str(uuid.UUID(publication))
        except (ValueError,TypeError,AttributeError):raise FoundationError('invalid_publication_reference') from None
        scope=request.args.get('scope','assigned')
        if scope not in {'assigned','conflicting'}:raise FoundationError('invalid_session_identity_scope')
        try:limit=int(request.args.get('limit','25'))
        except ValueError:raise FoundationError('invalid_page_size') from None
        if not 1<=limit<=100:raise FoundationError('invalid_page_size')
        cursor=request.args.get('cursor')
        if cursor is not None and len(cursor)>4096:raise FoundationError('invalid_page_cursor')
        origin=request.args.get('origin','session');service_key=request.args.get('from_service','')
        investigation_key=request.args.get('from_investigation','')
        if (origin not in {'session','registration','service','investigation'} or len(service_key)>200 or
            len(investigation_key)>200 or (origin=='service')!=bool(service_key) or
            (origin=='investigation')!=bool(investigation_key)):
            raise FoundationError('invalid_review_origin')
        return dict(publication=publication,scope=scope,limit=limit,cursor=cursor,origin=origin,
                    from_service=service_key,from_investigation=investigation_key)

    @app.get('/')
    def journey():
        p=parameters()
        with provider_factory() as provider:
            page=provider.session(p['publication'],identity_scope=p['scope'],limit=p['limit'],cursor=p['cursor'])
            examples=getattr(provider,'examples',[])
        return render_template('session.html',page=page,p=p,examples=examples,title='فعالیت Session')

    @app.get('/request/<key>')
    def request_detail(key):
        p=parameters()
        if len(key)>200:raise FoundationError('invalid_request_reference')
        with provider_factory() as provider:
            card=provider.request(p['publication'],key)['item']
            evidence=provider.evidence(p['publication'],key,limit=p['limit'],cursor=p['cursor'])
        return render_template('request.html',card=card,evidence=evidence,p=p,title='بررسی درخواست')

    @app.get('/registration-candidates')
    def registration_review():
        p=parameters()
        with provider_factory() as provider:page=provider.candidates(p['publication'],limit=p['limit'],cursor=p['cursor'])
        return render_template('candidates.html',page=page,p=p,title='ارتباط‌های احتمالی ثبت دستگاه')

    @app.get('/services')
    def services():
        p=parameters()
        with provider_factory() as provider:page=provider.services(p['publication'],limit=p['limit'],cursor=p['cursor'])
        return render_template('services.html',page=page,p=p,title='مرور Endpointها')

    @app.get('/incidents')
    def incident_list():
        p=parameters()
        with provider_factory() as provider:page=provider.incidents(p['publication'],limit=p['limit'],cursor=p['cursor'])
        return render_template('incidents.html',page=page,p=p,title='پرونده‌های بررسی')

    @app.get('/incident/<key>')
    def incident_detail(key):
        p=parameters();revision=request.args.get('revision')
        with provider_factory() as provider:
            saved=provider.incident(p['publication'],key,revision_id=revision)
            evidence=provider.incident_evidence(p['publication'],key,revision_id=saved['revision_id'],limit=p['limit'],cursor=p['cursor'])
            priority=provider.incident_priority(key)
            links=provider.incident_links(key)
            priority_cursor=request.args.get('priority_cursor')
            if priority_cursor is not None and len(priority_cursor)>4096:raise FoundationError('invalid_page_cursor')
            priority_history=provider.incident_priority_history(key,limit=p['limit'],cursor=priority_cursor)
            revision_status=provider.incident_revision_status(key,saved['revision_id'])
        from .incident_briefs import build_incident_brief
        brief=build_incident_brief(saved,is_latest_revision=revision_status['is_latest'])
        return render_template('incident.html',saved=saved,evidence=evidence,priority=priority,links=links,
                               priority_history=priority_history,priority_cursor=priority_cursor,brief=brief,p=p,title='شواهد پرونده')

    @app.get('/investigations')
    def investigation_queue():
        p=parameters()
        with provider_factory() as provider:page=provider.investigations(p['publication'])
        return render_template('investigations.html',page=page,p=p,title='گروه‌های بررسی مبتنی بر شواهد')

    @app.get('/investigation/<key>')
    def investigation_detail(key):
        p=parameters()
        if len(key)>200:raise FoundationError('invalid_investigation_reference')
        with provider_factory() as provider:group=provider.investigation(key)
        # The registry stores a proof row in each direction. Show each pair
        # once while retaining the signed reader's digest-validated payload.
        group['display_links']=[link for link in group['links']
                                if link['incident_id'] < link['linked_incident_id']]
        return render_template('investigation.html',group=group,p=p,title='جزئیات گروه بررسی')

    def validate_review_request():
        origin=request.headers.get('Origin')
        if origin is not None and origin!=request.host_url.rstrip('/'):
            raise FoundationError('review_permission_origin_denied')
        csrf=request.form.get('csrf','');expected=session.get('review_csrf','')
        if not expected or not hmac.compare_digest(csrf,expected):
            raise FoundationError('review_permission_csrf_denied')

    def priority_preview_hash(value):
        body=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('utf-8')
        return hashlib.sha256(body).hexdigest()

    @app.get('/incident/<key>/priority')
    def priority_form(key):
        p=parameters()
        if mode=='demo':raise FoundationError('review_requires_signed_operator')
        with provider_factory() as provider:
            incident=provider.incident(p['publication'],key)
            current=provider.incident_priority(key)
        session.setdefault('review_csrf',secrets.token_urlsafe(32))
        return render_template('priority_form.html',incident=incident,current=current,key=key,p=p,
            csrf=session['review_csrf'],title='ارزیابی اولویت پرونده')

    @app.post('/incident/<key>/priority/preview')
    def priority_preview(key):
        p=parameters()
        if mode=='demo':raise FoundationError('review_requires_signed_operator')
        validate_review_request()
        choices={name:request.form.get(name,'') for name in ('priority','impact','urgency','confidence','reason_key')}
        with provider_factory() as provider:
            pinned=provider.priority_preview(key,**choices)
        command_id=str(uuid.uuid4())
        digest=priority_preview_hash(pinned)
        session['priority_preview']=dict(key=key,command_id=command_id,pinned=pinned,digest=digest)
        return render_template('priority_preview.html',preview=pinned,digest=digest,command_id=command_id,
            key=key,p=p,csrf=session['review_csrf'],title='پیش‌نمایش ارزیابی اولویت')

    @app.post('/incident/<key>/priority/confirm')
    def priority_confirm(key):
        p=parameters()
        if mode=='demo':raise FoundationError('review_requires_signed_operator')
        validate_review_request()
        pending=session.get('priority_preview')
        if not pending or pending.get('key')!=key or pending.get('command_id')!=request.form.get('command_id'):
            raise FoundationError('priority_preview_not_available')
        if not hmac.compare_digest(pending.get('digest',''),request.form.get('preview_sha256','')):
            raise FoundationError('priority_preview_digest_mismatch')
        pinned=pending['pinned']
        with provider_factory() as provider:
            current=provider.priority_preview(key,**{n:pinned[n] for n in ('priority','impact','urgency','confidence','reason_key')})
            if current!=pinned:raise FoundationError('stale_priority_preview')
            provider.priority_decide(key,**{n:pinned[n] for n in ('priority','impact','urgency','confidence','reason_key')},
                expected_generation=pinned['decision_generation'],expected_revision_id=pinned['evidence_revision_id'],
                expected_evidence_sha256=pinned['evidence_sha256'])
        session.pop('priority_preview',None)
        return redirect(url_for('incident_detail',key=key,publication=p['publication'],origin=p['origin'],
            from_service=p['from_service'],from_investigation=p['from_investigation']),code=303)

    @app.get('/incident/<key>/review')
    def incident_review(key):
        p=parameters()
        if mode=='demo':raise FoundationError('review_requires_signed_operator')
        with provider_factory() as provider:preview=provider.review_preview(key,scope=request.args.get('review_scope','pattern'))
        session.setdefault('review_csrf',secrets.token_urlsafe(32))
        return render_template('incident_review.html',preview=preview,key=key,p=p,csrf=session['review_csrf'],
                               command_id=str(uuid.uuid4()),title='پیش‌نمایش تصمیم اپراتور')

    @app.post('/incident/<key>/review')
    def submit_incident_review(key):
        p=parameters()
        if mode=='demo':raise FoundationError('review_requires_signed_operator')
        origin=request.headers.get('Origin')
        if origin is not None and origin!=request.host_url.rstrip('/'):raise FoundationError('review_permission_origin_denied')
        csrf=request.form.get('csrf','');expected=session.get('review_csrf','')
        if not expected or not hmac.compare_digest(csrf,expected):raise FoundationError('review_permission_csrf_denied')
        with provider_factory() as provider:
            provider.review_decide(key,scope=request.form.get('scope'),verdict=request.form.get('verdict'),
                reason_key=request.form.get('reason_key'),preview_sha256=request.form.get('preview_sha256'),
                command_id=request.form.get('command_id'),expires_at=request.form.get('expires_at') or None)
        return redirect(url_for('incident_detail',key=key,publication=p['publication'],origin=p['origin'],
            from_service=p['from_service'],from_investigation=p['from_investigation']),code=303)

    @app.get('/workflow-examples')
    def workflow_review():
        if mode!='demo':raise FoundationError('workflow_examples_require_demo')
        from .workflow_demo import workflow_examples
        return render_template('workflows.html',examples=workflow_examples(),p=parameters(),title='بررسی منطق فرایند')

    @app.get('/workflows')
    def workflow_evidence():
        p=parameters()
        with provider_factory() as provider:page=provider.workflows(p['publication'],limit=p['limit'],cursor=p['cursor'])
        return render_template('workflow_evidence.html',page=page,p=p,title='شواهد فرایند و تحویل')

    @app.get('/workflow-state/<key>')
    def workflow_state(key):
        p=parameters()
        with provider_factory() as provider:page=provider.workflow_state(p['publication'],key,limit=p['limit'],cursor=p['cursor'])
        return render_template('workflow_state.html',page=page,p=p,title='شواهد نتیجهٔ فرایند')

    @app.get('/service/<key>')
    def service_detail(key):
        p=parameters()
        if len(key)>200:raise FoundationError('invalid_service_reference')
        with provider_factory() as provider:page=provider.service(p['publication'],key,limit=p['limit'],cursor=p['cursor'])
        return render_template('service.html',page=page,p=p,title='شواهد Endpoint')

    @app.errorhandler(Exception)
    def error_page(error):
        code=error.code if isinstance(error,FoundationError) else 'review_operation_failed'
        if isinstance(error,HTTPException):status=error.code;code='review_route_not_available'
        elif isinstance(error,FoundationError):
            status=403 if any(t in code for t in ('access','credential','permission','loopback','operator')) else 404 if 'not_available' in code else 400
        else:status=500
        app.logger.warning('review_failed code=%s error_type=%s',code,type(error).__name__)
        message='دسترسی به این شواهد مجاز نیست.' if status==403 else 'شواهد در نسخهٔ انتخاب‌شده در دسترس نیست.' if status==404 else 'درخواست قابل پردازش نیست؛ پارامترها و اتصال محلی را بررسی کنید.'
        if getattr(error,'code',None)==400 and request.url_rule is None:
            return app.response_class('درخواست قابل پردازش نیست.',status=400,mimetype='text/plain')
        return render_template('error.html',title='امکان نمایش وجود ندارد',message=message,code=code,p={'publication':initial_publication,'scope':'assigned','limit':25}),status

    return app


def live_provider_factory(config_path,session_path,access_token_path):
    from .config import read_config,connect
    from .privacy import Keys
    from .access import AccessPolicy,read_public_key
    from .cli import read_private_session,read_private_access_token
    from .store import FoundationStore
    from .investigation import InvestigationReader
    settings=read_config(config_path)
    if settings['access_public_key_path'] is None:raise FoundationError('access_policy_not_configured')
    keys=Keys.read(settings['keys_path'])
    policy=AccessPolicy(read_public_key(settings['access_public_key_path']),settings['namespace'],issuer=settings['access_issuer'],audience=settings['access_audience'])

    class LiveProvider:
        def __init__(self,reader,token,session):self.reader,self.token,self.raw_session=reader,token,session
        def session(self,p,**kwargs):return self.reader.session(p,self.raw_session,access_token=self.token,**kwargs)
        def request(self,p,key):return self.reader.request_by_key(p,key,access_token=self.token)
        def evidence(self,p,key,**kwargs):return self.reader.operations_by_key(p,key,access_token=self.token,**kwargs)
        def candidates(self,p,**kwargs):return self.reader.registration_context(p,self.raw_session,access_token=self.token,**kwargs)
        def services(self,p,**kwargs):return self.reader.services(p,access_token=self.token,**kwargs)
        def service(self,p,key,**kwargs):return self.reader.service(p,key,access_token=self.token,**kwargs)
        def registry(self):
            from .incidents import IncidentRegistry
            return IncidentRegistry(self.reader.store)
        def incidents(self,p,**kwargs):return self.registry().list(p,access_token=self.token,**kwargs)
        def incident(self,p,key,**kwargs):return self.registry().read(p,key,access_token=self.token,**kwargs)
        def incident_evidence(self,p,key,**kwargs):return self.registry().evidence(p,key,access_token=self.token,**kwargs)
        def incident_priority(self,key):
            from .investigation_links import InvestigationRegistry
            return InvestigationRegistry(self.reader.store).priority(key,access_token=self.token)
        def incident_revision_status(self,key,revision_id):
            return self.registry().revision_status(key,revision_id,access_token=self.token)
        def incident_priority_history(self,key,**kwargs):
            from .investigation_links import InvestigationRegistry
            return InvestigationRegistry(self.reader.store).priority_history(key,access_token=self.token,**kwargs)
        def incident_links(self,key):
            from .investigation_links import InvestigationRegistry
            return InvestigationRegistry(self.reader.store).for_incident(key,access_token=self.token)
        def investigations(self,publication):
            from .investigation_links import InvestigationRegistry
            return InvestigationRegistry(self.reader.store).list_for_publication(publication,access_token=self.token)
        def investigation(self,key):
            from .investigation_links import InvestigationRegistry
            return InvestigationRegistry(self.reader.store).read(key,access_token=self.token)
        def priority_preview(self,key,**choices):
            from .investigation_links import InvestigationRegistry
            return InvestigationRegistry(self.reader.store).preview_priority(key,access_token=self.token,**choices)
        def priority_decide(self,key,**choices):
            from .investigation_links import InvestigationRegistry
            return InvestigationRegistry(self.reader.store).decide_priority(key,access_token=self.token,**choices)
        def review_preview(self,key,**kwargs):return self.registry().preview(key,access_token=self.token,**kwargs)
        def review_decide(self,key,**kwargs):return self.registry().decide(key,access_token=self.token,**kwargs)
        def workflows(self,p,**kwargs):
            from .workflow_store import WorkflowStore
            return WorkflowStore(self.reader.store).for_publication(p,access_token=self.token,**kwargs)
        def workflow_state(self,p,key,**kwargs):
            from .workflow_store import WorkflowStore
            return WorkflowStore(self.reader.store).state_evidence(p,key,access_token=self.token,**kwargs)

    @contextmanager
    def factory():
        token=read_private_access_token(access_token_path);session=read_private_session(session_path)
        with connect(settings['database']) as connection:
            store=FoundationStore(connection,keys,settings['namespace'],settings['vault_path'],access_policy=policy)
            yield LiveProvider(InvestigationReader(store),token,session)
    return factory
