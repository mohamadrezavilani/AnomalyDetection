"""Evidence-backed behavior viewer; full events stored compressed in local DB."""
from __future__ import annotations

import gzip
import hashlib
import hmac
import json
import re
import sqlite3
import time
import uuid
from collections import Counter, defaultdict
from contextlib import contextmanager,nullcontext
from datetime import datetime, timezone
from pathlib import Path
from tempfile import SpooledTemporaryFile
from zoneinfo import ZoneInfo

from .privacy import Keys, generate_keys
from .viewer_raw import RawEvidenceMixin
from .viewer_bill_journey import BillItemJourneyMixin
from .viewer_service_sync import ServiceCatalogSyncMixin
from .viewer_service_catalog import role_proposal
from .viewer_capture import CaptureMixin
from .viewer_contract import PaymentContractMixin
from .viewer_payment_journey import ServicePaymentJourneyMixin
from .service_journey import ServiceJourneyMixin
from .viewer_service_context import ServiceContextMixin
from .session_behavior import SessionBehaviorMixin
from .viewer_semantic_index import SemanticIndexMixin
from .behavior_coverage import BehaviorCoverageMixin
from .parser import sql_parameters, opaque
from .viewer_projection_writes import ProjectionWritesMixin, REQUEST_TABLES, route_projection_statement

DB_PREFIX = 'p24_design_'
VIEWER_VERSION = 'p24-viewer-online-1'
ROOT_CALL = re.compile(r'^(?:Core|Services|Public|Ewano|Files|PaymentRedirect|PaymentCallback|Webhook|JobsQueue)\.')
STATUS_RE = re.compile(r'\((G[A-Z0-9]{4,8})\s*\|')
HEXISH = re.compile(r'^[A-Fa-f0-9-]{16,80}$')
SAFE_SCALAR = re.compile(r'^[A-Za-z0-9._:/-]{1,160}$')
# Unknown is deliberate: a newly observed API is NOT automatically a user action.
SERVICE_ROLES = ('business','user_management','support','system','unknown')
SERVICE_INITIATIONS = ('unknown','confirmed_manual','confirmed_automatic','system_followup')
# Limited, reviewable seeds. Only owner-confirmed initiations are marked confirmed.
OWNER_CONFIRMED = {
    'Services.v1/AddUserData': ('support','confirmed_automatic'),
    'Services.v1/GetUserData': ('support','confirmed_automatic'),
    'Services.v1/InvoiceRegister': ('support','confirmed_automatic'),
    # Owner clarification 2026-10-27: main market services. A service role
    # does not prove that every individual request was initiated by a click.
    'Public.v1/ExchangeCurrency': ('business','unknown'),
    'Public.v1/ExchangeGold': ('business','unknown'),
    'Public.v1/ExchangeCrypto': ('business','unknown'),
    # Owner explicitly identified these as homepage background calls.
    'Public.v1/Weather': ('support','confirmed_automatic'),
    'Public.v1/AirPollution': ('support','confirmed_automatic'),
    'Public.v1/CalendarToday': ('support','confirmed_automatic'),
    'Public.v1/CalendarMonth': ('support','confirmed_automatic'),
    'Public.v1/CalendarReligiousTimes': ('support','confirmed_automatic'),
}
# These roles are suggestions from observed workflow contracts and still editable.
CANDIDATE_ROLES = {
    'Services.v1/ElectricBills':'business',
    'Services.v1/LandLinePhoneBills':'business',
    'Services.v1/CellPhoneBills':'business',
    'Services.v1/WaterBills':'business',
    'Services.v1/GasBills':'business',
    'Services.v1/FreewayTollBills':'business',
    'Services.v1/PostPackagesStatus':'business',
    # Additional explicit service actions observed as independent HTTP root
    # requests in the 17-window inventory. These are *proposals*, not proof
    # that each call was directly initiated by a human click.
    'Services.v2/GasBills':'business',
    'Services.v2/FreewayTollBills':'business',
    'Services.v1/MunicipalityCarTollBills':'business',
    'Services.v1/CarAnnualTaxBills':'business',
    'Services.v1/TrafficFinesCar':'business',
    'Services.v1/TrafficFinesCarNoDetails':'business',
    'Services.v1/JusticeSharesPortfolio':'business',
    'Services.v1/NationalCardReceiveTracking':'business',
    'Services.v1/DrivingLicenseStatus':'business',
    'Services.v1/MilitaryCardIssuanceStatus':'business',
    'Services.v1/BankChequeStatusSayad':'business',
    'Services.v1/LivelihoodInformation':'business',
    'Services.v1/BankIbanInfo':'business',
    'Services.v2/BankIbanInfo':'business',
    'Services.v3/BankIbanInfo':'business',
    'Services.v1/VehiclePlateNumbers':'business',
    'Services.v1/IdentificationDocumentsStatusCar':'business',
    'Services.v1/FreewayTollBillsDetailed':'business',
    'Services.v1/TrafficFinesMotorcycle':'business',
    'Services.v2/ExitBanStatus':'business',
    'Services.v1/ExitBanStatus':'business',
    'Services.v2/PassportStatus':'business',
    'Services.v1/PlateNumberHistory':'business',
    'Services.v1/PostalCodeToAddress':'business',
    'Services.v1/MunicipalityCarAnnualTollBills':'business',
    'Services.v1/MunicipalityPropertyTollBills':'business',
    'Services.v1/TrafficFinesMotorcycleNoDetails':'business',
    'Services.v1/VehicleThirdPartyInsurance':'business',
    'Services.v1/TrafficFinesCarWithImage':'business',
    'Services.v1/TechnicalExaminationCertificateByVin':'business',
    'Services.v2/SocialSecurityInsuranceHistory':'business',
    'Services.v1/SocialSecurityInsuranceElectronicPrescription':'business',
    'Services.v1/RealEstateContract':'business',
    'Services.v2/RealEstateContract':'business',
    'Services.v2/TransferTaxMotorcycle':'business',
    'Services.v3/TransferTaxCar':'business',
    'Services.v1/TelecomRegisteredLines':'business',
    # Clearly contextual reads/init/login calls, not independent bill inquiry.
    'Core.v1/PaymentInfo':'support',
    'Core.v1/InvoiceInfo':'support',
    'Core.v1/UserWalletBalance':'support',
    'Core.v1/UserWallets':'support',
    'Core.v1/UserWalletChargeChannels':'support',
    'Core.v1/BillsPaymentChannels':'support',
    'Core.v1/UserInvoicePaymentSummary':'support',
    'Core.v1/UserBillsPaymentSummary':'support',
    'Core.v1/UserProfile':'support',
    'Core.v1/UserSessionInfo':'support',
    'Core.v1/UserCredentialInfo':'support',
    'Core.v1/UserSessionUpdateInfo':'support',
    'Core.v2/UserSessionUpdateInfo':'support',
    'Core.v1/BillsInfo':'support',
    'Core.v1/AutoPayGet':'support',
    'Core.v2/AutoPayGet':'support',
    'Core.v1/UserBasketGet':'support',
    'Core.v1/UserWalletCharge':'business',
    'Core.v1/LoginByOTP':'user_management',
    'Ewano.v1/EwanoLogin':'user_management',
    'Core.v1/LoginByUserCredential':'user_management',
    'Core.v1/UserServiceQueryNote':'user_management',
    'Core.v1/UserQuickAccessItemsUpdate':'user_management',
    'Core.v1/UserProfileUpdatePersonalInfo':'user_management',
    'Core.v1/UserCredentialChangePassword':'user_management',
    'Core.v1/UserBasketPayment':'business',
    'Core.v1/InvoicePayment':'business',
    'Core.v1/BillsPayment':'business',
    'Core.v1/WalletPayment':'business',
    'Core.v1/UserBasketPayment':'business',
    'Core.v1/UserBasketAddBills':'user_management',
    'Core.v1/UserServiceQueryBookmark':'user_management',
    'Core.v1/UserServiceQueryDelete':'user_management',
    'Core.v1/UserBasketDeleteItems':'user_management',
    'Core.v1/ConfigBasic':'support',
    'Core.v1/ConfigService':'support',
    'Core.v1/ConfigSearch':'support',
    'Core.v1/UserBasketGetItemCount':'support',
    'Core.v1/UserQuickAccessItems':'support',
    'Core.v1/UserServicesRecentlyUsed':'support',
    'Core.v1/UserServiceQueries':'support',
}
SYSTEM_PREFIXES = ('Webhook.', 'PaymentCallback.', 'JobsQueue.')
INQUIRIES={'ElectricBills','LandLinePhoneBills','CellPhoneBills','WaterBills','GasBills','FreewayTollBills','PostPackagesStatus'}


def service_path(root_call):
    """Stable API identity without the source-code line number."""
    return str(root_call).split(' Line:',1)[0].strip()


def initial_service_role(path):
    if path in OWNER_CONFIRMED:
        role,initiation=OWNER_CONFIRMED[path]
        return role,initiation,'owner_confirmed'
    if path.startswith(SYSTEM_PREFIXES):
        return 'system','system_followup','inferred'
    if path in CANDIDATE_ROLES:
        return CANDIDATE_ROLES[path],'unknown','inferred'
    proposal=role_proposal(path)
    if proposal and proposal['role']!='unknown':
        return proposal['role'],proposal['initiation'],'source_backed'
    return 'unknown','unknown','unclassified'


def utc_ns(raw):
    if not isinstance(raw,str):return None
    try:
        # ISO 8601 permits 7 fractional digits; Python 3.12 truncates at us.
        m=re.match(r'^(.*?)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)$',raw)
        if not m:return None
        left,frac,tz=m.groups(); nanos=int((frac or '')[:9].ljust(9,'0'))
        dt=datetime.fromisoformat(left+('+00:00' if tz=='Z' else tz))
        sec=int(dt.timestamp())
        return sec*1_000_000_000+nanos
    except (ValueError,OverflowError):return None


def tehran(ns):
    if ns is None:return 'زمان نامشخص'
    return datetime.fromtimestamp(ns//1_000_000_000,timezone.utc).astimezone(ZoneInfo('Asia/Tehran')).strftime('%Y-%m-%d %H:%M:%S')


def token(keys,kind,value):
    if value is None:return None
    return keys.token('p24-viewer.1',kind,value).split(':')[-1]


def clean_scalar(value):
    if not isinstance(value,str) or not SAFE_SCALAR.fullmatch(value):return None
    return value


def source_identity(row):
    sid=row.get('_source_id')
    if isinstance(sid,str) and ':' in sid:
        a,b=sid.split(':',1)
        if a and b:return a,b
    meta=row.get('_es_export_meta') or {}
    if isinstance(meta,dict) and meta.get('index') and meta.get('id'):
        return str(meta['index']),str(meta['id'])
    return None,None


def classify(call):
    if ROOT_CALL.match(call):return 'client'
    if call.startswith('DBPath.'):return 'sql'
    if call.startswith('CacheCoreApi.'):return 'cache'
    if call.startswith(('Client','PaymentGateway.')):return 'provider'
    return 'other'


def core_name(call):
    stem=call.split(' Line:',1)[0]
    if '/' in stem:return stem.rsplit('/',1)[-1]
    return stem.rsplit('.',1)[-1]


def safe_codes(message):
    if not isinstance(message,str):return None
    m=STATUS_RE.search(message[:450]);return m.group(1) if m else None


def sql_links(message):
    if not isinstance(message,str) or '(SQL Parameters:' not in message:return {}
    try:params,_=sql_parameters(message)
    except Exception:return {}
    out={}
    rules={'paymentkey':'platform_payment','invoiceuniqueid':'invoice',
           'queryuniqueid':'query','purchasekey':'purchase',
           'billid':'bill_id','paymentid':'payment_id','queryindex':'query_index',
           'billsuniqeid':'bill_unique_id','billuniqueid':'bill_unique_id',
           'basketid':'basket','paymentrequestid':'basket_payment_request',
           'queryparametershash':'query_parameters_hash','queryindexhash':'query_index_hash'}
    for k,domain in rules.items():
        v=clean_scalar(params.get(k))
        if v and v not in ('0','N/A'):
            out[domain]=v
    return out


def paid_observation(message,call):
    """Return named evidence only; never retain full bodies, names, tokens or PAN."""
    if not isinstance(message,str):return None
    if 'ud_prc_webhooksInformBillPaymentStatus_v1' in call:
        # Callback SQL explicitly records a successful payment notification.
        if re.search(r'@description=پرداخت با موفقیت',message):return 'webhook_payment_success'
        return 'webhook_notification_unknown'
    if 'GetPaymentInfo' in call and 'Output:[' in message:
        # API messages contain nested JSON, and Paid is sometimes inside stringified ExtraInfo.
        match=re.search(r'\\?"Paid\\?"\s*:\s*(true|false)',message,re.I)
        if match:return 'paid_true' if match.group(1).lower()=='true' else 'paid_false'
    if 'ud_prc_inquiryInvoiceResult2' in call:
        try:
            params,_=sql_parameters(message)
            status=params.get('statuscode')
            if status and re.fullmatch(r'[A-Z][A-Z0-9]{4,7}',status):
                return 'business_code:'+status
        except Exception:pass
    if 'Output:[' in message:
        m=re.search(r'\"Status\"\s*:\s*\{\s*\"Code\"\s*:\s*\"([A-Z0-9]{5,8})\"',message)
        if m:return 'provider_code:'+m.group(1)
    return None


def deep_objects(value, depth=0):
    """Walk typed JSON including nested JSON-encoded strings; bounded depth."""
    if depth>8:return
    if isinstance(value,dict):
        yield value
        for child in value.values(): yield from deep_objects(child,depth+1)
    elif isinstance(value,list):
        for child in value:yield from deep_objects(child,depth+1)
    elif isinstance(value,str) and value.lstrip().startswith(('[','{')):
        try:yield from deep_objects(json.loads(value),depth+1)
        except (ValueError,TypeError):pass


def message_json(message, marker):
    if not isinstance(message,str) or marker not in message:return None
    try:return json.JSONDecoder().raw_decode(message.split(marker,1)[1].lstrip())[0]
    except (ValueError,TypeError):return None


def financial_bill_items(message, call):
    """Extract *typed* bill identities from a payment outcome; not arbitrary text matches.

    Returns [(bill_id, payment_id, amount_or_None, paid_or_None)]. Each item
    is independent. Incomplete identity is not enough to certify settlement.
    """
    items=[]
    if not isinstance(message,str):return items
    if 'ud_prc_webhooksInformBillPaymentStatus_v1' in call or 'ud_prc_paymentServiceReportTransaction' in call:
        try:
            params,_=sql_parameters(message)
            bill=clean_scalar(params.get('billid'));pay=clean_scalar(params.get('paymentid'))
            amount=clean_scalar(params.get('amount'))
            if bill and pay: items.append((bill,pay,amount,None))
        except Exception:pass
    if 'GetPaymentInfo' in call and 'Output:' in message:
        try:
            # Decode the exact JSON output block; don't regex the first Paid
            # bit in a possibly multi-bill payload.
            fragment=message.split('Output:',1)[1].lstrip()
            output,_=json.JSONDecoder().raw_decode(fragment)
            stack=[output]
            while stack:
                obj=stack.pop()
                if isinstance(obj,list):stack.extend(obj)
                elif isinstance(obj,dict):
                    bid=obj.get('BillID');pid=obj.get('PaymentID')
                    if bid is not None and pid is not None:
                        bill=clean_scalar(str(bid));pay=clean_scalar(str(pid))
                        paid=obj.get('Paid')
                        if bill and pay:items.append((bill,pay,str(obj['Amount']) if obj.get('Amount') is not None else None,
                                                     paid if isinstance(paid,bool) else None))
                    for val in obj.values():
                        if isinstance(val,(dict,list)):stack.append(val)
                        elif isinstance(val,str) and val.lstrip().startswith(('[','{')):
                            try:stack.append(json.loads(val))
                            except (ValueError,TypeError):pass
        except (ValueError,TypeError):pass
    return items



SCHEMA = [
'''CREATE TABLE IF NOT EXISTS viewer_files(
 file_hash TEXT PRIMARY KEY, filename TEXT NOT NULL, window_start TEXT, window_end TEXT,
 declared_count INTEGER, record_count INTEGER NOT NULL, new_events INTEGER NOT NULL,
 duplicate_events INTEGER NOT NULL, conflicting_events INTEGER NOT NULL, imported_at TEXT NOT NULL,
 source_claim TEXT NOT NULL, issue TEXT)''',
'''CREATE TABLE IF NOT EXISTS viewer_events(
 origin_key TEXT NOT NULL, version_key TEXT NOT NULL, file_hash TEXT NOT NULL,
 filename TEXT NOT NULL, row_number INTEGER NOT NULL, at_ns BIGINT,
 request_key TEXT, session_key TEXT, ip_key TEXT, callpath TEXT NOT NULL,
 kind TEXT NOT NULL, code TEXT, observation TEXT, PRIMARY KEY(origin_key,version_key))''',
'''CREATE TABLE IF NOT EXISTS viewer_links(
 origin_key TEXT NOT NULL, version_key TEXT NOT NULL, request_key TEXT,
 link_domain TEXT NOT NULL, link_key TEXT NOT NULL,
 PRIMARY KEY(origin_key,version_key,link_domain,link_key))''',
'''CREATE TABLE IF NOT EXISTS viewer_event_captures(
 file_hash TEXT NOT NULL,origin_key TEXT NOT NULL,capture_key TEXT NOT NULL,
 canonical_version_key TEXT NOT NULL,row_number INTEGER NOT NULL,
 PRIMARY KEY(file_hash,origin_key,capture_key))''',
'''CREATE TABLE IF NOT EXISTS viewer_requests(
 request_key TEXT PRIMARY KEY, session_key TEXT, identity_state TEXT NOT NULL,
 started_ns BIGINT, ended_ns BIGINT, root_ns BIGINT, root_call TEXT,
 root_code TEXT, root_count INTEGER NOT NULL, event_count INTEGER NOT NULL,
 sql_count INTEGER NOT NULL, provider_count INTEGER NOT NULL,
 conflicted INTEGER NOT NULL, initiation TEXT NOT NULL)''',
'''CREATE TABLE IF NOT EXISTS viewer_actions(
 action_key TEXT PRIMARY KEY, session_key TEXT, label TEXT NOT NULL,
 name TEXT NOT NULL, category TEXT NOT NULL, initiation TEXT NOT NULL,
 at_ns BIGINT, current_outcome TEXT, root_request_key TEXT,
 target_type TEXT, target_key TEXT, workflow_key TEXT, evidence TEXT)''',
'''CREATE TABLE IF NOT EXISTS viewer_action_history(
 action_key TEXT NOT NULL, at_ns BIGINT, status TEXT NOT NULL, source_request_key TEXT NOT NULL,
 source_callpath TEXT NOT NULL, origin_key TEXT NOT NULL, version_key TEXT NOT NULL,
 PRIMARY KEY(action_key,origin_key,version_key,status))''',
'''CREATE TABLE IF NOT EXISTS viewer_service_roles(
 service_path TEXT PRIMARY KEY, role TEXT NOT NULL, initiation TEXT NOT NULL,
 source TEXT NOT NULL, reviewed INTEGER NOT NULL DEFAULT 0, note TEXT NOT NULL DEFAULT '',
 changed_at TEXT NOT NULL)''',
'''CREATE TABLE IF NOT EXISTS viewer_service_role_history(
 change_id TEXT PRIMARY KEY, service_path TEXT NOT NULL, old_role TEXT NOT NULL,
 new_role TEXT NOT NULL, old_initiation TEXT NOT NULL, new_initiation TEXT NOT NULL,
 note TEXT NOT NULL, changed_at TEXT NOT NULL)''',
'CREATE INDEX IF NOT EXISTS vei_request ON viewer_events(request_key,at_ns)',
'CREATE INDEX IF NOT EXISTS vei_session ON viewer_events(session_key,at_ns)',
'CREATE INDEX IF NOT EXISTS vei_time ON viewer_events(at_ns)',
'CREATE INDEX IF NOT EXISTS vei_callpath ON viewer_events(callpath)',
'CREATE INDEX IF NOT EXISTS vli_value ON viewer_links(link_domain,link_key)',
'CREATE INDEX IF NOT EXISTS vli_request ON viewer_links(request_key)',
'CREATE INDEX IF NOT EXISTS vri_session ON viewer_requests(session_key,ended_ns)',
'CREATE INDEX IF NOT EXISTS vri_call ON viewer_requests(root_call)',
'CREATE INDEX IF NOT EXISTS vri_paged_at ON viewer_requests(COALESCE(root_ns,started_ns) DESC,request_key DESC)',
'CREATE INDEX IF NOT EXISTS vai_session ON viewer_actions(session_key,at_ns)',
'CREATE INDEX IF NOT EXISTS vai_category ON viewer_actions(category,at_ns)',
]


class ViewerDB(ServiceContextMixin, ServicePaymentJourneyMixin, BillItemJourneyMixin, ProjectionWritesMixin, ServiceCatalogSyncMixin, SemanticIndexMixin, BehaviorCoverageMixin, SessionBehaviorMixin, ServiceJourneyMixin, PaymentContractMixin, CaptureMixin, RawEvidenceMixin):
    def __init__(self,*,sqlite_path=None,config=None,keys_path):
        self.keys=Keys.read(keys_path)
        self.sqlite=sqlite_path is not None
        if self.sqlite:
            self.conn=sqlite3.connect(str(sqlite_path),timeout=60)
            self.conn.row_factory=sqlite3.Row
            self.conn.execute('PRAGMA journal_mode=WAL');self.conn.execute('PRAGMA synchronous=NORMAL')
        else:
            import psycopg
            db=dict(config)
            if not str(db.get('dbname','')).startswith(DB_PREFIX):
                raise ValueError('guard: use a disposable p24_design_* PostgreSQL database')
            if db.get('dbname')=='pishkhan24_shadow':raise ValueError('application database forbidden')
            self.conn=psycopg.connect(**db)
            from psycopg.rows import dict_row
            self.conn.row_factory=dict_row
        self.param='?' if self.sqlite else '%s'

    def close(self):self.conn.close()
    def __enter__(self):return self
    def __exit__(self,*args):self.close()
    def sql(self,statement,params=()):
        statement=route_projection_statement(statement,getattr(self,'_projection_routes',None))
        if not self.sqlite: statement=statement.replace('?',self.param)
        return self.conn.execute(statement,params)
    def all(self,q,p=()):return [dict(x) for x in self.sql(q,p).fetchall()]
    def one(self,q,p=()):
        x=self.sql(q,p).fetchone();return dict(x) if x else None
    def progress(self,stage,**counts):
        callback=getattr(self,'progress_callback',None)
        if callback:
            try:callback(dict(stage=stage,**counts))
            except OSError:pass  # A closed console must not change publication.
    @contextmanager
    def bulk_writes(self):
        # psycopg pipeline groups wire round-trips but never commits. Readers
        # still see only the complete atomic publication from the outer caller.
        pipeline=getattr(self.conn,'pipeline',None) if not self.sqlite else None
        with pipeline() if callable(pipeline) else nullcontext():yield
    def many(self,statement,values):
        if not values:return
        statement=route_projection_statement(statement,getattr(self,'_projection_routes',None))
        if not hasattr(self.conn,'cursor'):
            for params in values:self.sql(statement,params)
            return
        cursor=self.conn.cursor()
        try:cursor.executemany(statement if self.sqlite else statement.replace('?',self.param),values)
        finally:cursor.close()
    _INGEST_INSERTS={
        'viewer_events':('origin_key,version_key,file_hash,filename,row_number,at_ns,request_key,session_key,ip_key,callpath,kind,code,observation',''),
        'viewer_raw_events':('origin_key,version_key,raw_request_id,raw_session_id,raw_ip,payload',' ON CONFLICT(origin_key,version_key) DO NOTHING'),
        'viewer_event_captures':('file_hash,origin_key,capture_key,canonical_version_key,row_number',' ON CONFLICT DO NOTHING'),
        'viewer_links':('origin_key,version_key,request_key,link_domain,link_key',''),
        'viewer_capture_projections':('origin_key,capture_key,canonical_version_key,file_hash,filename,row_number,payload',' ON CONFLICT DO NOTHING'),
    }
    _INGEST_ORDER={
        'viewer_events':'origin_key,version_key',
        'viewer_raw_events':'origin_key,version_key',
        'viewer_event_captures':'file_hash,origin_key,capture_key,row_number',
        'viewer_links':'origin_key,version_key,link_domain,link_key',
        'viewer_capture_projections':'origin_key,capture_key,row_number',
    }
    def _ingest_insert(self,table,values):
        columns,conflict=self._INGEST_INSERTS[table]
        buffers=getattr(self,'_ingest_buffers',None)
        if buffers is not None:buffers.setdefault(table,[]).append(values)
        else:self.sql('INSERT INTO '+table+'('+columns+') VALUES ('+','.join('?' for _ in values)+')'+conflict,values)
    @contextmanager
    def _ingest_writer(self):
        # COPY buffers are bounded. Stages append for one capture, then merge
        # once per table in the existing publication transaction. The capture's
        # origin/version cache makes unmerged earlier batches visible to the
        # revision decisions without repeatedly rewriting stage storage.
        enabled=not self.sqlite and callable(getattr(self.conn,'pipeline',None))
        self._ingest_buffers={} if enabled else None
        self._ingest_stage_ready=set()
        self._ingest_stage_rows={}
        try:
            yield
            self._flush_ingest_batch()
            self._merge_ingest_stages()
        finally:
            self._ingest_buffers=None
            self._ingest_stage_ready=set()
            self._ingest_stage_rows={}
    def _flush_ingest_batch(self):
        buffers=getattr(self,'_ingest_buffers',None)
        if not buffers:return
        started=time.monotonic()
        for table,values in buffers.items():
            if not values:continue
            columns,_=self._INGEST_INSERTS[table]
            stage='viewer_stage_'+table.removeprefix('viewer_')
            if table not in self._ingest_stage_ready:
                setup_started=time.monotonic()
                self.sql('CREATE TEMP TABLE IF NOT EXISTS '+stage+' (LIKE '+table+') ON COMMIT DROP')
                # A second input file may reuse these stages before the outer
                # transaction commits. Clear once per file, never per batch.
                self.sql('TRUNCATE TABLE '+stage)
                self._ingest_stage_ready.add(table)
                self._ingest_stage_details['setup_seconds']+=time.monotonic()-setup_started
            copy_started=time.monotonic()
            self._copy_ingest_stage(stage,columns,values)
            self._ingest_stage_details['copy_seconds']+=time.monotonic()-copy_started
            self._ingest_stage_rows[table]=self._ingest_stage_rows.get(table,0)+len(values)
            values.clear()
        timing=getattr(self,'_ingest_timing',None)
        if timing is not None:timing['staging_seconds']+=time.monotonic()-started
    def _merge_ingest_stages(self):
        for table,count in self._ingest_stage_rows.items():
            self.progress('ingest_merge',table=table,rows=count)
            started=time.monotonic()
            columns,conflict=self._INGEST_INSERTS[table]
            stage='viewer_stage_'+table.removeprefix('viewer_')
            # These two tables already contain only genuinely new versions.
            # Keep their strict PK errors, while using PostgreSQL's bulk heap
            # insertion instead of one INSERT executor operation per row.
            if table in ('viewer_events','viewer_links'):
                # Production remains on the existing strict native COPY path.
                # Only a disposable qualification harness may select an A/B
                # transport explicitly on this connection; never read env vars.
                method=getattr(self,'_qualification_final_write_method','copy_binary')
                if method not in ('copy_binary','insert_select_ordered','insert_select_unordered'):
                    raise ValueError('invalid_qualification_final_write_method')
                if method=='copy_binary':
                    from .viewer_storage_keys import KEYS,detect,digest_sql
                    order=digest_sql(KEYS[table]) if table in KEYS and detect(self) else self._INGEST_ORDER[table]
                    self._copy_ingest_stage_into_table(stage,table,columns,order)
                else:
                    self._insert_ingest_stage_into_table(stage,table,columns,
                        self._INGEST_ORDER[table] if method=='insert_select_ordered' else None)
            else:
                method='insert_select'
                self._insert_ingest_stage_into_table(stage,table,columns,self._INGEST_ORDER[table],conflict)
            elapsed=time.monotonic()-started
            self._ingest_timing['staging_seconds']+=elapsed
            self._ingest_stage_details['merge_seconds']+=elapsed
            self.progress('ingest_merge_complete',table=table,rows=count,seconds=round(elapsed,3),method=method)
    def _insert_ingest_stage_into_table(self,stage,table,columns,order,conflict=''):
        # Identical columns and strict conflict behavior: deliberately no
        # ON CONFLICT for viewer_events / viewer_links. This alternative is
        # reserved for isolated, controlled A/B runs until native qualification.
        query='INSERT INTO '+table+' ('+columns+') SELECT '+columns+' FROM '+stage
        if order:query+=' ORDER BY '+order
        self.sql(query+conflict)

    def _copy_ingest_stage_into_table(self,stage,table,columns,order):
        # A single connection cannot read and write COPY streams at once.
        # Keep the previous strict PK ordering and one publication transaction.
        # Separate server export, spool, client upload and command completion.
        export_started=time.monotonic()
        with SpooledTemporaryFile(max_size=128*1024*1024,mode='w+b') as spool:
            with self.conn.cursor() as cursor:
                with cursor.copy('COPY (SELECT '+columns+' FROM '+stage+' ORDER BY '+order+') TO STDOUT (FORMAT BINARY)') as copy:
                    for block in copy:spool.write(block)
            export_seconds=time.monotonic()-export_started
            bytes_in_spool=spool.tell()
            spool_on_disk=bool(getattr(spool,'_rolled',False))
            spool.seek(0)
            self.progress('ingest_bulk_copy',table=table,phase='write_final_table',
                export_seconds=round(export_seconds,3),spool_bytes=bytes_in_spool,
                spool_disk_rollover=spool_on_disk)
            upload_started=time.monotonic();bytes_uploaded=0
            try:
                with self.conn.cursor() as cursor:
                    with cursor.copy('COPY '+table+' ('+columns+') FROM STDIN (FORMAT BINARY)') as copy:
                        for block in iter(lambda:spool.read(1024*1024),b''):
                            bytes_uploaded+=len(block)
                            copy.write(block)
            finally:
                # Includes PostgreSQL's finish/acknowledgement and index work.
                self.progress('ingest_bulk_copy_completed',table=table,
                    export_seconds=round(export_seconds,3),
                    upload_and_finish_seconds=round(time.monotonic()-upload_started,3),
                    spool_bytes=bytes_in_spool,bytes_uploaded=bytes_uploaded,
                    spool_disk_rollover=spool_on_disk)
    def _ingest_progress(self,processed,total,started):
        timing=self._ingest_timing
        self.progress('ingest',processed=processed,total=total,
            lookup_seconds=round(timing['lookup_seconds'],3),
            stage_copy_merge_seconds=round(timing['staging_seconds'],3),
            **{name:round(value,3) for name,value in self._ingest_stage_details.items()},
            parse_encode_other_seconds=round(max(0,time.monotonic()-started-sum(timing.values())),3))
    def _copy_ingest_stage(self,stage,columns,values):
        with self.conn.cursor() as cursor:
            with cursor.copy('COPY '+stage+' ('+columns+') FROM STDIN') as copy:
                for row in values:copy.write_row(row)
    def _ingest_batches_globally_ordered(self, rows, digest, batch_size=500, lookup_chunk=2048):
        """Candidate: read already-stored origins once, in global B-tree order.

        Preserve original capture order, revision decisions, stage writes, and
        publisher transaction. Only the order and grouping of *reads* change.
        The local known-version lists remain mutable for versions added later
        within this very same capture. Qualification-only: enable explicitly.
        """
        import zlib
        if not 1 <= lookup_chunk <= 4096:
            raise ValueError('invalid_origin_lookup_chunk')
        prepared=[]
        for n,row in enumerate(rows):
            if not isinstance(row,dict):
                raise ValueError('non_object_record')
            index,doc_id=source_identity(row)
            origin=token(self.keys,'origin',[index,doc_id] if index else [digest,n])
            prepared.append((n,row,origin,token(self.keys,'version',row)))
        all_origins=sorted({record[2] for record in prepared})
        known={origin:[] for origin in all_origins}
        raw_lookup={}
        lookup_started=time.monotonic()
        # SQL parameters stay well below PostgreSQL's bind limit. Sorted
        # *globally*, not independently in 500-row source-order batches.
        for offset in range(0,len(all_origins),lookup_chunk):
            origins=all_origins[offset:offset+lookup_chunk]
            placeholders=','.join('?' for _ in origins)
            for old in self.all('SELECT origin_key,version_key,request_key FROM viewer_events WHERE origin_key IN ('+placeholders+')',origins):
                known[old['origin_key']].append(old)
        self._ingest_timing['lookup_seconds']+=time.monotonic()-lookup_started
        for offset in range(0,len(prepared),batch_size):
            self._flush_ingest_batch()
            batch=prepared[offset:offset+batch_size]
            candidates=sorted({origin for _,_,origin,sig in batch
                if known[origin] and not any(v['version_key']==sig for v in known[origin])
                and any((origin,v['version_key']) not in raw_lookup for v in known[origin])})
            if candidates:
                started=time.monotonic()
                for piece in range(0,len(candidates),lookup_chunk):
                    group=candidates[piece:piece+lookup_chunk]
                    for raw in self.all('SELECT origin_key,version_key,payload FROM viewer_raw_events WHERE origin_key IN ('+
                                        ','.join('?' for _ in group)+')',group):
                        raw_lookup[(raw['origin_key'],raw['version_key'])]=json.loads(
                            zlib.decompress(bytes(raw['payload'])).decode('utf-8'))
                self._ingest_timing['lookup_seconds']+=time.monotonic()-started
            for n,row,origin,sig in batch:
                yield n,row,origin,sig,known[origin],raw_lookup

    def _ingest_batches(self,rows,digest,batch_size=500):
        """Bounded SQL lookups plus capture-local state across staged batches.

        Raw entries for new versions reference the already loaded source rows;
        this cache covers this capture, never the whole database history.
        """
        if getattr(self,'_qualification_origin_lookup',
                   'legacy' if self.sqlite else 'global_ordered')=='global_ordered':
            yield from self._ingest_batches_globally_ordered(rows,digest,batch_size=batch_size)
            return
        import zlib
        known={};raw_lookup={}
        for offset in range(0,len(rows),batch_size):
            self._flush_ingest_batch()
            prepared=[]
            for n,row in enumerate(rows[offset:offset+batch_size],offset):
                if not isinstance(row,dict):raise ValueError('non_object_record')
                index,doc_id=source_identity(row)
                origin=token(self.keys,'origin',[index,doc_id] if index else [digest,n])
                prepared.append((n,row,origin,token(self.keys,'version',row)))
            origins=sorted({x[2] for x in prepared if x[2] not in known})
            slots=','.join('?' for _ in origins)
            lookup_started=time.monotonic()
            for origin in origins:known[origin]=[]
            if origins:
                for old in self.all('SELECT origin_key,version_key,request_key FROM viewer_events WHERE origin_key IN ('+slots+')',origins):
                    known[old['origin_key']].append(old)
            candidates=sorted({origin for _,_,origin,sig in prepared
                if known[origin] and not any(v['version_key']==sig for v in known[origin])
                and any((origin,v['version_key']) not in raw_lookup for v in known[origin])})
            if candidates:
                for raw in self.all('SELECT origin_key,version_key,payload FROM viewer_raw_events WHERE origin_key IN ('+
                                     ','.join('?' for _ in candidates)+')',candidates):
                    raw_lookup[(raw['origin_key'],raw['version_key'])]=json.loads(zlib.decompress(bytes(raw['payload'])).decode('utf-8'))
            self._ingest_timing['lookup_seconds']+=time.monotonic()-lookup_started
            for n,row,origin,sig in prepared:
                yield n,row,origin,sig,known[origin],raw_lookup
    def write_lock(self):
        """Serialize role edits, maintenance and atomic live publication."""
        if self.sqlite:
            if not self.conn.in_transaction:self.sql('BEGIN IMMEDIATE')
        else:self.sql('SELECT pg_advisory_xact_lock(240026, 2)')
    def init(self):
        for stmt in SCHEMA:self.sql(stmt)
        self.conn.commit()
        self.init_raw()
        self.init_payment_contract()
        self.init_capture()
        self.sync_service_catalog()
        layout=getattr(self,'_qualification_storage_layout','compact_evidence_keys_v1')
        if layout not in ('legacy','compact_evidence_keys_v1'):raise ValueError('invalid_storage_layout')
        if layout!='legacy':
            from .viewer_storage_keys import ensure
            ensure(self)

    def ensure_service_roles(self, paths=None):
        # Discover real HTTP root paths without overwriting operator decisions.
        self.sql('''CREATE TABLE IF NOT EXISTS viewer_service_roles(
 service_path TEXT PRIMARY KEY, role TEXT NOT NULL, initiation TEXT NOT NULL,
 source TEXT NOT NULL, reviewed INTEGER NOT NULL DEFAULT 0, note TEXT NOT NULL DEFAULT '',
 changed_at TEXT NOT NULL)''')
        self.sql('''CREATE TABLE IF NOT EXISTS viewer_service_role_history(
 change_id TEXT PRIMARY KEY, service_path TEXT NOT NULL, old_role TEXT NOT NULL,
 new_role TEXT NOT NULL, old_initiation TEXT NOT NULL, new_initiation TEXT NOT NULL,
 note TEXT NOT NULL, changed_at TEXT NOT NULL)''')
        if paths is None:
            paths={service_path(r['root_call']) for r in self.all(
                'SELECT DISTINCT root_call FROM viewer_requests WHERE root_call IS NOT NULL')}
        now=datetime.now(timezone.utc).isoformat()
        for path in sorted(paths):
            role,initiation,source=initial_service_role(path)
            self.sql('''INSERT INTO viewer_service_roles(service_path,role,initiation,source,reviewed,note,changed_at)
                        VALUES(?,?,?,?,0,'',?) ON CONFLICT DO NOTHING''',
                     (path,role,initiation,source,now))
            # New, evidence-based seeds may upgrade *unreviewed* unknowns.
            # Manual classifications (including manually chosen unknown) win.
            if role != 'unknown':
                self.sql('''UPDATE viewer_service_roles
                   SET role=?,initiation=?,source=?,changed_at=?
                   WHERE service_path=? AND role='unknown' AND reviewed=0
                   AND source='unclassified' ''',
                   (role,initiation,source,now,path))
        return paths

    def service_roles(self,limit=25,offset=0,search='',role=''):
        # All observed root routes; global counts not page totals.
        # Sample request links use exact canonical API paths.
        counted=defaultdict(lambda: [0,0,None])
        from .service_dispatch import TRANSPORT,dispatch_catalog
        for r in self.all('''SELECT r.root_call,a.label,COUNT(*) AS n,
                                   SUM(CASE WHEN r.session_key IS NOT NULL THEN 1 ELSE 0 END) AS with_session,
                                   MIN(r.request_key) AS sample_key
                            FROM viewer_requests r LEFT JOIN viewer_actions a ON a.action_key=r.request_key
                            WHERE r.root_call IS NOT NULL GROUP BY r.root_call,a.label'''):
            path=service_path(r['root_call'])
            if path==TRANSPORT and r['label'] in dispatch_catalog()['routes']:path=r['label']
            slot=counted[path]
            slot[0]+=r['n'];slot[1]+=r['with_session']
            if slot[2] is None or r['sample_key']<slot[2]:slot[2]=r['sample_key']
        rows=self.all('SELECT * FROM viewer_service_roles ORDER BY service_path')
        totals={key:0 for key in SERVICE_ROLES}
        sources=Counter()
        for row in rows:
            totals[row['role']]+=1
            sources[row['source']]+=1
            row['catalog_proposal']=role_proposal(row['service_path'])
            row['operator_preserved']=bool(row['reviewed'] or row['source']=='operator')
        all_count=len(rows)
        if search:rows=[r for r in rows if search.lower() in r['service_path'].lower()]
        if role:rows=[r for r in rows if r['role']==role]
        for r in rows:
            r['requests'],r['with_session'],r['sample_request_key']=counted.get(r['service_path'],(0,0,None))
        rows.sort(key=lambda r:(-r['requests'],r['service_path']))
        visible=rows[offset:offset+limit]
        # Display the original ID when available; otherwise the internal link
        # remains usable. Only resolve raw bodies for the current page.
        for r in visible:
            sample=r['sample_request_key']
            r['sample_request_id']=self.raw_request_id(sample) if sample else None
        return dict(items=visible,total=len(rows),limit=limit,offset=offset,
                    unknown=sum(r['role']=='unknown' for r in rows),
                    global_total=all_count,role_totals=totals,source_totals=dict(sources))

    def update_service_role(self,path,role,initiation,note=''):
        if role not in SERVICE_ROLES or initiation not in SERVICE_INITIATIONS:raise ValueError('invalid_service_classification')
        if len(note)>240:raise ValueError('note_too_long')
        self.write_lock()
        self.ensure_service_roles()
        existing=self.one('SELECT * FROM viewer_service_roles WHERE service_path=?',(path,))
        if not existing:raise ValueError('unknown_service_path')
        try:
            self.sql('''INSERT INTO viewer_service_role_history VALUES(?,?,?,?,?,?,?,?)''',
                     (uuid.uuid4().hex,path,existing['role'],role,existing['initiation'],initiation,
                      note,datetime.now(timezone.utc).isoformat()))
            self.sql('''UPDATE viewer_service_roles
                   SET role=?,initiation=?,note=?,source='operator',reviewed=1,changed_at=?
                   WHERE service_path=?''',(role,initiation,note,datetime.now(timezone.utc).isoformat(),path))
            # Apply immediately without rebuilding raw events, and across all HTTP
            # line-number variants (exact equality, never wildcard LIKE matching).
            raw_calls=self.all('SELECT DISTINCT root_call FROM viewer_requests WHERE root_call IS NOT NULL')
            for raw in (r['root_call'] for r in raw_calls if service_path(r['root_call'])==path):
                self.sql('''UPDATE viewer_actions SET category=?,initiation=?
                             WHERE root_request_key IN (SELECT request_key FROM viewer_requests WHERE root_call=?)''',
                         (role,initiation,raw))
            # A reviewed role edit changes the same semantic anchor, not a
            # second human action. Reconcile inside this exact transaction.
            impacted=[]
            for call in (r['root_call'] for r in raw_calls if service_path(r['root_call'])==path):
                impacted.extend(r['request_key'] for r in self.all(
                    'SELECT request_key FROM viewer_requests WHERE root_call=?',(call,)))
            impacted=sorted(set(impacted+self.dispatched_request_keys(path)))
            self.reconcile_service_dispatches(impacted)
            if self.semantic_checkpoint():
                self.reconcile_semantic_requests(impacted,commit=False)
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def ingest(self,paths,*,commit=True,_validated_capture=None):
        if _validated_capture is not None:
            paths=tuple(paths)
            if commit or len(paths)!=1:
                raise ValueError('validated_capture_requires_single_atomic_publication')
        self._ingest_impacted=set()
        results=[]
        for path in paths:
            self.write_lock()
            path=Path(path).resolve()
            digest=(hashlib.sha256(path.read_bytes()).hexdigest()
                    if _validated_capture is None else _validated_capture[0])
            prev=self.one('SELECT * FROM viewer_files WHERE file_hash=?',(digest,))
            if prev:
                results.append(dict(file=path.name,status='ALREADY_IMPORTED',sha256=digest,rows=prev['record_count'],new_events=0));continue
            try:
                if _validated_capture is None:
                    with gzip.open(path,'rt',encoding='utf-8') as stream:
                        payload=json.load(stream)
                else:
                    payload=_validated_capture[1]
                rows=payload['logs'];start=payload['window_start'];end=payload['window_end']
                if not isinstance(rows,list) or not isinstance(start,str) or not isinstance(end,str):raise ValueError('invalid_dump_contract')
                if utc_ns(start) is None or utc_ns(end) is None or utc_ns(start)>=utc_ns(end):raise ValueError('invalid_window')
                declared=payload.get('count')
                count_issue=(declared != len(rows))
                verification=payload.get('verification')
                proof_verified=(isinstance(verification,dict) and bool(verification) and not count_issue
                                and (verification.get('status') in ('verified','PASS','complete','COMPLETE')
                                     or (verification.get('counts_match') is True
                                         and verification.get('query_snapshot_complete') is True
                                         and verification.get('reached_empty_page') is True)))
            except Exception as exc:
                if not commit:raise
                results.append(dict(file=path.name,status='REJECTED',error=type(exc).__name__));continue
            new=dup=conf=0
            self._ingest_timing=dict(lookup_seconds=0.0,staging_seconds=0.0)
            self._ingest_stage_details=dict(setup_seconds=0.0,copy_seconds=0.0,merge_seconds=0.0)
            ingest_started=time.monotonic();self._ingest_progress(0,len(rows),ingest_started)
            try:
                with self._ingest_writer():
                    for n,row,origin,signature,existing,raw_lookup in self._ingest_batches(rows,digest):
                        if n and n%10000==0:self._ingest_progress(n,len(rows),ingest_started)
                        if existing:
                            if any(r['version_key']==signature for r in existing):
                                self._ingest_insert('viewer_event_captures',(digest,origin,signature,signature,n))
                                dup+=1;continue
                            compatible=self.compatible_known_capture(origin,row,known_versions=existing,raw_lookup=raw_lookup)
                            if compatible:
                                self.record_compatible_capture(origin,signature,compatible,digest,path.name,n,row)
                                self._ingest_insert('viewer_event_captures',(digest,origin,signature,compatible,n))
                                dup+=1;continue
                            conf+=1
                        self._ingest_impacted.update(r['request_key'] for r in existing if r['request_key'])
                        rid=opaque(row.get('RequestID'));session=opaque(row.get('Session'))
                        if rid:self._ingest_impacted.add(token(self.keys,'request',rid))
                        ip=opaque(row.get('IP'));call=str(row.get('CallPath') or 'Unknown')[:240]
                        if not isinstance(row.get('message'),str):raise ValueError('message_type')
                        kind=classify(call);code=safe_codes(row['message']);obs=paid_observation(row['message'],call)
                        self._ingest_insert('viewer_events',(origin,signature,digest,path.name,n,utc_ns(row.get('@timestamp')),
                             token(self.keys,'request',rid),token(self.keys,'session',session),token(self.keys,'ip',ip),call,kind,code,obs))
                        # Store full original data alongside HMAC relational keys.
                        self.insert_raw_event(origin,signature,row)
                        existing.append(dict(version_key=signature,request_key=token(self.keys,'request',rid)))
                        raw_lookup[(origin,signature)]=row
                        self._ingest_insert('viewer_event_captures',(digest,origin,signature,signature,n))
                        # SQL parameters are evidence, not new user requests.
                        if kind=='sql':
                            parsed=sql_links(row['message'])
                            if 'ud_prc_userSessionHasAccess' in call:
                                try:
                                    access,_=sql_parameters(row['message'])
                                    asserted=opaque(access.get('session'))
                                    if asserted:parsed['access_session']=asserted
                                except Exception:pass
                            for domain,value in parsed.items():
                                self._ingest_insert('viewer_links',(origin,signature,token(self.keys,'request',rid),domain,token(self.keys,'session' if domain=='access_session' else domain,value)))
                        new+=1
                self._ingest_progress(len(rows),len(rows),ingest_started)
                self.sql('''INSERT INTO viewer_files VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                         (digest,path.name,start,end,payload.get('count'),len(rows),new,dup,conf,datetime.now(timezone.utc).isoformat(),
                          'verified_snapshot_export' if proof_verified else 'unverified_snapshot_claim',
                          ';'.join(x for x in ('versions_conflict' if conf else '', 'declared_count_mismatch' if count_issue else '',
                                             'verification_missing_or_incomplete' if not proof_verified else '') if x) or None))
                if commit:self.conn.commit()
                results.append(dict(file=path.name,status='IMPORTED',sha256=digest,rows=len(rows),new_events=new,duplicates=dup,conflicts=conf))
            except Exception as exc:
                self.conn.rollback()
                # The atomic online caller needs the actual SQL/IO cause for
                # diagnosis. Legacy manual imports retain their result-list API.
                if not commit:raise
                results.append(dict(file=path.name,status='REJECTED',error=type(exc).__name__))
        return results

    def backfill_identity_assertions(self):
        """Upgrade existing v0.2.3 raw evidence without reimport or erasure."""
        import zlib
        from .viewer_storage_keys import exact_origin_join
        query="""SELECT e.origin_key,e.version_key,e.request_key,b.payload
          FROM viewer_events e JOIN viewer_raw_events b
           ON b.origin_key=e.origin_key AND b.version_key=e.version_key
          WHERE e.callpath LIKE ? AND NOT EXISTS(
            SELECT 1 FROM viewer_links l WHERE """+exact_origin_join(self,'l','e')+"""
               AND l.link_domain='access_session')"""
        cur=self.sql(query,('%ud_prc_userSessionHasAccess%',))
        checked=written=0
        while True:
            batch=cur.fetchmany(500)
            if not batch:break
            inserts=[]
            for item in batch:
                r=dict(item);checked+=1
                try:
                    raw=json.loads(zlib.decompress(bytes(r['payload'])).decode('utf-8'))
                    params,_=sql_parameters(raw.get('message',''))
                    value=opaque(params.get('session'))
                    if value:
                        inserts.append((r['origin_key'],r['version_key'],r['request_key'],
                                        'access_session',token(self.keys,'session',value)))
                except (ValueError,TypeError,KeyError):continue
            for value in inserts:
                from .viewer_storage_keys import conflict_clause
                self.sql('INSERT INTO viewer_links(origin_key,version_key,request_key,link_domain,link_key) VALUES(?,?,?,?,?)'+conflict_clause(self,'viewer_links'),value)
            written+=len(inserts)
        self.conn.commit()
        return dict(scanned=checked,assertions_written=written)

    def backfill_payment_observations(self,paths):
        """Upgrade safe payment observations from verified private files."""
        updated=0; scanned=0
        for path in paths:
            path=Path(path).resolve()
            digest=hashlib.sha256(path.read_bytes()).hexdigest()
            if not self.one('SELECT 1 AS found FROM viewer_files WHERE file_hash=?',(digest,)):
                raise ValueError('file_not_imported_or_sha_mismatch')
            with gzip.open(path,'rt',encoding='utf-8') as f:payload=json.load(f)
            for ordinal,row in enumerate(payload['logs']):
                call=row.get('CallPath') or ''
                if not any(k in call for k in ('ud_prc_webhooksInformBillPaymentStatus_v1','ud_prc_inquiryInvoiceResult2','GetPaymentInfo','ClientAyanCoInquiry.')):continue
                scanned+=1
                obs=paid_observation(row.get('message',''),call)
                if not obs:continue
                idx,docid=source_identity(row)
                origin=token(self.keys,'origin',[idx,docid] if idx else [digest,ordinal])
                signature=token(self.keys,'version',row)
                r=self.sql('UPDATE viewer_events SET observation=? WHERE origin_key=? AND version_key=? AND (observation IS NULL OR observation<>?)',
                           (obs,origin,signature,obs))
                updated+=max(r.rowcount,0)
                if 'ud_prc_inquiryInvoiceResult2' in call:
                    for domain,value in sql_links(row.get('message','')).items():
                        from .viewer_storage_keys import conflict_clause
                        self.sql('INSERT INTO viewer_links(origin_key,version_key,request_key,link_domain,link_key) VALUES(?,?,?,?,?)'+conflict_clause(self,'viewer_links'),
                            (origin,signature,token(self.keys,'request',opaque(row.get('RequestID'))),domain,token(self.keys,domain,value)))
            self.conn.commit()
        return dict(scanned=scanned,updated=updated)

    def _prepare_projection_events(self):
        """Read each impacted request's retained events once, including old windows.

        The PostgreSQL lateral fence makes unrelated history ineligible for a
        sequential scan. Reused local events keep subsequent outcome queries
        proportional to the actual dependency closure, not the entire database.
        Global origin-version checks below deliberately remain global.
        """
        self.progress('projection_scope_events')
        if self.sqlite:
            self.sql('CREATE TEMP TABLE IF NOT EXISTS viewer_projection_events AS SELECT * FROM viewer_events WHERE 0')
            self.sql('DELETE FROM viewer_projection_events')
            self.sql('''INSERT INTO viewer_projection_events SELECT e.* FROM viewer_projection_scope s
                JOIN viewer_events e ON e.request_key=s.request_key''')
        else:
            self.sql('CREATE TEMP TABLE IF NOT EXISTS viewer_projection_events (LIKE viewer_events) ON COMMIT DROP')
            self.sql('TRUNCATE TABLE viewer_projection_events')
            self.sql('''INSERT INTO viewer_projection_events SELECT e.* FROM viewer_projection_scope s
                CROSS JOIN LATERAL (SELECT source.* FROM viewer_events source
                    WHERE source.request_key=s.request_key OFFSET 0) e''')
        self.sql('CREATE INDEX IF NOT EXISTS vpe_request ON viewer_projection_events(request_key,at_ns)')
        self.sql('CREATE INDEX IF NOT EXISTS vpe_origin ON viewer_projection_events(origin_key,version_key)')
        if not self.sqlite:
            self.sql('ANALYZE viewer_projection_events')
            self._prepare_projection_inputs()
            if getattr(self,'d1_explain',False):
                counts=self.one('SELECT COUNT(*) AS events,COUNT(DISTINCT request_key) AS requests FROM viewer_projection_events')
                self.progress('projection_scope_ready',**counts)

    def _prepare_projection_inputs(self):
        """Snapshot links and global origin validity once under the writer lock.

        Every scoped request link is copied, including links with no retained
        event. Each distinct origin in events OR links is checked globally;
        versions belonging to another RequestID must still invalidate it.
        Only 0 / 1 / at-least-2 versions matter, so PG reads at most two PK
        entries per origin. No validity survives the publication transaction.
        """
        self.progress('projection_scope_inputs')
        if self.sqlite:
            self.sql('CREATE TEMP TABLE IF NOT EXISTS viewer_projection_links AS SELECT * FROM viewer_links WHERE 0')
            self.sql('DELETE FROM viewer_projection_links')
            self.sql('''INSERT INTO viewer_projection_links SELECT l.* FROM viewer_projection_scope s
                JOIN viewer_links l ON l.request_key=s.request_key''')
        else:
            self.sql('CREATE TEMP TABLE IF NOT EXISTS viewer_projection_links (LIKE viewer_links) ON COMMIT DROP')
            self.sql('TRUNCATE TABLE viewer_projection_links')
            self.sql('''INSERT INTO viewer_projection_links SELECT l.* FROM viewer_projection_scope s
                CROSS JOIN LATERAL (SELECT source.* FROM viewer_links source
                    WHERE source.request_key=s.request_key OFFSET 0) l''')
        self.sql('CREATE INDEX IF NOT EXISTS vpl_origin ON viewer_projection_links(origin_key,version_key,link_domain)')
        self.sql('CREATE INDEX IF NOT EXISTS vpl_request ON viewer_projection_links(request_key)')
        self.sql('''CREATE TEMP TABLE IF NOT EXISTS viewer_projection_versions(
            origin_key TEXT PRIMARY KEY,version_count BIGINT NOT NULL,only_version_key TEXT)'''+
            ('' if self.sqlite else ' ON COMMIT DROP'))
        self.sql('DELETE FROM viewer_projection_versions' if self.sqlite else 'TRUNCATE TABLE viewer_projection_versions')
        origins='''(SELECT origin_key FROM viewer_projection_events UNION
            SELECT origin_key FROM viewer_projection_links ORDER BY origin_key) k'''
        if self.sqlite:
            self.sql('''INSERT INTO viewer_projection_versions SELECT k.origin_key,
                (SELECT COUNT(*) FROM viewer_events v WHERE v.origin_key=k.origin_key),
                (SELECT MIN(version_key) FROM viewer_events v WHERE v.origin_key=k.origin_key)
                FROM '''+origins)
        else:
            self.sql('''INSERT INTO viewer_projection_versions SELECT k.origin_key,v.n,v.only_version
                FROM '''+origins+''' CROSS JOIN LATERAL
                (SELECT COUNT(*) AS n,MIN(b.version_key) AS only_version FROM
                    (SELECT version_key FROM viewer_events source
                     WHERE source.origin_key=k.origin_key LIMIT 2 OFFSET 0) b) v''')
            self.sql('ANALYZE viewer_projection_links')
            self.sql('ANALYZE viewer_projection_versions')
        self.progress('projection_scope_inputs_ready')

    @staticmethod
    def _global_conflict_predicate(indexed=False,cached=False):
        # PK(origin_key,version_key) makes >1 exactly the existence of a
        # competing material version, including another RequestID's version.
        if cached:return '(SELECT version_count FROM viewer_projection_versions v WHERE v.origin_key=e.origin_key)>1'
        return ('''(SELECT COUNT(*) FROM viewer_events bad WHERE bad.origin_key=e.origin_key)>1'''
                if indexed else
                '''EXISTS(SELECT 1 FROM viewer_events bad WHERE bad.origin_key=e.origin_key AND bad.version_key<>e.version_key)''')

    @staticmethod
    def _single_version_origin_sql(alias='e', *, indexed=False,cached=False):
        # The global PK is (origin_key,version_key). A scalar count cannot be
        # flattened into a history-wide anti-join. Never scope this lookup to
        # the current RequestID: a competing version may belong to another one.
        if cached:
            return ('(SELECT CASE WHEN v.version_count=0 OR v.version_count=1 AND v.only_version_key='+alias+
                '.version_key THEN 1 ELSE 0 END FROM viewer_projection_versions v WHERE v.origin_key='+alias+'.origin_key)=1')
        if indexed:
            return ('(SELECT COUNT(*) FROM viewer_events bad WHERE bad.origin_key='+alias+
                    '.origin_key AND bad.version_key<>'+alias+'.version_key)=0')
        return ('NOT EXISTS(SELECT 1 FROM viewer_events bad WHERE bad.origin_key='+alias+
                '.origin_key AND bad.version_key<>'+alias+'.version_key)')

    @classmethod
    def _request_conflict_evidence_sql(cls, events, *, indexed=False,cached=False):
        return ('''SELECT DISTINCT e.request_key,e.callpath,e.code FROM '''+events+''' e
            JOIN viewer_requests r ON r.request_key=e.request_key
            WHERE r.root_count>1 AND e.kind='client' AND '''+
            cls._single_version_origin_sql(indexed=indexed,cached=cached))

    @classmethod
    def _access_session_conflicts_sql(cls, events, *, scoped=False, indexed=False,cached=False,compact=False):
        # The link PK begins with origin/version. Keep both probes correlated
        # to the bounded event relation rather than joining all retained links.
        from .viewer_storage_keys import digest_sql
        accelerated=(digest_sql(('origin_key','version_key'),'l')+'='+digest_sql(('origin_key','version_key'),'e')+' AND ') if compact and not cached else ''
        links='''SELECT COUNT(*) FROM '''+('viewer_projection_links' if cached else 'viewer_links')+''' l
            WHERE '''+accelerated+'''l.origin_key=e.origin_key AND l.version_key=e.version_key
              AND l.link_domain='access_session' AND l.link_key<>e.session_key'''
        access=('('+links+')>0' if indexed else 'EXISTS('+links.replace('COUNT(*)','1')+')')
        scope=' AND request_key IN (SELECT request_key FROM viewer_projection_scope)' if scoped else ''
        return ('''UPDATE viewer_requests SET identity_state='conflicting',conflicted=1,session_key=NULL
            WHERE request_key IN (SELECT e.request_key FROM '''+events+''' e
                WHERE e.session_key IS NOT NULL AND '''+access+' AND '+
                cls._single_version_origin_sql(indexed=indexed,cached=cached)+')'+scope)

    @classmethod
    def _projection_payment_links_sql(cls, *, scoped=False, postgres=False,cached=False):
        domains="('platform_payment','invoice','purchase','query','query_index','query_parameters_hash')"
        if scoped and postgres:
            # OFFSET 0 preserves the per-request index probe (vli_request),
            # including old windows for these requests. Global version checks
            # still read the retained origin PK, not the private work table.
            source='''viewer_projection_scope s CROSS JOIN LATERAL
                (SELECT source.* FROM '''+('viewer_projection_links' if cached else 'viewer_links')+''' source WHERE source.request_key=s.request_key
                    AND source.link_domain IN '''+domains+''' OFFSET 0) l'''
            filters=cls._single_version_origin_sql('l',indexed=True,cached=cached)
        else:
            source='viewer_links l'
            filters='l.link_domain IN '+domains+' AND '+cls._single_version_origin_sql('l')
            if scoped:filters+=' AND l.request_key IN (SELECT request_key FROM viewer_projection_scope)'
        return 'SELECT DISTINCT l.request_key,l.link_key,l.link_domain FROM '+source+' WHERE '+filters

    @staticmethod
    def _request_aggregate_sql(events, *, scoped=False, indexed_conflict=False,cached=False):
        """Keep the global origin/version conflict invariant with bounded lookups.

        The global PK(origin_key,version_key) means one origin row is clean,
        two or more indicate version conflict. A correlated scalar aggregate
        keeps the probe keyed by origin instead of encouraging an unbounded
        PostgreSQL anti-join. SQLite/full rebuild keep their existing SQL.
        """
        if cached:
            conflict='(SELECT version_count FROM viewer_projection_versions v WHERE v.origin_key=e.origin_key)=1'
        elif indexed_conflict:
            conflict='''(SELECT COUNT(*) FROM viewer_events versions
                           WHERE versions.origin_key=e.origin_key)=1'''
        else:
            conflict='''NOT EXISTS(SELECT 1 FROM viewer_events bad
                 WHERE bad.origin_key=e.origin_key AND bad.version_key<>e.version_key)'''
        # Already scoped on creation. A second semi-join changes planner
        # choices for no benefit on the PostgreSQL materialized path.
        scope=(' AND e.request_key IN (SELECT request_key FROM viewer_projection_scope)'
               if scoped and events=='viewer_events' else '')
        return '''INSERT INTO viewer_requests(request_key,session_key,identity_state,started_ns,ended_ns,
                   root_ns,root_call,root_code,root_count,event_count,sql_count,provider_count,conflicted,initiation)
            SELECT e.request_key,
                   CASE WHEN COUNT(DISTINCT e.session_key)=1 THEN MIN(e.session_key) END,
                   CASE WHEN COUNT(DISTINCT e.session_key)=0 THEN 'missing' WHEN COUNT(DISTINCT e.session_key)=1 THEN 'assigned' ELSE 'conflicting' END,
                   MIN(e.at_ns),MAX(e.at_ns),NULL,NULL,NULL,
                   SUM(CASE WHEN e.kind='client' THEN 1 ELSE 0 END),COUNT(*),
                   SUM(CASE WHEN e.kind='sql' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN e.kind='provider' THEN 1 ELSE 0 END),0,'unknown'
            FROM '''+events+''' e
            WHERE e.request_key IS NOT NULL AND '''+conflict+scope+''' GROUP BY e.request_key'''

    @staticmethod
    def _request_roots_sql(events,*,scoped=False,indexed_conflict=False,cached=False):
        # The retained-event PK makes COUNT=1 equivalent to no competing
        # version. Keep both root probes bounded by origin on incremental PG,
        # including versions assigned to another request outside the scope.
        clean=('''(SELECT COUNT(*) FROM viewer_events e2 WHERE e2.origin_key=e.origin_key)=1'''
               if indexed_conflict else
               '''NOT EXISTS (SELECT 1 FROM viewer_events e2
                              WHERE e2.origin_key=e.origin_key AND e2.version_key<>e.version_key)''')
        if cached:clean='(SELECT version_count FROM viewer_projection_versions v WHERE v.origin_key=e.origin_key)=1'
        scope=' AND r.request_key IN (SELECT request_key FROM viewer_projection_scope)' if scoped else ''
        return """UPDATE viewer_requests AS r
            SET (root_call,root_code,root_ns,initiation) = (
                SELECT e.callpath,e.code,e.at_ns,
                       CASE WHEN e.callpath LIKE ? THEN 'confirmed_automatic'
                            WHEN e.callpath LIKE ? OR e.callpath LIKE ?
                              OR e.callpath LIKE ? THEN 'system_followup'
                            ELSE 'unknown' END
                FROM """+events+""" e
                WHERE e.request_key=r.request_key AND e.kind='client' AND """+clean+"""
                ORDER BY e.at_ns DESC,e.callpath DESC LIMIT 1)
            WHERE EXISTS (SELECT 1 FROM """+events+""" e WHERE e.request_key=r.request_key
                          AND e.kind='client' AND """+clean+')'+scope

    def _aggregate_plan(self,statement,variant):
        """EXPLAIN without ANALYZE: emit no customer data or SQL literals."""
        raw=self.one('EXPLAIN (FORMAT JSON) '+statement)
        plan=next(iter(raw.values()))
        if isinstance(plan,str):plan=json.loads(plan)
        nodes=[]
        def visit(node,depth=0):
            if len(nodes)>=24:return
            nodes.append(dict(depth=depth,node=node.get('Node Type'),relation=node.get('Relation Name'),
                index=node.get('Index Name'),rows=node.get('Plan Rows'),cost=node.get('Total Cost')))
            for child in node.get('Plans',[]):visit(child,depth+1)
        visit(plan[0]['Plan'])
        self.progress('rebuild_aggregate_plan',variant=variant,nodes=nodes)

    def rebuild(self,*,request_keys=None,commit=True,use_indexed_scope=False):
        if request_keys is None or getattr(self,'_legacy_projection_writes',False):
            return self._rebuild_requests(request_keys=request_keys,commit=commit)
        self.write_lock()
        with self.finalized_projection(REQUEST_TABLES,use_indexed_scope=use_indexed_scope):
            result=self._rebuild_requests(request_keys=request_keys,commit=False)
        if commit:self.conn.commit()
        return result

    def _rebuild_requests(self,*,request_keys=None,commit=True):
        """Deterministic read model; preserve every origin version in viewer_events."""
        self.write_lock()
        self.progress('rebuild_requests',scope='incremental' if request_keys is not None else 'bootstrap')
        self._journey_fingerprint_cache={}
        # Keep the M1/LC3E history relation itself: DROP/CREATE would break
        # PostgreSQL readers holding an older repeatable-read snapshot. Only
        # derived rows are reconciled; distinct observations retain their PK.
        scoped=request_keys is not None
        if scoped:
            self.sql('CREATE TEMP TABLE IF NOT EXISTS viewer_projection_scope(request_key TEXT PRIMARY KEY)')
            self.sql('DELETE FROM viewer_projection_scope')
            statement='INSERT INTO viewer_projection_scope VALUES (?)'
            if not self.sqlite:statement=statement.replace('?',self.param)
            with_cursor=self.conn.cursor()
            try:with_cursor.executemany(statement,[(k,) for k in sorted(set(request_keys))])
            finally:with_cursor.close()
            if not self.sqlite:self.sql('ANALYZE viewer_projection_scope')
            self._prepare_projection_events()
        events='viewer_projection_events' if scoped else 'viewer_events'
        def scope(alias=''):
            return (' AND '+(alias+'.' if alias else '')+'request_key IN (SELECT request_key FROM viewer_projection_scope)') if scoped else ''
        self._active_projection_scope=scoped
        if not getattr(self,'_projection_routes',None):
            self.sql('''CREATE TABLE IF NOT EXISTS viewer_action_history(action_key TEXT NOT NULL, at_ns BIGINT,
                      status TEXT NOT NULL, source_request_key TEXT NOT NULL,
                      source_callpath TEXT NOT NULL, origin_key TEXT NOT NULL, version_key TEXT NOT NULL,
                      PRIMARY KEY(action_key,origin_key,version_key,status))''')
        for table,col in (('viewer_action_history','action_key'),('viewer_actions','action_key'),('viewer_requests','request_key')):
            self.sql('DELETE FROM '+table+(' WHERE '+col+' IN (SELECT request_key FROM viewer_projection_scope)' if scoped else ''))
        self.progress('rebuild_requests_aggregate',scope='incremental' if scoped else 'bootstrap')
        # Only this failing aggregate is modified; remaining read models,
        # business classifications and financial relationships are unchanged.
        aggregate=self._request_aggregate_sql(events,scoped=scoped,
            indexed_conflict=scoped and not self.sqlite,cached=scoped and not self.sqlite)
        if scoped and not self.sqlite and getattr(self,'d1_explain',False):
            # Compare both *estimates* during the native transaction. Neither
            # EXPLAIN executes the INSERT or provides measured runtime.
            legacy=self._request_aggregate_sql('viewer_events',scoped=True)
            self._aggregate_plan(legacy,'legacy_global_scope')
            self._aggregate_plan(aggregate,'bounded_origin_index')
        aggregate_start=time.monotonic()
        self.sql(aggregate)
        self.progress('rebuild_requests_aggregate_complete',seconds=round(time.monotonic()-aggregate_start,3))
        # The private request relation has just grown from empty to a full
        # window. Its actual cardinality must be known before anti-joins.
        if scoped and not self.sqlite:self.sql('ANALYZE viewer_requests')
        missing_started=time.monotonic()
        self.progress('rebuild_missing_requests')
        # Create a reachable read-model entity even when every origin conflicts.
        # Its unqualified versions remain available in evidence(), not in a
        # confidently assigned session, root, or financial result.
        self.sql("""INSERT INTO viewer_requests(request_key,session_key,identity_state,
               started_ns,ended_ns,root_ns,root_call,root_code,root_count,event_count,
               sql_count,provider_count,conflicted,initiation)
             SELECT e.request_key,NULL,'conflicting',MIN(e.at_ns),MAX(e.at_ns),
                    NULL,NULL,NULL,0,COUNT(*),0,0,1,'unknown'
             FROM """+events+""" e WHERE e.request_key IS NOT NULL
               AND NOT EXISTS(SELECT 1 FROM viewer_requests r WHERE r.request_key=e.request_key)
             """+scope('e')+""" GROUP BY e.request_key""")
        self.progress('rebuild_missing_requests_complete',seconds=round(time.monotonic()-missing_started,3))
        # A conflicting original cannot be silently attributed; mark affected requests.
        conflict_started=time.monotonic()
        self.progress('rebuild_global_conflicts')
        conflict_test=self._global_conflict_predicate(indexed=scoped and not self.sqlite,cached=scoped and not self.sqlite)
        self.sql('''UPDATE viewer_requests SET conflicted=1,identity_state='conflicting',session_key=NULL
                     WHERE request_key IN
                       (SELECT DISTINCT e.request_key FROM '''+events+''' e WHERE '''+conflict_test+'''
                          '''+scope('e')+''')'''+scope())
        self.progress('rebuild_global_conflicts_complete',seconds=round(time.monotonic()-conflict_started,3))
        # One indexed correlated update instead of 1 SQL round-trip per root
        # (essential for 145k+ real requests, especially on PostgreSQL).
        self.progress('rebuild_request_roots')
        roots_started=time.monotonic()
        self.sql(self._request_roots_sql(events,scoped=scoped,indexed_conflict=scoped and not self.sqlite,cached=scoped and not self.sqlite),
                 ('%/InvoiceRegister %','Webhook.%','PaymentCallback.%','JobsQueue.%'))
        self.progress('rebuild_request_roots_complete',seconds=round(time.monotonic()-roots_started,3))
        # Distinct HTTP routes / contradictory root status are not resolved by
        # sorting timestamps. Only exact compatible repeated observations may
        # share one authoritative root.
        self.progress('rebuild_request_conflicts')
        conflict_started=time.monotonic()
        roots=defaultdict(set)
        for e in self.all(self._request_conflict_evidence_sql(events,indexed=scoped and not self.sqlite,cached=scoped and not self.sqlite)):
            roots[e['request_key']].add((service_path(e['callpath']),e['code']))
        conflicting=[(key,) for key,values in roots.items() if len(values)>1]
        self.many("""UPDATE viewer_requests SET conflicted=1,root_call=NULL,
                       root_code=NULL,root_ns=NULL,initiation='unknown' WHERE request_key=?""",conflicting)
        self.progress('rebuild_request_conflicts_complete',seconds=round(time.monotonic()-conflict_started,3),
                      conflicting_requests=len(conflicting))
        # Access-check session assertions are separate from the structured
        # Session field. Disagreement is explicit and never forcibly relinked.
        self.progress('rebuild_access_session_conflicts')
        access_started=time.monotonic()
        from .viewer_storage_keys import detect
        self.sql(self._access_session_conflicts_sql(events,scoped=scoped,indexed=scoped and not self.sqlite,cached=scoped and not self.sqlite,compact=detect(self)))
        self.progress('rebuild_access_session_conflicts_complete',seconds=round(time.monotonic()-access_started,3))
        # Actions remain separate per HTTP RequestID, including manual retries.
        self.progress('rebuild_service_roles')
        roles_started=time.monotonic()
        self.ensure_service_roles({service_path(r['root_call']) for r in self.all(
            'SELECT DISTINCT root_call FROM viewer_requests WHERE root_call IS NOT NULL'+scope())})
        catalog={r['service_path']:r for r in self.all('SELECT * FROM viewer_service_roles')}
        sql_requests=self.all('SELECT * FROM viewer_requests WHERE root_call IS NOT NULL'+scope())
        self.progress('rebuild_service_roles_complete',seconds=round(time.monotonic()-roles_started,3))
        self.progress('rebuild_payment_index')
        payment_started=time.monotonic()
        payment_index=defaultdict(list)
        for link in self.all(self._projection_payment_links_sql(scoped=scoped,postgres=not self.sqlite,cached=scoped and not self.sqlite)):
            payment_index[(link['link_domain'],link['link_key'])].append(link['request_key'])
        request_links=defaultdict(list)
        for (kind,key),rids in payment_index.items():
            for rid in set(rids):request_links[rid].append((kind,key))
        self.progress('rebuild_payment_index_complete',seconds=round(time.monotonic()-payment_started,3))
        self.progress('rebuild_actions',processed=0,total=len(sql_requests))
        action_values=[]
        action_statement='''INSERT INTO viewer_actions(action_key,session_key,label,name,category,initiation,at_ns,current_outcome,root_request_key,target_type,target_key,workflow_key,evidence)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)'''
        for r in sql_requests:
            if r['conflicted']:continue  # ambiguity must not become a confident action
            name=core_name(r['root_call'])
            classified=catalog[service_path(r['root_call'])]
            kind=classified['role']
            outcome='unknown' if not r['root_code'] else ('success' if r['root_code']=='G00000' else 'failure')
            matches=request_links.get(r['request_key'],[])
            # Exact identifier-level grouping: invoice for inquiry, paymentKey for payment lifecycle.
            workflow=None
            for preferred in (('platform_payment',) if name in ('WalletPayment','UserBasketPayment','InvoicePayment','BillsPayment','InformBillsPaymentStatus','PaymentCallback')
                              else ('invoice','purchase','query') if name in INQUIRIES|{'InvoiceRegister'} else ()):
                v=next((key for typ,key in matches if typ==preferred),None)
                if v:workflow=preferred+':'+v;break
            target_type=name if name in INQUIRIES else None
            target_key=(next((key for typ,key in matches if typ=='query_index'),None) or
                        next((key for typ,key in matches if typ=='query_parameters_hash'),None)) if target_type else None
            action_values.append((r['request_key'],r['session_key'],name,name,kind,classified['initiation'],r['root_ns'] or r['ended_ns'],
                      outcome,r['request_key'],target_type,target_key,workflow,json.dumps(dict(request_key=r['request_key']),ensure_ascii=False)))
            if len(action_values)>=1000:self.many(action_statement,action_values);action_values.clear()
        self.many(action_statement,action_values)
        self.progress('reconcile_outcomes')
        self.progress('reconcile_business_outcomes')
        outcomes_started=time.monotonic()
        self._reconcile_business_outcomes()
        self.progress('reconcile_business_outcomes_complete',seconds=round(time.monotonic()-outcomes_started,3))
        self.progress('reconcile_payment_outcomes')
        outcomes_started=time.monotonic()
        self._reconcile_payment_outcomes()
        self.progress('reconcile_payment_outcomes_complete',seconds=round(time.monotonic()-outcomes_started,3))
        # A manual legacy full rebuild does not silently serve stale semantic
        # anchors. The next explicit semantic-index-build reconciles them.
        if not scoped and self.semantic_checkpoint():
            self.sql("UPDATE viewer_semantic_checkpoint SET state='stale' WHERE id=1")
        self._active_projection_scope=False
        if commit:self.conn.commit()
        return dict(recomputed_requests=len(set(request_keys))) if scoped else self.metrics()

    def _reconcile_business_outcomes(self):
        # Specific meanings: confirmed only for the corresponding service.
        supported={('LandLinePhoneBills','GD2028'):'no_payable_bill',
                   ('LandLinePhoneBills','GD2027'):'not_found',
                   ('LandLinePhoneBills','GD2026'):'provider_unavailable',
                   ('ElectricBills','GD2016'):'provider_unavailable',
                   ('FreewayTollBills','GM2030'):'no_payable_bill'}
        scoped=getattr(self,'_active_projection_scope',False)
        events='viewer_projection_events' if scoped else 'viewer_events'
        clean=self._single_version_origin_sql(indexed=scoped and not self.sqlite,cached=scoped and not self.sqlite)
        scope=" AND e.request_key IN (SELECT request_key FROM viewer_projection_scope)" if scoped else ''
        names={a['action_key']:a['name'] for a in self.all('SELECT action_key,name FROM viewer_actions'+
            (' WHERE action_key IN (SELECT request_key FROM viewer_projection_scope)' if scoped else ''))}
        updates=[]
        for row in self.all("SELECT DISTINCT e.request_key,e.observation FROM "+events+" e WHERE "+clean+" AND e.observation LIKE ?"+scope, ('business_code:%',)):
            name=names.get(row['request_key'])
            if not name:continue
            code=row['observation'].partition(':')[2]
            status=supported.get((name,code))
            if status:
                updates.append((status,row['request_key']))
                if len(updates)>=1000:self.many('UPDATE viewer_actions SET current_outcome=? WHERE action_key=?',updates);updates.clear()
        self.many('UPDATE viewer_actions SET current_outcome=? WHERE action_key=?',updates)

    def _reconcile_payment_outcomes(self):
        """Never certify bill payment without a matching, eligible bill item.

        PaymentKey is a transaction grouping key, *not* authorization to
        upgrade unrelated BillID/PaymentID items. No temporal/IP inference.
        """
        scoped=getattr(self,'_active_projection_scope',False)
        events='viewer_projection_events' if scoped else 'viewer_events'
        clean=self._single_version_origin_sql(indexed=scoped and not self.sqlite,cached=scoped and not self.sqlite)
        scope=" AND e.request_key IN (SELECT request_key FROM viewer_projection_scope)" if scoped else ''
        if scoped and not self.sqlite:
            link_source=events+''' e CROSS JOIN LATERAL
              (SELECT source.* FROM viewer_projection_links source WHERE source.origin_key=e.origin_key
                AND source.version_key=e.version_key AND source.link_domain='platform_payment'
                AND source.request_key IS NOT NULL OFFSET 0) l'''
        else:
            from .viewer_storage_keys import exact_origin_join
            link_source='viewer_links l JOIN '+events+' e ON '+exact_origin_join(self,'l','e')
        clean_links=self.all("""SELECT l.link_domain,l.link_key,l.request_key,e.origin_key,e.version_key
          FROM """+link_source+"""
          WHERE l.request_key IS NOT NULL AND l.link_domain='platform_payment'
            AND """+clean+scope)
        groups=defaultdict(set)
        for link in clean_links:groups[link['link_key']].add(link['request_key'])
        roots={r['request_key']:r for r in self.all('SELECT request_key,root_call,root_code,conflicted FROM viewer_requests WHERE 1=1'+(' AND request_key IN (SELECT request_key FROM viewer_projection_scope)' if scoped else ''))}
        relevant=set().union(*groups.values()) if groups else set()
        observations=defaultdict(list)
        # Select only admissible, single-version origins. Bring origin identity
        # through to the append-only payment observation history.
        for e in self.all("""SELECT e.origin_key,e.version_key,e.request_key,e.at_ns,e.observation,e.callpath
          FROM """+events+""" e
          WHERE e.observation IN ('paid_true','paid_false','webhook_payment_success')
            AND """+clean+scope):
            if e['request_key'] in relevant:observations[e['request_key']].append(e)
        item_cache={}
        def items_for(e):
            k=(e['origin_key'],e['version_key'])
            if k not in item_cache:
                raw=self.get_raw(*k)
                item_cache[k]=financial_bill_items(raw.get('message',''),e['callpath']) if raw else []
            return item_cache[k]
        for _,rids in groups.items():
            paid_requests=[];confirm=[];callbacks=[]
            for rid in rids:
                root=roots.get(rid) or {}
                if root.get('conflicted'):continue
                name=core_name(root.get('root_call') or '')
                if name in {'WalletPayment','UserBasketPayment','InvoicePayment','BillsPayment','PaymentCallback'}:
                    paid_requests.append((rid,name))
                if name=='PaymentCallback':callbacks.append(rid)
                if name=='InformBillsPaymentStatus' and root.get('root_code')=='G00000':
                    confirm.extend(e for e in observations[rid]
                                   if e['observation']=='webhook_payment_success')
            cb_paid=[e for rid in callbacks for e in observations[rid]
                     if e['observation'] in ('paid_true','paid_false')]
            for rid,name in paid_requests:
                primary=[e for e in observations[rid] if e['observation'] in ('paid_true','paid_false')]
                scoped=primary+([e for e in cb_paid if e['request_key']!=rid] if name!='PaymentCallback' else [])
                # Item scope is recorded independently of a transaction key.
                # In multi-bill payments every observed bill must be covered.
                required=set()
                required_amounts=defaultdict(set)
                latest={}
                for e in primary:
                    for bid,pid,amt,paid in items_for(e):
                        ident=(bid,pid)
                        required.add(ident)
                        if amt is not None:required_amounts[ident].add(str(amt))
                        event_ns=e['at_ns'] or 0
                        if ident not in latest or (event_ns,e['origin_key'])>(latest[ident][0],latest[ident][1]):
                            latest[ident]=(event_ns,e['origin_key'],paid)
                for e in scoped:
                    self.sql("INSERT INTO viewer_action_history VALUES(?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
                             (rid,e['at_ns'],e['observation'],e['request_key'],e['callpath'],e['origin_key'],e['version_key']))
                matched=set()
                for e in confirm:
                    seen=items_for(e)
                    eligible=bool(seen) and all(
                        (b,p) in required and len(required_amounts[(b,p)])<=1 and
                        (amt is None or not required_amounts[(b,p)] or str(amt) in required_amounts[(b,p)])
                        for b,p,amt,_ in seen)
                    if eligible:
                        matched.update((b,p) for b,p,_,_ in seen)
                        self.sql("INSERT INTO viewer_action_history VALUES(?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
                                 (rid,e['at_ns'],'webhook_payment_success',e['request_key'],e['callpath'],e['origin_key'],e['version_key']))
                # R5: a notification belongs to an object/item scope. A shared
                # PaymentKey does not identify which HTTP execution, retry,
                # customer debit or provider token the notification belongs to.
                # Preserve the evidence in history, but do NOT overwrite the
                # current API outcome with an apparent financial result.
                # End-to-end financial confirmation remains unverified until
                # a route-specific contract and frozen manifest are present.

    def metrics(self):
        values={}
        for name,query in [('events','SELECT COUNT(*) AS n FROM viewer_events'),
                           ('origins','SELECT COUNT(DISTINCT origin_key) AS n FROM viewer_events'),
                           ('requests','SELECT COUNT(*) AS n FROM viewer_requests'),
                           ('session_ids','SELECT COUNT(DISTINCT session_key) AS n FROM viewer_requests'),
                           ('actions',"SELECT COUNT(*) AS n FROM viewer_actions WHERE category IN ('business','user_management')"),
                           ('root_calls','SELECT COUNT(*) AS n FROM viewer_actions'),
                           ('unknown_calls',"SELECT COUNT(*) AS n FROM viewer_actions WHERE category='unknown'"),
                           ('files','SELECT COUNT(*) AS n FROM viewer_files'),
                           ('conflicting_origins','SELECT COUNT(*) AS n FROM (SELECT origin_key FROM viewer_events GROUP BY origin_key HAVING COUNT(*)>1) AS c')]:
            values[name]=self.one(query)['n']
        return values

    def sessions(self,limit=25,offset=0,search=None,ip=None,from_ns=None,to_ns=None):
        filter_sql='WHERE r.session_key IS NOT NULL';args=[]
        if search:
            filter_sql+=' AND r.session_key=?';args.append(token(self.keys,'session',search))
        if ip:
            filter_sql+=' AND EXISTS(SELECT 1 FROM viewer_events e WHERE e.request_key=r.request_key AND e.ip_key=?)'
            args.append(token(self.keys,'ip',ip))
        if from_ns is not None:
            filter_sql+=' AND r.ended_ns>=?';args.append(from_ns)
        if to_ns is not None:
            filter_sql+=' AND r.started_ns<?';args.append(to_ns)
        sql='''FROM viewer_requests r '''+filter_sql
        count=self.one('SELECT COUNT(DISTINCT session_key) AS n '+sql,args)['n']
        rows=self.all('''SELECT session_key,MIN(started_ns) AS started_ns,MAX(ended_ns) AS ended_ns,
                      COUNT(*) AS requests, SUM(event_count) AS events
                      '''+sql+''' GROUP BY session_key ORDER BY MAX(ended_ns) DESC,session_key LIMIT ? OFFSET ?''',args+[limit,offset])
        for row in rows:
            row['raw_session_id']=self.raw_session_id(row['session_key'])
            row['alias']=row['raw_session_id'] or 'نشست '+row['session_key'][:10]
            row['started_fa']=tehran(row['started_ns'])
            row['ended_fa']=tehran(row['ended_ns'])
            summary=self.one('''SELECT COUNT(*) AS n,MAX(at_ns) AS latest
                    FROM viewer_actions WHERE session_key=? AND category='business' ''',
                    (row['session_key'],))
            row['business_count']=summary['n']
            latest=self.one('''SELECT name FROM viewer_actions
                     WHERE session_key=? AND category='business'
                     ORDER BY at_ns DESC,action_key DESC LIMIT 1''',(row['session_key'],))
            row['latest_business']=latest['name'] if latest else None
        return dict(items=rows,total=count,limit=limit,offset=offset)

    def requests_page(self,limit=25,offset=0,*,session='',session_key='',request_id='',service='',service_path_filter='',
                      role='',outcome='',target='',from_ns=None,to_ns=None,include_internal=False):
        """Globally paged logical RequestIDs, not SQL/cache log lines.

        One row per distinct RequestID. No collapsing by subject, IP or time.
        Rootless requests (e.g. background/corrupt slices) remain accessible
        via the explicit include_internal flag. The service classification is
        operator-controlled and always separate from initiation provenance.
        """
        where=[];args=[]
        if not include_internal:where.append('(r.root_call IS NOT NULL OR r.conflicted=1)')
        if session:
            where.append('r.session_key=?')
            args.append(token(self.keys,'session',session))
        if session_key:
            if not re.fullmatch(r'[0-9a-f]{64}',session_key):
                raise ValueError('invalid_internal_session_key')
            where.append('r.session_key=?')
            args.append(session_key)
        if service_path_filter:
            # Exact canonical route, including API family and version, with
            # optional logged source-line suffix. Wildcards are escaped.
            # No interpolation of user input into the SQL statement.
            if len(service_path_filter)>240:raise ValueError('service_path_too_long')
            esc=service_path_filter.replace('!','!!').replace('%','!%').replace('_','!_')
            where.append("(r.root_call=? OR r.root_call LIKE ? ESCAPE '!' OR a.label=?)")
            args.extend((service_path_filter,esc+' Line:%',service_path_filter))
        if request_id:
            where.append('r.request_key=?')
            args.append(token(self.keys,'request',request_id))
        if service:
            # ! escapes operator-entered LIKE wildcards in a portable way.
            fragment=service.replace('!','!!').replace('%','!%').replace('_','!_')
            where.append("(LOWER(r.root_call) LIKE ? ESCAPE '!' OR LOWER(a.label) LIKE ? ESCAPE '!')")
            args.extend(['%'+fragment.lower()+'%']*2)
        if role:
            where.append('a.category=?');args.append(role)
        if target:
            where.append('a.target_key IN (?,?)')
            args.extend((token(self.keys,'query_index',target),token(self.keys,'query_parameters_hash',target)))
        if outcome:
            if outcome=='success':where.append("r.root_code='G00000'")
            elif outcome=='failure':where.append("r.root_code IS NOT NULL AND r.root_code<>'G00000'")
            elif outcome=='unknown':where.append('r.root_code IS NULL')
            elif outcome=='confirmed':where.append("a.current_outcome='confirmed_per_approved_contract'")
        if from_ns is not None:where.append('r.ended_ns>=?');args.append(from_ns)
        if to_ns is not None:where.append('r.started_ns<?');args.append(to_ns)
        scope=' WHERE '+' AND '.join(where) if where else ''
        src=' FROM viewer_requests r LEFT JOIN viewer_actions a ON a.action_key=r.request_key'
        count=self.one('SELECT COUNT(*) AS n'+src+scope,args)['n']
        rows=self.all('''SELECT r.request_key,r.session_key,r.identity_state,
                            r.started_ns,r.ended_ns,r.root_ns,r.root_call,r.root_code,
                            r.event_count,r.sql_count,r.provider_count,r.root_count,
                            a.action_key,a.name,a.category,a.initiation,a.current_outcome,a.target_type,a.target_key
                     '''+src+scope+''' ORDER BY COALESCE(r.root_ns,r.started_ns) DESC,
                           r.request_key DESC LIMIT ? OFFSET ?''',args+[limit,offset])
        self.apply_service_contexts(rows)
        for item in rows:
            item['raw_request_id']=self.raw_request_id(item['request_key'])
            item['when_fa']=tehran(item['root_ns'] or item['started_ns'])
            item['service_name']=item['name'] or (core_name(item['root_call']) if item['root_call'] else 'بدون API اصلی')
            item['raw_target']=self.raw_target_value(item['request_key'],item['target_key']) if item.get('target_key') else None
            item['inquiry_journey']=self.inquiry_payment_journey(item['request_key']) if item.get('name') in INQUIRIES and (target or role=='business' or session or session_key or service) else None
            item['service_journey']=self.service_journey(item['request_key']) if (session or session_key or request_id) else None
        return dict(items=rows,total=count,limit=limit,offset=offset)

    def actions(self,session_key,limit=25,offset=0,category=None,service=None,result=None):
        where=['a.session_key=?'];args=[session_key]
        if category=='main':where.append("a.category='business'")
        elif category:where.append('a.category=?');args.append(category)
        if service:where.append('a.name=?');args.append(service)
        if result:where.append('a.current_outcome=?');args.append(result)
        constraint=' WHERE '+' AND '.join(where)
        count=self.one('SELECT COUNT(*) AS n FROM viewer_actions a'+constraint,args)['n']
        rows=self.all('''SELECT a.*,r.event_count,r.sql_count,r.provider_count,r.root_code,
                  r.identity_state,r.root_count FROM viewer_actions a
                  LEFT JOIN viewer_requests r ON r.request_key=a.root_request_key'''+constraint+
                  ' ORDER BY a.at_ns DESC,a.action_key LIMIT ? OFFSET ?',args+[limit,offset])
        for r in rows:
            r['raw_request_id']=self.raw_request_id(r['root_request_key'])
            r['when_fa']=tehran(r['at_ns']);r['target_alias']=r['target_key'][:9] if r['target_key'] else 'نامشخص'
        return dict(items=rows,total=count,limit=limit,offset=offset)

    def raw_target_value(self,request_key,target_key):
        """Recover the exact visible query subject from retained SQL evidence."""
        for e in self.all("""SELECT origin_key,version_key FROM viewer_events e
               WHERE e.request_key=? AND e.callpath LIKE ?
                 AND NOT EXISTS(SELECT 1 FROM viewer_events o WHERE o.origin_key=e.origin_key AND o.version_key<>e.version_key)
               LIMIT 6""",(request_key,'%ud_prc_inquiryInvoiceResult2%')):
            r=self.get_raw(e['origin_key'],e['version_key'])
            if not r:continue
            try:
                params,_=sql_parameters(r['message']);value=clean_scalar(params.get('queryindex'))
                if value and token(self.keys,'query_index',value)==target_key:return value
            except Exception:continue
        return None

    def related_bill_evidence(self,request_key,session_key):
        """Bill-level leads, NEVER a certified same-payment-key relationship.

        Uses the exact opaque bill UniqueID shared with a prior invoice lookup,
        then the typed BillID+PaymentID pair from that same lookup. Multiple
        payments of the same bill remain multiple *candidates*, not one attempt.
        """
        if not session_key:return []
        req=self.one('SELECT root_call,conflicted FROM viewer_requests WHERE request_key=?',(request_key,))
        if not req or req['conflicted'] or core_name(req['root_call'] or '') not in ('BillsPayment','UserBasketPayment','InvoicePayment'):
            return []
        unique_ids=set()
        for e in self.all("""SELECT origin_key,version_key,callpath FROM viewer_events e
                    WHERE e.request_key=? AND e.callpath LIKE ? AND
                      NOT EXISTS(SELECT 1 FROM viewer_events o WHERE o.origin_key=e.origin_key AND o.version_key<>e.version_key)""",
                    (request_key,'%ud_prc_billsBelongs%')):
            raw=self.get_raw(e['origin_key'],e['version_key'])
            if not raw:continue
            try:
                values,_=sql_parameters(raw['message']);value=clean_scalar(values.get('bills'))
                if value:unique_ids.add(value)
            except Exception:continue
        if not unique_ids:return []
        matched=[]
        inquiries=self.all("""SELECT r.request_key,r.root_call FROM viewer_requests r
                     WHERE r.session_key=? AND r.conflicted=0 AND r.root_call LIKE ?""",
                          (session_key,'Services.v1/ElectricBills%'))
        for ir in inquiries:
            cache_ids=set();bill_items=set()
            for e in self.all("""SELECT origin_key,version_key,callpath FROM viewer_events e
                   WHERE e.request_key=? AND (e.callpath LIKE 'CacheCoreApi.%' OR
                                               e.callpath LIKE 'ClientAyanCoInquiry.ElectricityBillInquiry%')
                     AND NOT EXISTS(SELECT 1 FROM viewer_events o WHERE o.origin_key=e.origin_key AND o.version_key<>e.version_key)""",
                              (ir['request_key'],)):
                raw=self.get_raw(e['origin_key'],e['version_key'])
                if not raw:continue
                msg=raw.get('message','')
                if e['callpath'].startswith('CacheCoreApi.') and 'Cache/Add' in msg:
                    for obj in deep_objects(message_json(msg,'Input:')):
                        v=obj.get('UniqueID')
                        if isinstance(v,str):cache_ids.add(v)
                if 'ClientAyanCoInquiry.ElectricityBillInquiry' in e['callpath']:
                    for obj in deep_objects(message_json(msg,'Output:')):
                        bid=obj.get('BillID');pid=obj.get('PaymentID')
                        if bid is not None and pid is not None:bill_items.add((str(bid),str(pid)))
            # Multiple invoice items are not safely bindable by positional guess.
            if len(cache_ids)==1 and len(bill_items)==1 and cache_ids.intersection(unique_ids):
                matched.append((ir['request_key'],next(iter(bill_items))))
        result=[];found=set()
        for inquiry_key,(bill,pay) in matched:
            bill_h=token(self.keys,'bill_id',bill);pay_h=token(self.keys,'payment_id',pay)
            webhook_ids=self.all("""SELECT DISTINCT lb.request_key FROM viewer_links lb
                  JOIN viewer_links lp ON lp.request_key=lb.request_key AND lp.link_domain='payment_id'
                  JOIN viewer_events eb ON eb.origin_key=lb.origin_key AND eb.version_key=lb.version_key
                  JOIN viewer_events ep ON ep.origin_key=lp.origin_key AND ep.version_key=lp.version_key
                  WHERE lb.link_domain='bill_id' AND lb.link_key=? AND lp.link_key=?
                    AND NOT EXISTS(SELECT 1 FROM viewer_events v WHERE v.origin_key=eb.origin_key AND v.version_key<>eb.version_key)
                    AND NOT EXISTS(SELECT 1 FROM viewer_events v WHERE v.origin_key=ep.origin_key AND v.version_key<>ep.version_key)""",
                   (bill_h,pay_h))
            for hook in webhook_ids:
                # The webhook is a bill-level lead; same payment transaction
                # cannot be asserted until a direct transaction key joins it.
                ident=(inquiry_key,hook['request_key'])
                if ident in found:continue
                found.add(ident)
                result.append(dict(inquiry_request_key=inquiry_key,financial_request_key=hook['request_key'],
                      relation='same_bill_item',transaction_confirmed=False))
        return result

    def action(self,key):
        row=self.one('SELECT * FROM viewer_actions WHERE action_key=?',(key,))
        if not row:return None
        row['raw_request_id']=self.raw_request_id(row['root_request_key'])
        root=self.one('SELECT request_key,root_call FROM viewer_requests WHERE request_key=?',(row['root_request_key'],))
        if root:self.apply_service_contexts([root])
        row['service_context']=root.get('service_context') if root else None
        row['api']=(root['root_call'] or '').split(' Line:',1)[0] if root else ''
        row['when_fa']=tehran(row['at_ns'])
        row['link_basis']='platform_payment' if (row['workflow_key'] or '').startswith('platform_payment:') else (
              'invoice_or_query' if row['workflow_key'] else 'none')
        # Payment-linked activity is shown beside (not folded into) each distinct HTTP attempt.
        if row['workflow_key']:
            row['related']=self.all('''SELECT action_key,label,name,at_ns,current_outcome,initiation FROM viewer_actions
                   WHERE workflow_key=? ORDER BY at_ns,action_key''',(row['workflow_key'],))
            for x in row['related']:x['when_fa']=tehran(x['at_ns'])
        else:row['related']=[]
        row['bill_related']=self.related_bill_evidence(row['root_request_key'],row['session_key'])
        row['inquiry_journey']=self.inquiry_payment_journey(row['root_request_key']) if row['name'] in INQUIRIES else None
        row['bill_item_journey']=self.bill_item_journey(row['root_request_key'],inquiry_journey=row['inquiry_journey'])
        row['payment_contract']=self.payment_contract_card(key)
        row['service_payments']=self.service_payment_journey(row['root_request_key'])
        row['service_journey']=self.service_journey(key)
        row['outcome_history']=self.all('SELECT status,at_ns,source_callpath,source_request_key,origin_key,version_key FROM viewer_action_history WHERE action_key=? ORDER BY at_ns,origin_key,version_key,status',(key,))
        for o in row['outcome_history']:o['when_fa']=tehran(o['at_ns'])
        return row

    def request(self,key):
        row=self.one('SELECT * FROM viewer_requests WHERE request_key=?',(key,))
        if row:
            self.apply_service_contexts([row])
            row['raw_request_id']=self.raw_request_id(key)
            row['raw_session_id']=self.raw_session_id(row['session_key']) if row['session_key'] else None
            row['from_fa']=tehran(row['started_ns']);row['to_fa']=tehran(row['ended_ns'])
            row['inquiry_journey']=self.inquiry_payment_journey(key) if core_name(row['root_call'] or '') in INQUIRIES else None
            row['bill_item_journey']=self.bill_item_journey(key,request=row,inquiry_journey=row['inquiry_journey'])
            row['payment_contract']=self.payment_contract_card(key)
            row['service_payments']=self.service_payment_journey(key)
            row['service_journey']=self.service_journey(key)
        return row

    def evidence(self,request_key,limit=50,offset=0):
        total=self.one('SELECT COUNT(*) AS n FROM viewer_events WHERE request_key=?',(request_key,))['n']
        rows=self.all('''SELECT e.origin_key,e.version_key,e.filename,e.row_number,e.at_ns,e.kind,e.callpath,e.code,e.observation,
                       (SELECT COUNT(*) FROM viewer_events c WHERE c.origin_key=e.origin_key) AS variant_count
                       FROM viewer_events e WHERE e.request_key=?
                       ORDER BY e.at_ns,e.origin_key LIMIT ? OFFSET ?''',(request_key,limit,offset))
        for r in rows:r['when_fa']=tehran(r['at_ns'])
        return dict(items=rows,total=total,limit=limit,offset=offset)

    def lookup_request(self,raw):return self.request(token(self.keys,'request',raw))
    def lookup_session(self,raw):return token(self.keys,'session',raw)

    def find_payment_groups(self):
        """Return HMAC-key groups for exact platform paymentKey, with evidence pointers."""
        return self.all('''SELECT l.link_key,COUNT(DISTINCT l.request_key) AS requests
             FROM viewer_links l WHERE l.link_domain='platform_payment'
             GROUP BY l.link_key HAVING COUNT(DISTINCT l.request_key)>1 ORDER BY requests DESC''')
