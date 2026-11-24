"""Conservative review policy over current signals, not a fraud classifier."""
from collections import defaultdict
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from compact_behavior import FIVE, inquiry
from compact_behavior.extract import digest

from compact_ad.inquiry_patterns import POLICY as INQUIRY_BURST
from compact_ad.security import POLICY as SECURITY_POLICY
from compact_ad.inquiry_breadth import POLICY as BREADTH_POLICY

POLICY = 'qualified-review-8'
CASE_ID_NAMESPACE = 'qualified-review-4'  # Existing case URLs identify the session/service.
LIMIT = 10000
CONTEXT_METHODS = {'isolation_forest', 'repeated_target'}
BULK_DELETE = 'Core.v1/UserServiceQueryDelete'


def reviewed_diversity(row):
    r = row['result']
    return (row['method'] == 'target_diversity' and r.get('subject_policy') == inquiry.POLICY
            and any(r.get('numeric_path') == axis for axis, _ in inquiry.ROUTES.get(row['service'], ()))
            and type(r.get('observed')) is int and type(r.get('threshold')) in (int, float)
            and 0 < r['threshold'] < r['observed'])


def dimension(row, service):
    method = row['method']
    if row['service'] == BULK_DELETE or service == BULK_DELETE:
        return None
    if method in ('actor_rate', 'rate_limit_rejections'):
        return 'volume'
    if reviewed_diversity(row):
        return 'targets'
    if method == 'service_sequence' and service in row['result'].get('rare_cross_services', ()):
        return 'cross_service_sequence'
    if method == 'timing_regularization' and service in row['result'].get('timing_services', ()):
        return 'timing'
    return None


def day_bounds(value=None):
    zone=ZoneInfo('Asia/Tehran')
    day=value or datetime.now(zone).strftime('%Y-%m-%d')
    start=datetime.strptime(day,'%Y-%m-%d').replace(tzinfo=zone)
    if start.strftime('%Y-%m-%d')!=day:raise ValueError('invalid_day')
    return day,int(start.timestamp())*10**9,int((start+timedelta(days=1)).timestamp())*10**9


def supported(row):
    r=row['result']
    return (r.get('reference_windows',0)>=24 and len(set(r.get('evidence') or []))>=3)


def service_groups(cases):
    groups={}
    for case in cases:
        for service in case['services']:
            # Session-wide patterns are not attributed to every visited service.
            if service=='*':continue
            group=groups.setdefault(service,dict(service=service,sessions=set(),cases=set(),
                methods=set(),last_ns=0,health=False))
            group['cases'].add(case['case_id'])
            if case['session_id']:group['sessions'].add(case['session_id'])
            elif case['domain']=='service_health':group['health']=True
            if case['domain']=='network_attempts':group['network']=True
            for finding in case['findings']:
                if (finding['service']==service or case['domain']=='network_attempts'
                        and service in finding['result'].get('endpoints', ())):
                    if ('preview' not in group or finding['start_ns']>group['preview']['start_ns']):
                        group['preview']=finding
                        group['preview_case_id']=case['case_id']
                    group['methods'].add(finding['method'])
                    group['last_ns']=max(group['last_ns'],finding['start_ns'])
    return sorted(groups.values(),key=lambda g:(g['last_ns'],g['service']),reverse=True)


def select_cases(rows):
    """Caller fences source/model/revision, pending work and human feedback.

    Keep model outliers as context. Only reviewed target counts or specific
    measured dimensions can qualify automatic session cases. A rare self-loop
    caused by retries cannot substantiate a rate finding. Stored older pattern
    rows without the new scope evidence stay available in the signal view.
    """
    accepted={};reasons=defaultdict(set)
    def accept(group, why):
        for r in group:
            accepted[r['finding_id']]=r;reasons[r['finding_id']].add(why)
    sessions=defaultdict(list);persistent=defaultdict(list)
    for row in rows:
        if row.get('verdict')=='CONFIRMED':accept([row],'HUMAN_CONFIRMED')
        r=row['result']
        if (row.get('session_id') and row['method']=='target_diversity'
                and r.get('inquiry_breadth_policy')==BREADTH_POLICY and r.get('single_signal_review_eligible') is True
                and r.get('subject_policy')==inquiry.POLICY
                and r.get('numeric_path') in {axis for axis,_ in inquiry.ROUTES.get(row['service'],())}
                and r.get('requests',0)>=r.get('covered_requests',0)>=r.get('distinct_targets',0)>=10
                and len(set(r.get('evidence') or []))>=3):
            accept([row],'ENUMERATED_REQUESTED_TARGETS')
        if (row['method'] in ('access_denied_attempts', 'invalid_session_attempts')
                and r.get('security_policy') == SECURITY_POLICY
                and r.get('single_signal_review_eligible') is True
                and r.get('entity_key') and r.get('span_seconds', 0) >= 30
                and len(set(r.get('evidence') or [])) >= 3):
            accept([row], 'REPEATED_ACCESS_DENIALS' if row['method']=='access_denied_attempts' else 'REPEATED_INVALID_SESSION_ATTEMPTS')
        if (row.get('session_id') and row['method'] in ('target_diversity','repeated_target')
                and r.get('inquiry_pattern_policy') == INQUIRY_BURST and r.get('single_signal_review_eligible')
                and r.get('subject_policy') == inquiry.POLICY and r.get('requests',0) >= 12
                and r['requests'] == r.get('covered_requests') == r.get('successful_requests')
                and r.get('numeric_path') in {axis for axis,_ in inquiry.ROUTES.get(row['service'], ())}
                and len(set(r.get('evidence') or [])) >= 3):
            accept([row], 'REPEATED_VERIFIED_INQUIRIES' if row['method']=='repeated_target' else 'ENUMERATED_VERIFIED_INQUIRIES')
        if not supported(row):continue
        if (row.get('session_id') and row['method'] == 'long_target_enumeration'
                and r.get('single_signal_review_eligible') is True and r.get('peer_count',0) >= 100
                and r.get('adjusted_tail_rank',1) <= .05 and r.get('horizon_days') in (3,7,30)):
            accept([row], 'QUALIFIED_SINGLE_METHOD')
        if row.get('session_id') and reviewed_diversity(row) and r['observed'] >= 2 * r['threshold']:
            accept([row], 'DISTINCT_REVIEWED_TARGETS')
        if row.get('session_id') and row['method'] in (
                'actor_rate', 'target_diversity', 'rate_limit_rejections', 'service_sequence',
                'timing_regularization', *CONTEXT_METHODS):
            sessions[(row['session_id'],row['start_ns'])].append(row)
        # Persistence cannot validate an inappropriate reference population.
        # Current latency/result detectors have no validated time-context model;
        # keep those signals available, but do not promote them automatically.
        if (row['method'] in ('service_latency','reported_result') and row.get('session_id') is None
                and row['result'].get('baseline_family') in ('daily','weekly')
                and row['result'].get('validation_samples',0)>=12
                and (row['method']!='service_latency' or row['result'].get('duration_valid',0)>=40)):
            persistent[(row['service'],row['method'])].append(row)
    for group in sessions.values():
        services={r['service'] for r in group if r['service']!='*'} or {'*'}
        for service in services:
            subset=[r for r in group if r['service'] in (service,'*')]
            evidence = [r for r in subset if dimension(r, service)]
            if len({dimension(r, service) for r in evidence}) >= 2:
                accept(evidence, 'CORROBORATED_SAME_SESSION_WINDOW')
                for r in subset:
                    if r['method'] in CONTEXT_METHODS:
                        accepted[r['finding_id']] = r
    for group in persistent.values():
        # Multiple numeric paths in a single window are not persistence.
        by_time=defaultdict(list)
        for r in group:by_time[r['start_ns']].append(r)
        for at in by_time:
            if at-FIVE in by_time and at-2*FIVE in by_time:
                accept(by_time[at]+by_time[at-FIVE]+by_time[at-2*FIVE],'PERSISTENT_SERVICE_HEALTH')
    cases={}
    for fid,row in accepted.items():
        # Session-wide pattern signals stay on their own scope; never invent a
        # service binding. Link corroborating findings inside the same case.
        network = row['method']=='invalid_session_attempts' and row['result'].get('entity_type')=='ip'
        domain='network_attempts' if network else 'session' if row.get('session_id') else 'service_health'
        key=(domain,row['result']['entity_key'] if network else row.get('session_id') or row['service'])
        c=cases.setdefault(key,dict(case_id=digest([CASE_ID_NAMESPACE,*key])[:32],domain=domain,
            session_id=row.get('session_id'),services=set(),methods=set(),reasons=set(),findings=[],
            first_ns=row['start_ns'],last_ns=row['start_ns']))
        c['findings'].append(row)
        c['services'].update(row['result'].get('endpoints') or ['*']) if network else c['services'].add(row['service'])
        c['methods'].add(row['method'])
        c['reasons'].update(reasons[fid]);c['first_ns']=min(c['first_ns'],row['start_ns']);c['last_ns']=max(c['last_ns'],row['start_ns'])
    for c in cases.values():
        for k in ('services','methods','reasons'):c[k]=sorted(c[k])
        c['findings'].sort(key=lambda r:(r['start_ns'],r['finding_id']),reverse=True)
        c['highlights']=[];seen=set()
        for row in c['findings']:
            if row['method'] not in seen and len(c['highlights'])<3:
                c['highlights'].append(row);seen.add(row['method'])
    return sorted(cases.values(),key=lambda c:(c['last_ns'],c['case_id']),reverse=True)


REASONS={
 'ENUMERATED_REQUESTED_TARGETS':'یک نشست در بازهٔ کوتاه هدف‌های متفاوتی را برای یک خدمت درخواست کرده است؛ موفق، ناموفق و نامعلوم بودن پاسخ جدا نمایش داده می‌شود.',
 'REPEATED_ACCESS_DENIALS':'در پنج دقیقه، تلاش‌های معتبر و پرتکرار برای خدمت بدون مجوز ثبت شده است؛ مجوز و تکرارهای برنامه باید بررسی شوند.',
 'REPEATED_INVALID_SESSION_ATTEMPTS':'از یک IP مشاهده‌شده، تلاش‌های پرتکرار با نشست نامعتبر ثبت شده است. نشست منقضی، خطای برنامه و IP مشترک هم ممکن‌اند؛ حدس‌زدن توکن اثبات نشده است.',
 'REPEATED_VERIFIED_INQUIRIES':'یک نشست در پنج دقیقه بارها با ورودی‌های یکسان استعلام موفق گرفته است.',
 'ENUMERATED_VERIFIED_INQUIRIES':'یک نشست در پنج دقیقه برای شناسه‌های متعدد و متفاوت استعلام موفق گرفته است.',
 'QUALIFIED_SINGLE_METHOD':'یک روش به‌تنهایی شرایط شواهد قوی را دارد: پوشش معتبر، مرجع کافی و فاصلهٔ روشن از رفتار مرجع. وجود روش دوم شرط نیست؛ نتیجه نیازمند بررسی است.',
 'DISTINCT_REVIEWED_TARGETS':'تعداد شناسه‌های ورودی متمایز در پنج دقیقه دست‌کم دو برابر آستانهٔ محاسبه‌شده از سابقهٔ همان خدمت و فیلد است.',
 'CORROBORATED_SAME_SESSION_WINDOW':'در همان نشست و پنجره، دو ویژگی قابل بررسی برای یک خدمت دیده شده‌اند. جزئیات هر روش در ادامه آمده است.',
 'PERSISTENT_SERVICE_HEALTH':'تداوم هشدار همین خدمت در سه پنجرهٔ متوالی با مرجع زمانی اعتبارسنجی‌شده؛ مربوط به عملکرد خدمت، نه اثبات سوءاستفادهٔ کاربر.',
 'HUMAN_CONFIRMED':'این نسخهٔ نتیجه قبلاً توسط بررسی‌کننده تأیید شده است.'}
