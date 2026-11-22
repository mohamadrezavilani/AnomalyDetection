"""Conservative review policy over current signals, not a fraud classifier."""
from collections import defaultdict
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from compact_behavior import FIVE
from compact_behavior.extract import digest

POLICY = 'qualified-review-4'
LIMIT = 10000
FAMILIES = {'actor_rate':'volume','isolation_forest':'volume',
    'rate_limit_rejections':'volume','repeated_target':'targets',
    'target_diversity':'targets','service_sequence':'sequence','timing_regularization':'timing'}
CONTEXT_ONLY = {'repeated_target'}


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
            else:group['health']=True
            for finding in case['findings']:
                if finding['service']==service:
                    group['methods'].add(finding['method'])
                    group['last_ns']=max(group['last_ns'],finding['start_ns'])
    return sorted(groups.values(),key=lambda g:(g['last_ns'],g['service']),reverse=True)


def select_cases(rows):
    """Caller fences source/model/revision, pending work and human feedback.

    A qualified standalone detector or two behavioral dimensions can qualify.
    Corroborating dimensions must refer to the same session and
    five-minute window. Rate, forest and rate-limit counts share one dimension;
    Repeated-target counts are context only: the same requests can generate both
    high volume and high repetition, even when every attempt has one target.
    This does not label retries benign or discard their findings. Distinct target
    diversity, sequence and timing can still corroborate another dimension.
    Service health is kept separate.
    No learned precision or statistical independence is claimed by this policy.
    """
    accepted={};reasons=defaultdict(set)
    def accept(group, why):
        for r in group:
            accepted[r['finding_id']]=r;reasons[r['finding_id']].add(why)
    sessions=defaultdict(list);persistent=defaultdict(list)
    for row in rows:
        if row.get('verdict')=='CONFIRMED':accept([row],'HUMAN_CONFIRMED')
        if not supported(row):continue
        r=row['result']
        if (r.get('single_signal_review_eligible') is True and
                ((row['method']=='long_target_enumeration' and r.get('peer_count',0)>=100
                  and r.get('adjusted_tail_rank',1)<=.05 and r.get('horizon_days') in (3,7,30)) or
                 (row['method']=='isolation_forest' and r.get('calibration_rows',0)>=100
                  and r.get('calibration_tail_rank',1)<=.01))):
            accept([row],'QUALIFIED_SINGLE_METHOD')
        if row.get('session_id') and row['method'] in FAMILIES:
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
            if len({FAMILIES[r['method']] for r in subset
                    if r['method'] not in CONTEXT_ONLY})>=2:
                accept(subset,'CORROBORATED_SAME_SESSION_WINDOW')
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
        domain='session' if row.get('session_id') else 'service_health'
        key=(domain,row.get('session_id') or row['service'])
        c=cases.setdefault(key,dict(case_id=digest([POLICY,*key])[:32],domain=domain,
            session_id=row.get('session_id'),services=set(),methods=set(),reasons=set(),findings=[],
            first_ns=row['start_ns'],last_ns=row['start_ns']))
        c['findings'].append(row);c['services'].add(row['service']);c['methods'].add(row['method'])
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
 'QUALIFIED_SINGLE_METHOD':'یک روش به‌تنهایی شرایط شواهد قوی را دارد: پوشش معتبر، مرجع کافی و فاصلهٔ روشن از رفتار مرجع. وجود روش دوم شرط نیست؛ نتیجه نیازمند بررسی است.',
 'CORROBORATED_SAME_SESSION_WINDOW':'هم‌زمانی دست‌کم دو بُعد رفتاری در همان نشست و پنجره؛ مانند نرخ غیرعادی همراه الگوی ورودی یا توالی غیرعادی.',
 'PERSISTENT_SERVICE_HEALTH':'تداوم هشدار همین خدمت در سه پنجرهٔ متوالی با مرجع زمانی اعتبارسنجی‌شده؛ مربوط به عملکرد خدمت، نه اثبات سوءاستفادهٔ کاربر.',
 'HUMAN_CONFIRMED':'این نسخهٔ نتیجه قبلاً توسط بررسی‌کننده تأیید شده است.'}
