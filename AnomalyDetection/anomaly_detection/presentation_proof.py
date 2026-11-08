"""Read-only receipt of a persisted rate comparison, never an evaluator."""
from datetime import datetime
import json
import re
from zoneinfo import ZoneInfo
from . import BUILD_ID,FIVE_NS


def target_time(value):
    parsed=datetime.strptime(value,'%Y-%m-%d %H:%M').replace(tzinfo=ZoneInfo('Asia/Tehran'))
    at=int(parsed.timestamp())*1_000_000_000
    if at%FIVE_NS:raise ValueError('target must start at a five-minute boundary in Tehran')
    return at


def collect(store,session,target):
    if not re.fullmatch('[0-9a-f]{64}',session) or not 0<target<2**63 or target%FIVE_NS:raise ValueError('invalid proof scope')
    job=store.raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(session,target)).fetchone()
    if not job:return {'build_id':BUILD_ID,'status':'WAITING_FOR_SOURCE_OR_JOB','session_key':session,'target_ns':target,'models_executed':False}
    summary=store.raw.execute('SELECT w.body,sw.complete FROM anomaly_detection.adp_windows w LEFT JOIN anomaly_detection.adp_source_windows sw ON sw.start_ns=w.start_ns WHERE w.session_key=%s AND w.start_ns=%s',(session,target)).fetchone()
    window=json.loads(summary['body']) if summary else {};source_complete=bool(summary and summary['complete'] and window.get('coverage_complete'))
    from .primary_pipeline import counts_proof
    rows=counts_proof(store,session,target)
    counts={r['service_path']:r['n'] for r in rows};qualified={r['service_path']:r['qualified'] for r in rows}
    count_match=counts==window.get('counts');value=json.loads(job['evaluation'] or '{}')
    primary_current=value.get('primary_version')==job.get('primary_version') and job.get('primary_version') is not None
    from .cases import identity
    from .case_summary import case_status
    from .service_reference import rank_screen
    from .input_subjects import CONTRACTS as INPUT_CONTRACTS,FAMILY as INPUT_FAMILY,decisions as input_decisions
    services=[]
    subject_context=None
    for service,count in sorted((window.get('counts') or {}).items()):
        decision=next((d for d in value.get('decisions',[]) if d['family']=='peer_service_rate_5m' and d.get('service_path')==service),None)
        row=store.raw.execute('SELECT body FROM anomaly_detection.adp_models WHERE model_id=%s',((decision or {}).get('model_id',''),)).fetchone()
        model=json.loads(row['body']) if row else None
        key=identity('actor',session,'activity',service);case=case_status(store,key)
        case_bucket=case['bucket'] if case else None
        screen=rank_screen(model,count,decision.get('comparison_count',1)) if model and model.get('status')=='READY_BASELINE' else None
        eligible=bool(screen and screen['high'] and count>model['upper'])
        rank_match=bool(screen and decision and abs(screen['adjusted_empirical_tail_rank']-decision.get('adjusted_empirical_tail_rank',-1))<1e-12 and decision.get('observed')==count and model.get('cutoff_ns')==target)
        evidence_complete=bool(count>0 and qualified.get(service,0)==count and count_match and source_complete)
        status='WAITING_FOR_CURRENT_COMPARISON'
        if primary_current and source_complete and count_match and decision:
            if decision['status']=='INSUFFICIENT_DATA':status='INSUFFICIENT_REFERENCE_OR_COMPARABILITY'
            elif not rank_match:status='REFERENCE_RECEIPT_MISMATCH'
            elif decision['status']=='CANDIDATE' and eligible:
                status='PASS_REVIEWABLE_RATE_FINDING' if evidence_complete and case_bucket in ('READY','REVIEWED','EVIDENCE') else 'WAITING_FOR_QUALIFIED_EVIDENCE_OR_DISPLAY'
            elif decision['status']=='CANDIDATE':status='STATISTICAL_OBSERVATION_ONLY_WITHIN_REFERENCE_MAX'
            else:status='PASS_RATE_COMPARISON_ONLY' if not screen['high'] else 'REFERENCE_RECEIPT_MISMATCH'
        input_decision=next((d for d in value.get('decisions',[]) if d['family']==INPUT_FAMILY and d.get('service_path')==service),None)
        input_finding=None
        if input_decision:
            subject_key=identity('actor',session,'subject_enumeration',service)
            subject_case=case_status(store,subject_key) if input_decision['status']=='CANDIDATE' else None
            recomputed=None
            if input_decision['status']=='CANDIDATE' and model and rank_match and primary_current and source_complete and count_match:
                from .primary_pipeline import context as primary_context
                if subject_context is None:subject_context=primary_context(store,job)
                if subject_context:
                    recomputed=next(input_decisions(job,subject_context,subject_context['primary_details'],[decision|{'model':model}]),None)
            confirmed=bool(recomputed and recomputed['status']=='CANDIDATE'
                and all(recomputed.get(k)==input_decision.get(k) for k in ('observed','verified_input_requests','observed_requests','observed_span_ns','reference_model_id','upper_bound_tail_rank'))
                and subject_case and subject_case['bucket'] in ('READY','REVIEWED','EVIDENCE'))
            input_finding={'status':'PASS_REVIEWABLE_INPUT_SUBJECT_FINDING' if confirmed else 'INPUT_SUBJECT_NOT_CONFIRMED',
                'decision':input_decision,'case_key':subject_key if subject_case else None,
                'case_bucket':subject_case['bucket'] if subject_case else None}
        elif service in INPUT_CONTRACTS and decision:
            input_finding={'status':'INPUT_SUBJECT_METHOD_NOT_RECORDED',
                'decision':{'status':'INSUFFICIENT_DATA','reason':'INPUT_SUBJECT_METHOD_NOT_RECORDED',
                    'explanation_fa':'ارزیابی موضوع ورودی برای این نشست و بازه هنوز ثبت نشده است.'},
                'case_key':None,'case_bucket':None}
        services.append({'service_path':service,'status':status,'summary_executions':count,'persisted_fact_executions':counts.get(service,0),
            'qualified_evidence_executions':qualified.get(service,0),'decision':decision,'model_id':model.get('model_id') if model else None,
            'reference_sessions':model.get('other_session_epochs') if model else None,'reference_max':model.get('upper') if model else None,
            'reference_median':model.get('expected') if model else None,'recomputed_adjusted_rank':screen.get('adjusted_empirical_tail_rank') if screen else None,
            'case_key':key if case else None,'case_bucket':case_bucket,'evidence_complete':evidence_complete,
            'input_subject_finding':input_finding})
    statuses={s['status'] for s in services}
    overall='PASS_REVIEWABLE_RATE_FINDING' if 'PASS_REVIEWABLE_RATE_FINDING' in statuses and all(s.startswith('PASS_') for s in statuses) else 'PASS_RATE_COMPARISON_ONLY' if statuses and all(s.startswith('PASS_') for s in statuses) else 'NOT_READY_OR_LIMITED'
    if any((s['input_subject_finding'] or {}).get('status')=='PASS_REVIEWABLE_INPUT_SUBJECT_FINDING' for s in services):
        overall='PASS_REVIEWABLE_INPUT_SUBJECT_FINDING'
    return {'build_id':BUILD_ID,'status':overall,'session_key':session,'target_ns':target,'target_tehran':datetime.fromtimestamp(target/1e9,ZoneInfo('Asia/Tehran')).isoformat(),
        'source_window_complete':source_complete,'summary_matches_persisted_facts':count_match,'primary_input_current':primary_current,
        'global_job_dirty':job['dirty'],'secondary_pending_families':value.get('pending_families',[]),'last_evaluated_ns':job['last_evaluated_ns'],
        'services':services,'models_executed':False,'database_modified':False,'evidence_scope':'PERSISTED_AD_AUDIT_OF_VIEWER_NOT_A_NEW_SOURCE_READ',
        'meaning_fa':'این مدرک ثبت، مقایسه، شاهد و نمایش همین رفتار را بررسی می‌کند؛ اثبات تقلب یا سنجش دقت کل محصول نیست. گذر مقایسهٔ نرخ به معنی عادی بودن تمام رفتار کاربر نیست.'}


def render(store,session,target):
    from .product_web import text,when
    value=collect(store,session,target)
    labels={'PASS_REVIEWABLE_INPUT_SUBJECT_FINDING':'یافتهٔ موضوع‌های ورودی متمایز آمادهٔ بررسی',
        'PASS_REVIEWABLE_RATE_FINDING':'یافتهٔ نرخ با شاهد کامل و پروندهٔ قابل بررسی',
        'PASS_RATE_COMPARISON_ONLY':'مقایسهٔ نرخ کامل است؛ از معیار عبور نکرده',
        'WAITING_FOR_QUALIFIED_EVIDENCE_OR_DISPLAY':'یافته ثبت شده؛ تکمیل شاهد یا نمایش در جریان است',
        'INSUFFICIENT_REFERENCE_OR_COMPARABILITY':'مرجع کافی یا مقایسهٔ هم‌دامنه فراهم نیست',
        'STATISTICAL_OBSERVATION_ONLY_WITHIN_REFERENCE_MAX':'مشاهدهٔ آماری؛ داخل بیشینهٔ مرجع',
        'WAITING_FOR_CURRENT_COMPARISON':'مقایسهٔ ورودی جاری هنوز کامل نشده',
        'REFERENCE_RECEIPT_MISMATCH':'مدرک مقایسه نیازمند بررسی فنی است',
        'NOT_READY_OR_LIMITED':'یک یا چند بخش هنوز آماده نیست',
        'WAITING_FOR_SOURCE_OR_JOB':'دریافت رفتار یا ساخت کار ارزیابی هنوز انجام نشده'}
    body='<section><h2>مدرک قابل ارائهٔ ارزیابی</h2><p><strong>'+text(labels.get(value['status'],value['status']))+'</strong></p>'
    body+='<p>'+text(value.get('target_tehran',when(target)))+'</p><p class="identity">'+text(session)+'</p>'
    body+='<p>خواندن این صفحه مدل را اجرا نمی‌کند و داده را تغییر نمی‌دهد. '+text(value.get('meaning_fa',''))+'</p>'
    for item in value.get('services',[]):
        body+='<h3 class="ltr">'+text(item['service_path'])+'</h3><p>'+text(labels.get(item['status'],item['status']))+'</p>'
        body+='<p>خلاصه / رفتار یکتا / شاهد تأییدشده: '+text(item['summary_executions'])+' / '+text(item['persisted_fact_executions'])+' / '+text(item['qualified_evidence_executions'])+'</p>'
        body+='<p>نشست‌های مرجع: '+text(item['reference_sessions'])+' · میانه: '+text(item['reference_median'])+' · بیشینه: '+text(item['reference_max'])+'</p>'
        if item['case_key']:body+='<a href="/case/'+text(item['case_key'])+'">پرونده و تاریخچهٔ همین رفتار</a>'
        subject=item.get('input_subject_finding')
        if subject:
            body+='<p>'+text(subject['decision'].get('explanation_fa'))+'</p>'
            if subject['case_key']:body+='<a href="/case/'+text(subject['case_key'])+'">پروندهٔ موضوع‌های ورودی</a>'
    body+='<details><summary>جزئیات قابل ذخیرهٔ مدرک</summary><pre class="ltr">'+text(json.dumps(value,ensure_ascii=False,indent=2))+'</pre></details></section>'
    return body
