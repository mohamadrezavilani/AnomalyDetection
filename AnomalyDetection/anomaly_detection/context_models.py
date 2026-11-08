"""Qualified context signals. Missing optional OTP/payment is never failure.

These dimensions explain a service/journey deviation; they do not count as
independent proof of suspicious customer intent or settled financial outcome.
"""
from collections import Counter,defaultdict
import math
from . import FIVE_NS
from .snapshot import digest
from .temporal import quantile

FAMILIES=('request_latency','otp_result_change','payment_result_change','typed_target_diversity','journey_profile_change')

def evaluate(context,details):
    session=context['session_key'];target=context['target_ns'];decisions=[]
    records=defaultdict(list)
    for record in details:
        fact=record.get('details') or {};quality=fact.get('quality',{})
        if not (fact.get('source_present') and quality.get('evidence_available') and not quality.get('conflicted')):continue
        service=record.get('service_path');at=record['at_ns'];kind=fact.get('semantic',{}).get('kind')
        if not service:continue
        key=(service,kind);transport=fact.get('transport',{});start=transport.get('started_ns');end=transport.get('ended_ns')
        duration=(end-start)/1e9 if type(start) is int and type(end) is int and end>=start else None
        if at<target and (type(end) is not int or end>=target):duration=None
        otp={str(o['value']) for o in fact.get('observations',[]) if o.get('qualified') and o.get('axis')=='service_dispatch.otp_validation'
             and (at>=target or type(o.get('at_ns')) is int and o['at_ns']<target)}
        # Scope/type/issuer are part of the identifier, so unrelated namespaces
        # and equal-looking numeric IDs are never combined.
        observed={e['origin_key']:e.get('at_ns') for e in fact.get('evidence',[])}
        ids={(i['issuer'],i['kind'],i.get('scope'),i['identity_key']) for i in fact.get('identifiers',[]) if i.get('evidence_quality',{}).get('qualified')
             and (at>=target or type(observed.get(i['origin_key'])) is int and observed[i['origin_key']]<target)}
        enrichment=fact.get('viewer_journey') or {};journey=enrichment.get('journey') or {}
        profile=None
        if journey and not journey.get('truncated') and not journey.get('coverage_caveats') and journey.get('identity_status') in ('resolved','multiple_anchors_not_merged'):
            # Related step roles/types are observed shape, not a reconstructed
            # sequence of clicks. Optional missing stages add no negative flag.
            profile=tuple(sorted({s.get('role','unknown') for s in journey.get('steps',[])}))
            if at<target and any(type(s.get('ended_ns')) is not int or s['ended_ns']>=target for s in journey.get('steps',[])):profile=None
        payment=enrichment.get('payment') or {};reported=[]
        if not payment.get('truncated'):
            for invoice in payment.get('invoices',[]):
                if record['request_key'] not in {s['request_key'] for s in invoice.get('sources',[])}:continue
                for field,label in (('inquiry_payments','invoice_fee'),('bill_payments','bill_payment')):
                    for item in invoice.get(field,[]):
                        values={s['value'] for s in item.get('statuses',[]) if at>=target or
                            type(s.get('evidence',{}).get('at_ns')) is int and s['evidence']['at_ns']<target}
                        if values:reported.append((label,tuple(sorted(values))))
        records[key].append({'at':at,'session':fact.get('semantic',{}).get('session_key',session),'request_key':record['request_key'],'latency':duration,'otp':otp,'targets':ids,'profile':profile,'payments':tuple(sorted(reported))})
    def emit(family,service,status,reason,**values):
        decisions.append({'finding_key':'pf1:'+digest([session,target,family,service]),'session_key':session,'target_ns':target,
            'family':family,'dimension':'context','service_path':service,'status':status,'reason':reason,
            'baseline_origin':'same_service_and_kind_verified_history','comparison_cutoff_ns':target,'method_version':'qualified-context-2',
            'operator_alert':False,'precision_recall':'NOT_EVALUATED','score_interpretation':'context_deviation_not_fraud_probability',**values})
    seen=set()
    for (service,kind),rows in records.items():
        past=[r for r in rows if r['at']<target];current=[r for r in rows if target<=r['at']<target+FIVE_NS]
        if not current:continue
        durations=[r['latency'] for r in past if r['latency'] is not None]
        now=[r for r in current if r['latency'] is not None]
        if len(durations)>=100 and now:
            upper=max(.001,quantile(durations,.99));worst=max(now,key=lambda r:r['latency']);value=worst['latency'];high=value>3*upper
            emit('request_latency',service,'CANDIDATE' if high else 'NO_DEVIATION_OBSERVED','OBSERVED_REQUEST_SPAN_CHANGE' if high else 'OBSERVED_REQUEST_SPAN_WITHIN_RANGE',
                score=math.log2(1+value/upper),observed=value,upper=upper,witness_request_key=worst['request_key'],
                measurement='first_to_last_observed_event_span',is_http_duration_proof=False,
                explanation_fa='فاصلهٔ اولین تا آخرین شاهد همان درخواست با سابقه مقایسه شد؛ این مقدار زمان قطعی HTTP یا اثبات کندی Provider نیست.')
            seen.add('request_latency')
        otp_before=Counter(next(iter(r['otp'])) for r in past if len(r['otp'])==1)
        otp_now=[r for r in current if len(r['otp'])==1]
        if sum(otp_before.values())>=100 and len(otp_now)>=10:
            novel=sum(otp_before[next(iter(r['otp']))]==0 for r in otp_now)/len(otp_now)
            emit('otp_result_change',service,'CANDIDATE' if novel>.5 else 'NO_DEVIATION_OBSERVED','OTP_RESULT_DISTRIBUTION',score=novel,
                witness_request_key=otp_now[0]['request_key'],explanation_fa='کدهای صریح نتیجهٔ تأیید OTP در همان خدمت مقایسه شدند؛ نبود مرحلهٔ OTP شکست فرض نشده است.')
            seen.add('otp_result_change')
        payment_before=Counter(r['payments'] for r in past if r['payments'])
        payment_now=[r for r in current if r['payments']]
        if sum(payment_before.values())>=100 and len(payment_now)>=10:
            novel=sum(payment_before[r['payments']]==0 for r in payment_now)/len(payment_now)
            emit('payment_result_change',service,'CANDIDATE' if novel>.5 else 'NO_DEVIATION_OBSERVED','REPORTED_PAYMENT_PROFILE_CHANGE',score=novel,
                witness_request_key=payment_now[0]['request_key'],
                explanation_fa='الگوی وضعیت گزارش‌شدهٔ هزینهٔ استعلام و پرداخت قبض، جداگانه مقایسه شد؛ نبود پرداخت اختیاری شکست و Success گواه تسویه بانکی نیست.')
            seen.add('payment_result_change')
        profiles=Counter(r['profile'] for r in past if r['profile'] is not None)
        current_profiles=[r for r in current if r['profile'] is not None]
        if sum(profiles.values())>=100 and len(current_profiles)>=10:
            novel=sum(profiles[r['profile']]==0 for r in current_profiles)/len(current_profiles)
            emit('journey_profile_change',service,'CANDIDATE' if novel>.5 else 'NO_DEVIATION_OBSERVED','OBSERVED_JOURNEY_PROFILE',score=novel,
                witness_request_key=current_profiles[0]['request_key'],
                explanation_fa='ترکیب نقش‌های مرتبط در خروجی خود Viewer تغییر کرده است؛ این مشاهده فقدان پرداخت اختیاری، علت کلیک یا تقلب را اثبات نمی‌کند.')
            seen.add('journey_profile_change')
        # Require verified complete target evidence before measuring diversity.
        buckets=defaultdict(set)
        for r in past:buckets[(r['session'],r['at']//FIVE_NS*FIVE_NS)].update(r['targets'])
        values=[len(v) for v in buckets.values() if v]
        now_ids=set().union(*(r['targets'] for r in current))
        if len(values)>=60 and context.get('evidence_verified') and now_ids:
            upper=max(1,quantile(values,.99));value=len(now_ids);high=value>3*upper
            emit('typed_target_diversity',service,'CANDIDATE' if high else 'NO_DEVIATION_OBSERVED','QUALIFIED_TYPED_IDENTIFIER_DIVERSITY',
                score=math.log2(1+value/upper),observed=value,upper=upper,witness_request_key=current[0]['request_key'],
                explanation_fa='تنوع مراجع وابسته مانند فاکتور و آیتم نتیجه در مقایسه با سابقهٔ همان خدمت بررسی شد. شمار موضوع ورودی معیار جداگانه دارد.')
            seen.add('typed_target_diversity')
    for family in FAMILIES:
        if family not in seen:emit(family,'*','INSUFFICIENT_DATA','QUALIFIED_CONTEXT_HISTORY_INSUFFICIENT',
            explanation_fa='شواهد یا سابقهٔ هم‌دامنه برای این محور کافی نیست؛ نتیجهٔ عادی یا شکست صادر نشده است.')
    return decisions
