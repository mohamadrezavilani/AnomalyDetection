"""Explainable content/network screens. Findings are review candidates.

Ranks and exact-table comparisons are descriptive screens, not a validated
production false-alarm guarantee. No service names or owner test IDs appear.
"""
from collections import Counter,defaultdict
from statistics import median
import math,re
from . import FIVE_NS
from .snapshot import digest

ACTOR_FAMILIES=('repeated_target','subject_enumeration','client_ip_rotation','workflow_change')
SERVICE_FAMILIES=('response_schema_change','response_content_change','service_health','multi_session_target')


def fisher_greater(a,b,c,d):
    """One-sided Fisher exact table: current successes/failures, past ditto."""
    total=a+b+c+d;success=a+c;n=a+b
    if not total:return 1.
    def lc(n,k):return math.lgamma(n+1)-math.lgamma(k+1)-math.lgamma(n-k+1) if 0<=k<=n else -math.inf
    logs=[lc(success,k)+lc(total-success,n-k)-lc(total,n) for k in range(a,min(success,n)+1)]
    m=max(logs)
    return min(1.,math.exp(m)*sum(math.exp(x-m) for x in logs)) if math.isfinite(m) else 0.


def past_only(rows,target):
    return [r for r in rows if r.get('qualified') and r['at_ns']<target and type(r.get('ended_ns')) is int and r['ended_ns']<target and all(w['at_ns']<target for w in r.get('witnesses',[]))]


def metrics(rows):
    rows=list({r['request_key']:r for r in rows}.values())
    bills_by_request={r['request_key']:[x for x in r.get('subjects',[]) if 'billid' in re.sub(r'[^a-z0-9]','',x['field'].lower())] for r in rows}
    bill_fields=[{(x['channel'],x['field']) for x in bills_by_request[r['request_key']]} for r in rows]
    common_bill_fields=set.intersection(*bill_fields) if bill_fields else set()
    groups=defaultdict(set);subjects=defaultdict(set);ips=[]
    for r in sorted(rows,key=lambda x:(x['at_ns'],x['request_key'])):
        if common_bill_fields:
            for x in bills_by_request[r['request_key']]:
                if (x['channel'],x['field']) in common_bill_fields:groups[('typed_bill',x['channel'],x['field'],x['key'])].add(r['request_key'])
        else:
            for channel,key in r.get('targets',{}).items():groups[('business_input',channel,key)].add(r['request_key'])
        for x in r.get('subjects',[]):subjects[(x['channel'],x['field'])].add(x['key'])
        ips.extend(r.get('ip_keys',[]))
    repeated=sorted(max(groups.values(),key=len,default=set()))
    typed=bool(rows and all(r.get('subjects') for r in rows))
    input_diversity=defaultdict(set)
    for r in rows:
        for channel,key in r.get('targets',{}).items():input_diversity[channel].add(key)
    content_covered=bool(rows and all(r.get('targets') and r.get('input_complete',r.get('content_complete',True)) for r in rows))
    return {'repeated_target':len(repeated),'subject_enumeration':max((len(x) for x in (subjects if typed else input_diversity).values()),default=0),
        'repeat_basis':'typed_bill' if common_bill_fields else 'business_input_fingerprints','repeat_fields':sorted(common_bill_fields),
        'subject_basis':'typed_subject_identifiers' if typed else 'business_input_fingerprints',
        'subject_fields':frozenset(subjects if typed else input_diversity),
        'target_coverage':content_covered,'ip_coverage':bool(rows and all(r.get('ip_keys') for r in rows)),
        'service_traversal':len({r['service_path'] for r in rows}),
        'client_ip_rotation':len(set(ips)),'ip_transitions':sum(a!=b for a,b in zip(ips,ips[1:])) if all(len(r.get('ip_keys',[]))==1 for r in rows) else None,
        'repeat_keys':repeated,'observed_requests':len(rows)}


def actor(session,service,target,current,past,reference_units,*,complete):
    result=[];current=[r for r in current if r.get('qualified')];prior=past_only(past,target)
    # Last observed sequence carries a run across window/day boundaries. Its
    # exact expected request list is checked by the store before reviewability.
    now=sorted((prior+current),key=lambda r:(r['at_ns'],r['request_key']))[-100:]
    value=metrics(now);refs=[metrics(sorted(past_only(rows,target),key=lambda r:(r['at_ns'],r['request_key']))[-100:]) for rows in reference_units if len(past_only(rows,target))>=2]
    refs=[r for r in refs if r['observed_requests']>=len(now)]
    def emit(family,status,reason,**kw):
        result.append({'family':family,'entity_type':'actor','entity_key':session,'service_path':service,'target_ns':target,
            'status':status,'reason':reason,'begin_ns':min((r['at_ns'] for r in now),default=target),'end_ns':target+FIVE_NS,
            'evidence_verified':bool(complete and current),'request_keys':[r['request_key'] for r in now],
            'count_scope':'qualified_observed_logical_requests','cold_start':not bool(prior),'reference_actor_units':len(refs),**kw})
    highs={}
    families=(*ACTOR_FAMILIES[:3],'service_traversal') if service=='*' else ACTOR_FAMILIES[:3]
    for family in families:
        n=value[family];base=[r[family] for r in refs]
        comparable=[r[family] for r in refs if (r['target_coverage'] if family in ('repeated_target','subject_enumeration') else r['ip_coverage'] if family=='client_ip_rotation' else True) and
            (family!='subject_enumeration' or r[family]>0 and r['subject_basis']==value['subject_basis']
             and r['subject_fields']==value['subject_fields']) and
            (family!='repeated_target' or r['repeat_basis']==value['repeat_basis'] and r['repeat_fields']==value['repeat_fields'])]
        field='targets' if family in ('repeated_target','subject_enumeration') else 'service_path' if family=='service_traversal' else 'ip_keys'
        covered=bool(complete and current and all(
            r.get(field) and (family in ('client_ip_rotation','service_traversal')
                              or r.get('input_complete',r.get('content_complete',True))) for r in now))
        rank_floor=len(families)/(1+len(comparable))
        enough_reference=len(comparable)>=100 and rank_floor<=.01
        ready=covered and enough_reference
        rank=(1+sum(x>=n for x in comparable))/(1+len(comparable))
        high=bool(ready and n>max(comparable) and rank*len(families)<=.01 and n>=2)
        highs[family]=high
        observed_repeat=family=='repeated_target' and n>=2
        status='CANDIDATE' if high or observed_repeat else 'NO_DEVIATION_OBSERVED' if ready else 'INSUFFICIENT_DATA'
        names={'repeated_target':'تکرار همان موضوع استعلام','subject_enumeration':'تنوع شناسه‌ها یا محتوای موضوع استعلام','client_ip_rotation':'تغییر IP در رویدادهای client همین نشست','service_traversal':'گسترش غیرمعمول پیمایش خدمات در همین نشست'}
        reason='INSUFFICIENT_COMPARABLE_PROFILE_HISTORY'
        note='مرجع یا پوشش کافی فراهم نیست.'
        if high:
            reason='LEARNED_PROFILE_CONTRAST'
            note='از مرجع مقایسه عبور کرده است.'
        elif observed_repeat:
            reason='REPEATED_TARGET_OBSERVED_REFERENCE_NOT_EXCEEDED'
            note='تکرار ثبت شد. مرجع هنوز اولویت مستقل را تأیید نکرده است.'
        elif ready:
            reason='PROFILE_WITHIN_REFERENCE'
            note='از معیار مقایسه عبور نکرده است.'
        elif covered and len(comparable)>=100:
            reason='REFERENCE_TAIL_RESOLUTION_INSUFFICIENT'
            note=f'با {len(comparable)} نشست مرجع، کمترین رتبهٔ تعدیل‌شده {rank_floor:.4g} است و برای این مقایسه کفایت ندارد.'
        emit(family,status,reason,
            activation_rule_fa='پوشش معتبر و مرجع هم‌حجم با تعداد کافی برای تفکیک رتبه لازم است. مقدار باید از بیشینهٔ مرجع عبور کند و رتبهٔ دُم پس از تعدیل حداکثر ۰٫۰۱ باشد. تکرار مشاهده‌شده جدا ثبت می‌شود و تغییر IP به پشتوانهٔ رفتاری نیاز دارد.',
            observed_requests=len(now),
            observed=n,expected=median(comparable) if comparable else None,upper=max(comparable) if comparable else None,
            reference_values=comparable,comparison_count=len(families),subject_basis=value['subject_basis'] if family=='subject_enumeration' else None,
            repeated_subject_basis=value['repeat_basis'] if family=='repeated_target' else None,
            adjusted_empirical_tail_rank=min(1.,rank*len(families)),single_signal_review_eligible=high and family!='client_ip_rotation',
            score=n/max(1,max(comparable,default=1)),ip_transitions=value['ip_transitions'] if family=='client_ip_rotation' else None,
            explanation_fa=f'{names[family]} در {len(now)} درخواستِ مشاهده‌شده مقدار {n} داشت. '+note+
                (' تغییر IP به‌تنهایی اثبات crawling نیست.' if family=='client_ip_rotation' else ' شناسهٔ موضوع، تعداد انسان یا مالکیت آن را ثابت نمی‌کند.' if family=='subject_enumeration' else ''))
    failed_retry_context=bool(current and all(r.get('result') and r['result'].get('code')!='G00000' for r in current) and len({r['result']['scope'] for r in current})==1)
    if failed_retry_context:
        highs['repeated_target']=False
        for d in result:
            if d['family']=='repeated_target':
                d['single_signal_review_eligible']=False;d['reason']='REPEATED_TARGET_WITH_REPORTED_UNSUCCESSFUL_RESULTS'
                d['explanation_fa']+=' تمام نتیجه‌های هم‌دامنهٔ این بخش ناموفق گزارش شده‌اند؛ retry ممکن است توضیح این تکرار باشد و علت ریشه‌ای هنوز معلوم نیست.'
    # IP change corroborated by a learned content deviation, not IP alone.
    if highs.get('client_ip_rotation') and (highs.get('repeated_target') or highs.get('subject_enumeration') or highs.get('service_traversal')):
        for d in result:
            if d['family']=='client_ip_rotation':d.update(single_signal_review_eligible=True,review_basis='QUALIFIED_INDEPENDENT_DIMENSIONS')
    if service=='*':return result
    history=[r for unit in reference_units for r in past_only(unit,target)]
    stage_counts=Counter(s for r in history for s in set(r.get('stages',[])))
    tested=[s for s,n in stage_counts.items() if len(history)>=100 and n/len(history)>=.99]
    changes=[]
    if complete and len(current)>=3:
        for stage in tested:
            missing=sum(stage not in r.get('stages',[]) for r in current);past_missing=len(history)-stage_counts[stage]
            p=fisher_greater(missing,len(current)-missing,past_missing,len(history)-past_missing)
            if missing>=3 and p*max(1,len(tested))<=.01:changes.append({'stage':stage,'missing':missing,'checked':len(current),'past_missing':past_missing,'past_checked':len(history),'comparison_count':len(tested),'adjusted_p':min(1,p*len(tested))})
    emit('workflow_change','CANDIDATE' if changes else 'NO_DEVIATION_OBSERVED' if tested and complete and current else 'INSUFFICIENT_DATA',
        'OBSERVED_WORKFLOW_STAGE_SHIFT' if changes else 'WORKFLOW_REFERENCE_OR_COVERAGE_INSUFFICIENT' if not tested or not complete else 'WORKFLOW_WITHIN_REFERENCE',
        observed=len(changes),single_signal_review_eligible=bool(changes),changed_stages=changes,
        explanation_fa='مراحل تقریباً همیشگیِ مسیر مشاهده‌شده با سابقهٔ همان خدمت مقایسه شدند؛ غیبت در لاگ، اثبات دورزدن مجوز نیست.'+
            (' مراحل تغییرکرده: '+ '، '.join(x['stage'] for x in changes[:8]) if changes else ''))
    return result


def service(service,target,current,past,*,independent=False):
    history=past_only(past,target);current=[r for r in current if r.get('qualified')];out=[]
    actors=lambda rows:{r['session_key'] for r in rows if r.get('session_key') and r.get('actor_qualified',True)}
    ready=bool(independent and len(history)>=100 and len(actors(history))>=20 and len(current)>=10 and len(actors(current))>=3)
    def emit(family,status,reason,**kw):
        out.append({'family':family,'entity_type':'service','entity_key':service,'service_path':service,'target_ns':target,
            'begin_ns':target,'end_ns':target+FIVE_NS,'status':status,'reason':reason,'evidence_verified':ready,
            'single_signal_review_eligible':status=='CANDIDATE','request_keys':[r['request_key'] for r in current],
            'count_scope':'independent_qualified_request_sample_not_all_customers','reference_requests':len(history),
            'observed_requests':len(current),'distinct_sessions':len(actors(current)),**kw})
    if not ready:
        for f in SERVICE_FAMILIES:emit(f,'INSUFFICIENT_DATA','INDEPENDENT_CONTENT_SAMPLE_OR_HISTORY_INCOMPLETE',explanation_fa='نمونهٔ مستقل، شاهد کامل درخواست یا سابقهٔ هم‌دامنه کافی نیست؛ نتیجهٔ عادی یا قطعی صادر نمی‌شود.')
        return out
    tests=[];comparisons=0;available_families=set()
    def add_test(item):
        nonlocal comparisons
        comparisons+=1;available_families.add(item[0])
        a,n,c,m=item[3:7]
        # Keep the full multiplicity count without retaining or evaluating
        # every singleton response value. Only a sufficiently large effect
        # can pass the rule, regardless of its exact-table probability.
        if a>=5 and a/n-c/m>=.3:tests.append(item)
    channels=set.intersection(*(set(r.get('outputs',{})) for r in current)) if current and all(r.get('output_complete',r.get('content_complete',True)) for r in current) else set()
    for channel in sorted(channels):
        older=[r for r in history if channel in r.get('outputs',{}) and r.get('output_complete',r.get('content_complete',True))]
        old=[r['outputs'][channel] for r in older];new=[r['outputs'][channel] for r in current]
        if len(old)<100 or len(actors(older))<20:continue
        shape=Counter(x['shape'] for x in old)
        for k,n in Counter(x['shape'] for x in new).items():add_test(('response_schema_change',channel,k,n,len(new),shape[k],len(old),{}))
        fields=set().union(*(set(x['categories']) for x in old+new))
        for field in sorted(fields)[:64]:
            before=Counter(x['categories'].get(field,'<absent>') for x in old)
            for category,n in Counter(x['categories'].get(field,'<absent>') for x in new).items():
                add_test(('response_content_change',channel,field,n,len(new),before[category],len(old),{'value':category}))
    flagged=defaultdict(list)
    for family,channel,field,a,n,c,m,extra in tests:
        affected=[r for r in current if (r['outputs'][channel]['shape']==field if family=='response_schema_change' else r['outputs'][channel]['categories'].get(field,'<absent>')==extra['value'])]
        # Many calls by one actor cannot support a service-wide incident.
        support=len(actors(affected))
        if support<3:continue
        p=fisher_greater(a,n-a,c,m-c);adjusted=min(1.,p*max(1,comparisons))
        if adjusted<=.01:flagged[family].append({'channel':channel,'field':field,'current_count':a,'current_total':n,'reference_count':c,'reference_total':m,'comparison_count':comparisons,'supporting_sessions':support,'witness_request_key':affected[0]['request_key'],'current_share':a/n,'past_share':c/m,'adjusted_p':adjusted,**extra})
    for family in SERVICE_FAMILIES[:2]:
        changed=flagged[family]
        available=family in available_families
        emit(family,'CANDIDATE' if changed else 'NO_DEVIATION_OBSERVED' if available else 'INSUFFICIENT_DATA','RESPONSE_DISTRIBUTION_SHIFT' if changed else 'OBSERVED_RESPONSE_WITHIN_REFERENCE' if available else 'NO_COMPARABLE_OUTPUT_FIELDS',
            observed=len(changed),changed_fields=changed[:64],witness_request_key=changed[0]['witness_request_key'] if changed else None,score=max((x['current_share']-x['past_share'] for x in changed),default=0),
            explanation_fa=('ساختار خروجی' if family=='response_schema_change' else 'محتوا و مقادیر نتیجهٔ خروجی')+' در نمونهٔ مستقل چندنشستی نسبت به گذشته تغییر کرده است؛ موفقیت کد API صحت معنای پاسخ یا قطعیت کسر پول را ثابت نمی‌کند.' if changed else 'در این روش، تغییرِ واجد معیار در نمونهٔ شاهددار مشاهده نشد.' if available else 'خروجیِ کامل و مقایسه‌پذیر برای تمام نمونه فراهم نیست؛ نتیجه نامعلوم است.')
    old=Counter((r.get('result') or {}).get('code') for r in history if r.get('result'))
    scopes={r['result']['scope'] for r in history+current if r.get('result')};new=[r['result']['code'] for r in current if r.get('result')]
    known=len(new)==len(current) and sum(old.values())==len(history) and len(scopes)==1
    bad=sum(c!='G00000' for c in new);past_bad=sum(n for c,n in old.items() if c!='G00000');p=fisher_greater(bad,len(new)-bad,past_bad,len(history)-past_bad) if known else 1.
    failed=[r for r in current if r.get('result') and r['result']['code']!='G00000']
    failure_sessions=len(actors(failed))
    high=bool(known and bad>=5 and failure_sessions>=3 and bad/len(new)>past_bad/len(history)+.2 and p<=.01)
    emit('service_health','CANDIDATE' if high else 'NO_DEVIATION_OBSERVED' if known else 'INSUFFICIENT_DATA',
        'REPORTED_SERVICE_FAILURE_RATE_SHIFT' if high else 'SERVICE_OUTCOME_SAMPLE_INCOMPLETE' if not known else 'SERVICE_OUTCOME_WITHIN_REFERENCE',
        activation_rule_fa='نمونهٔ مستقل و نتیجهٔ صریح هم‌دامنه برای همهٔ درخواست‌ها؛ حداقل ۵ نتیجهٔ ناموفق در حداقل ۳ نشست، افزایش بیش از ۲۰ واحد درصد نسبت به مرجع و مقایسهٔ دقیق جدول با مقدار حداکثر ۰٫۰۱. مرجع خدمت حداقل ۱۰۰ درخواست از ۲۰ نشست و نمونهٔ جاری حداقل ۱۰ درخواست از ۳ نشست دارد.',
        reference_requests=len(history),current_result_requests=len(new),reference_failure_share=past_bad/len(history) if history else None,
        observed_failure_share=bad/len(new) if new else None,reference_cutoff_ns=target,
        observed=bad if known else None,expected=past_bad/len(history)*len(current) if known else None,adjusted_p=p,supporting_failure_sessions=failure_sessions,witness_request_key=failed[0]['request_key'] if failed else None,
        explanation_fa=f'{bad} نتیجهٔ ناموفق هم‌دامنه از {len(current)} درخواستِ نمونه؛ دوره‌های بعدی در همان پروندهٔ سلامت خدمت نگه داشته می‌شوند؛ علت ریشه‌ای و قطعیت مالی اثبات نشده است.' if known else 'نتیجهٔ هم‌دامنه برای تمام اعضای نمونه فراهم نیست؛ ارزیابی خطا نامعلوم است.')
    def share(rows):
        rows=[r for r in rows if r.get('session_key') and r.get('actor_qualified',True)]
        linked=defaultdict(set);actors={r['session_key'] for r in rows}
        for r in rows:
            for channel,key in r.get('targets',{}).items():linked[(channel,key)].add(r['session_key'])
        n=max((len(x) for x in linked.values()),default=0)
        return n/max(1,len(actors)),n,len(actors)
    groups=defaultdict(list)
    for r in history:groups[r['at_ns']//FIVE_NS*FIVE_NS].append(r)
    now_share,now_actors,total_actors=share(current)
    references=[share(rows)[0] for rows in groups.values() if share(rows)[2]>=total_actors and all(r.get('targets') for r in rows)]
    comparable=len(references)>=100 and all(r.get('targets') for r in current)
    rank=(1+sum(x>=now_share for x in references))/(len(references)+1)
    high=bool(comparable and now_actors>=3 and now_share>max(references) and rank<=.01)
    emit('multi_session_target','CANDIDATE' if high else 'NO_DEVIATION_OBSERVED' if comparable else 'INSUFFICIENT_DATA',
        'SHARED_QUERY_TARGET_ACROSS_SESSIONS' if high else 'SHARED_TARGET_REFERENCE_INCOMPLETE' if not comparable else 'SHARED_TARGET_WITHIN_REFERENCE',
        observed=now_actors,expected=median(references)*total_actors if references else None,shared_target_share=now_share,
        upper=max(references)*total_actors if references else None,
        explanation_fa=f'{now_actors} نشست در نمونهٔ مستقل روی همان محتوای موضوع استعلام هم‌پوشانی دارند؛ مرجعِ هم‌دامنه و با حداقل همین تعداد نشست مقایسه شده است. اشتراک هدف، یکسان‌بودن اشخاص یا تبانی قطعی نیست.')
    return out


def traffic(service,target,current,history):
    """Complete logical-request census, two-sided temporal volume and fan-out."""
    from .temporal import Point,fit,predict
    history=[r for r in history if r.get('complete') and r['start_ns']<target]
    out=[]
    def emit(family,status,reason,**kw):
        out.append({'family':family,'entity_type':'service','entity_key':service,'service_path':service,'target_ns':target,
            'begin_ns':target,'end_ns':target+FIVE_NS,'status':status,'reason':reason,
            'evidence_verified':bool(current.get('complete')),'single_signal_review_eligible':status=='CANDIDATE',
            'request_keys':current.get('request_keys',[]),'count_scope':'complete_root_client_request_census',**kw})
    model=fit([Point(r['start_ns'],r['requests'],True,True) for r in history],before_ns=target)
    prediction=predict(model,target);ready=current.get('complete') and prediction.get('status')=='READY'
    # temporal.predict uses READY_BASELINE in released models.
    ready=bool(current.get('complete') and prediction.get('expected') is not None and len(history)>=100)
    n=current['requests'];expected=prediction.get('expected');low=prediction.get('lower');highbound=prediction.get('upper')
    direction='increase' if ready and n>highbound else 'decrease' if ready and n<low else None
    values=[r['requests'] for r in history];rank=(1+sum(x>=n if direction=='increase' else x<=n for x in values))/(len(values)+1)
    high=bool(direction and rank*2<=.02 and abs(n-expected)>=max(3,math.sqrt(expected+1)*3))
    emit('service_volume','CANDIDATE' if high else 'NO_DEVIATION_OBSERVED' if ready else 'INSUFFICIENT_DATA',
        'SERVICE_VOLUME_'+str(direction).upper() if high else 'TEMPORAL_VOLUME_REFERENCE_INCOMPLETE' if not ready else 'VOLUME_WITHIN_TEMPORAL_REFERENCE',
        observed=n,expected=expected,lower=low,upper=highbound,direction=direction,baseline_origin=model.get('family'),
        reference_windows=len(history),reference_cutoff_ns=target,
        activation_rule_fa='پوشش کامل هدف و مدل زمانی معتبر با حداقل ۱۰۰ بازهٔ گذشته؛ عبور از کران پایین یا بالا، رتبهٔ دُم دوطرفه حداکثر ۰٫۰۲ و اختلاف حداقل بزرگ‌ترِ ۳ درخواست یا سه برابر ریشهٔ (مرجع + ۱) لازم است.',
        explanation_fa='حجم درخواست منطقیِ خدمت در هر دو جهت افزایش و کاهش با مرجع زمانی همان خدمت مقایسه شد؛ نبود ترافیک بدون پوشش کامل، صفر فرض نمی‌شود.')
    values=[r['sessions'] for r in history if r.get('sessions_complete',True)];n=current['sessions'];rank=(1+sum(x>=n for x in values))/(len(values)+1)
    covered=bool(current.get('complete') and current.get('sessions_complete',True))
    high=bool(covered and len(values)>=100 and n>max(values) and n>=3 and rank<=.01)
    emit('multi_session_service','CANDIDATE' if high else 'NO_DEVIATION_OBSERVED' if len(values)>=100 and covered else 'INSUFFICIENT_DATA',
        'UNUSUAL_MULTI_SESSION_SERVICE_ACTIVITY' if high else 'MULTI_SESSION_REFERENCE_OR_COVERAGE_INCOMPLETE' if len(values)<100 or not covered else 'MULTI_SESSION_ACTIVITY_WITHIN_REFERENCE',
        observed=n,expected=median(values) if values else None,upper=max(values) if values else None,
        explanation_fa=f'{n} نشست در census درخواست‌های همین خدمت؛ عبور هم‌زمان از سابقهٔ تعداد نشست گزارش شده است. این الگو به‌تنهایی هماهنگی سازمان‌یافته یا یکسان‌بودن اشخاص را ثابت نمی‌کند.')
    return out
