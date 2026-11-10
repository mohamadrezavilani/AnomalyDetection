"""Past-only interpretable detectors and a small isolation forest; no ML install."""
from __future__ import annotations
from collections import Counter,deque
import math
import random
from statistics import median,pstdev

from . import FIVE_NS
from .snapshot import digest,api_path
from .temporal import Point,fit,predict,phase,quantile


def valid(row):
    first=row.get('first_observed_ns')
    return bool(row.get('coverage_complete') and row.get('population_complete',True) and row.get('counts') is not None and
        (first is None or row['start_ns']>=first//FIVE_NS*FIVE_NS))


def distribution(counts):
    total=sum(counts.values())
    return {key:value/total for key,value in counts.items()} if total else {}


def distance(left,right):return sum(abs(left.get(key,0)-right.get(key,0)) for key in left.keys()|right.keys())/2
def rank(value,values):return (1+sum(other>=value for other in values))/(len(values)+1)


def _expected_path(n):
    if n<=1:return 0.
    if n==2:return 1.
    return 2*(math.log(n-1)+0.5772156649015329)-2*(n-1)/n


class SmallIsolationForest:
    """Bounded reference isolation-tree implementation, deterministic and serializable."""
    def __init__(self,trees=32,sample=128,seed=17):self.count=trees;self.sample=sample;self.seed=seed;self.trees=[]
    def fit(self,rows):
        rng=random.Random(self.seed);size=min(self.sample,len(rows));depth=math.ceil(math.log2(max(2,size)))
        def grow(values,level):
            if len(values)<=1 or level>=depth:return {'n':len(values)}
            features=[i for i in range(len(values[0])) if min(row[i] for row in values)<max(row[i] for row in values)]
            if not features:return {'n':len(values)}
            feature=rng.choice(features);lo=min(row[feature] for row in values);hi=max(row[feature] for row in values)
            split=rng.uniform(lo,hi);left=[row for row in values if row[feature]<split];right=[row for row in values if row[feature]>=split]
            if not left or not right:return {'n':len(values)}
            return {'f':feature,'v':split,'l':grow(left,level+1),'r':grow(right,level+1)}
        self.size=size;self.trees=[grow(rng.sample(rows,size),0) for _ in range(self.count)];return self
    def score(self,row):
        def length(node,level):
            if 'n' in node:return level+_expected_path(node['n'])
            return length(node['l'] if row[node['f']]<node['v'] else node['r'],level+1)
        denominator=_expected_path(self.size)
        return 2**(-(sum(length(tree,0) for tree in self.trees)/len(self.trees))/denominator) if denominator else .5


def count_vector(counts):
    values=[value for value in counts.values() if value>0];total=sum(values);p=distribution(counts)
    return [math.log1p(total),math.log1p(len(values)),max(p.values(),default=0),-sum(value*math.log(value) for value in p.values() if value>0)]


def evaluate(context,history,details=(), *, peer_provider=None):
    target=context['target_ns'];session=context['session_key'];decisions=[]
    current=next((row for row in context['windows'] if row['start_ns']==target),{'start_ns':target,'counts':None})
    previous=sorted([row for row in history if row['start_ns']<target],key=lambda row:row['start_ns'])
    eligible=[row for row in previous if valid(row)]
    ready=bool(context.get('target_complete') and current.get('counts') is not None)
    counts=current.get('counts') or {}
    def emit(family,dimension,status,reason,service='*',**values):
        result={'finding_key':'pf1:'+digest([session,target,family,service]),'session_key':session,'target_ns':target,
            'family':family,'dimension':dimension,'service_path':service,'status':status,'reason':reason,
            'operator_alert':False,'precision_recall':'NOT_EVALUATED','score_interpretation':'statistical_deviation_not_fraud_probability',**values}
        decisions.append(result);return result
    def cold(family,dimension,reason):return emit(family,dimension,'INSUFFICIENT_DATA',reason,
        explanation_fa='سابقه یا پوشش معتبر برای این مقایسه کافی نیست؛ عادی بودن رفتار نتیجه نمی‌شود.')
    if current.get('unmapped_behaviors') and not counts:ready=False
    if not ready:
        for family,dimension in [('rate_5m','activity'),('rate_60m','activity'),('service_mix','activity'),('isolation_forest','activity'),
            ('service_sequence','sequence_statistics'),('timing_regularization','timing'),('business_result_change','context')]:cold(family,dimension,'TARGET_COVERAGE_UNKNOWN')
        return decisions
    if not sum(counts.values()):
        for family,dimension in [('rate_5m','activity'),('rate_60m','activity'),('service_mix','activity'),('isolation_forest','activity'),
            ('service_sequence','sequence_statistics'),('timing_regularization','timing'),('business_result_change','context')]:
            emit(family,dimension,'NO_DEVIATION_OBSERVED','NO_MAPPED_SERVICE_EXECUTIONS_IN_COMPLETE_TARGET',explanation_fa='در دامنهٔ مسیرهای حل‌شدهٔ فعلی، اجرای فعالی باقی نمانده است.')
        return decisions
    by_time={row['start_ns']:row for row in previous+[current]}
    # 5-minute and rolling-hour rates share one activity dimension, never two votes.
    for service in sorted(counts):
        expected_kind=current.get('count_kinds',{}).get(service)
        def matching_kind(row):
            kind=row.get('count_kinds',{}).get(service)
            return (not expected_kind or kind==expected_kind or
                kind is None and (expected_kind=='service_execution' or row.get('count_scope')=='RESOLVED_SERVICE_PATHS'))
        for size,label in ((1,'5m'),(12,'60m')):
            points=[];observed=None
            for at in sorted(by_time):
                if at>target:continue
                rows=[by_time.get(at-step*FIVE_NS) for step in range(size)]
                covered=all(row is not None and matching_kind(row) and (valid(row) if at<target else row.get('coverage_complete') and row.get('counts') is not None) for row in rows)
                value=sum(row['counts'].get(service,0) for row in rows) if covered else None
                if at==target:observed=value
                else:points.append(Point(at,value,covered,covered))
            if observed is None:
                emit('rate_'+label,'activity','INSUFFICIENT_DATA','ROLLING_SCOPE_HAS_GAPS',service,
                    explanation_fa='پوشش بازهٔ تجمیعی کامل نیست؛ شکاف به صفر تبدیل نشده است.');continue
            model=fit(points,before_ns=target)
            # Overlapping rolling-hour points from one burst are one source of
            # positive history, not twelve independent prior observations.
            positives=0;last_positive=None
            for point in points:
                if point.value is not None and point.value>0 and (last_positive is None or point.at_ns-last_positive>=size*FIVE_NS):
                    positives+=1;last_positive=point.at_ns
            peer=peer_provider(service,target) if size==1 and peer_provider else None
            personal_ready=model['status']=='READY_BASELINE' and positives>=5
            origin='personal_session'
            if not personal_ready and peer and peer.get('status')=='READY_BASELINE':model=peer;origin='active_session_peers'
            elif not personal_ready:
                emit('rate_'+label,'activity','INSUFFICIENT_DATA',model.get('reason','INSUFFICIENT_INDEPENDENT_POSITIVE_HISTORY'),service,
                    observed=observed,history_windows=model.get('observations',0),personal_history_windows=model.get('observations',0),
                    positive_history_windows=positives,peer_windows=(peer or {}).get('population_windows'),
                    peer_qualified_windows=(peer or {}).get('qualified_population_windows'),
                    explanation_fa='سابقهٔ معتبر این خدمت برای مقایسه کافی نیست.');continue
            forecast=predict(model,target);upper=max(1,forecast['upper'],forecast['expected']);high=observed>=3*upper
            peer_explains=False
            if size==1 and peer_provider and origin=='personal_session':
                if peer and peer.get('status')=='READY_BASELINE':
                    reference=predict(peer,target)
                    peer_explains=observed<3*max(1,reference['upper'],reference['expected'])
            record=emit('rate_'+label,'activity','CANDIDATE' if high else 'NO_DEVIATION_OBSERVED',
                'RELATIVE_INCREASE' if high else 'LEARNED_RANGE_NOT_EXCEEDED',service,observed=observed,expected=forecast['expected'],
                upper=upper,score=math.log2((observed+1)/(forecast['expected']+1)),model=model,
                independent_positive_history=positives,history_interval_ns=size*FIVE_NS,
                baseline_origin=origin,
                peer_activity_can_explain=peer_explains,
                witness_request_key=current.get('witnesses',{}).get(service),
                explanation_fa=f'{observed} اجرای {service} در بازهٔ {5*size} دقیقه‌ای؛ انتظار آموخته‌شده {forecast["expected"]:.2f} و کران {upper:.2f} است.')
    volume=sum(counts.values())
    comparable=[row for row in eligible if volume/2<=sum(row['counts'].values())<=2*volume and sum(row['counts'].values())>0][-2048:]
    if volume<20 or len(comparable)<80:
        cold('service_mix','activity','INSUFFICIENT_COMPARABLE_VOLUME_HISTORY')
    else:
        split=max(30,len(comparable)*3//4);training,validation=comparable[:split],comparable[split:]
        def reference(rows):
            total=Counter()
            for row in rows:total.update(row['counts'])
            return distribution(total)
        base=reference(training);family='rolling';selected=training
        errors=[distance(distribution(row['counts']),base) for row in validation]
        best=sum(errors)/len(errors)
        for period in ('hourly','daily','weekly'):
            buckets={}
            for row in training:buckets.setdefault(phase(row['start_ns'],period),[]).append(row)
            if any(len(buckets.get(phase(row['start_ns'],period),[]))<3 for row in validation):continue
            candidate=[distance(distribution(row['counts']),reference(buckets[phase(row['start_ns'],period)])) for row in validation]
            error=sum(candidate)/len(candidate)
            selected_rows=[row for row in comparable if phase(row['start_ns'],period)==phase(target,period)]
            if len(selected_rows)>=30 and error<best*.75:family=period;best=error;selected=selected_rows;errors=candidate
        baseline=reference(selected);observed=distance(distribution(counts),baseline)
        cutoff=max(.25,quantile(errors,.99));high=observed>cutoff and rank(observed,errors)<=.05
        model={'model_id':'pm1:'+digest([target,[[row['start_ns'],row['counts']] for row in selected],family]),
            'version':'automatic-mix-1','family':family,'cutoff_ns':target,'reference_distribution':baseline,
            'validation_errors':errors,'calibration':'temporal_holdout_not_fraud_probability'}
        emit('service_mix','activity','CANDIDATE' if high else 'NO_DEVIATION_OBSERVED','MIX_DISTANCE' if high else 'MIX_WITHIN_LEARNED_RANGE',
            score=observed,upper=cutoff,model=model,observed_distribution=distribution(counts),
            explanation_fa=f'فاصلهٔ ترکیب خدمات از الگوی {family} با حجم مشابه {observed:.3f} و کران آموخته‌شده {cutoff:.3f} است.')
    active=[row for row in eligible if sum(row['counts'].values())>0][-512:]
    if len(active)<100:
        cold('isolation_forest','activity','INSUFFICIENT_MULTIVARIATE_HISTORY')
    else:
        vectors=[count_vector(row['counts']) for row in active];cut=len(vectors)*3//4
        forest=SmallIsolationForest().fit(vectors[:cut]);calibration=[forest.score(row) for row in vectors[cut:]]
        observed=forest.score(count_vector(counts));upper=max(.65,max(calibration)+.02)
        high=observed>upper and rank(observed,calibration)<=.05
        model={'model_id':'pi1:'+digest([vectors[:cut],target]),'version':'isolation-forest-1','family':'isolation_forest',
            'cutoff_ns':target,'sample_size':forest.size,'trees':forest.trees,'calibration_scores':calibration}
        emit('isolation_forest','activity','CANDIDATE' if high else 'NO_DEVIATION_OBSERVED','MULTIVARIATE_ISOLATION' if high else 'MULTIVARIATE_WITHIN_RANGE',
            score=observed,upper=upper,model=model,
            explanation_fa=f'امتیاز دورافتادگی چندمتغیره {observed:.3f} و کران حاصل از بخش ارزیابیِ گذشته {upper:.3f} است؛ این سیگنال از بُعد فعالیت است.')
    events=[event for event in context.get('events',[]) if event['anchor_ns']<target+FIVE_NS and api_path(event.get('root_call')) and
        event.get('identity_state')=='assigned' and not event.get('conflicted',True) and event.get('request_session_key')==session]
    past=[event for event in events if event['anchor_ns']<target];current_events=[event for event in events if event['anchor_ns']>=target]
    sequence=[event['root_call'].split(' Line:')[0].strip() for event in past]
    current_sequence=[event['root_call'].split(' Line:')[0].strip() for event in current_events]
    history_start=min((e['anchor_ns']//FIVE_NS*FIVE_NS for e in events),default=target)
    ordered_coverage=all(at in by_time and by_time[at].get('coverage_complete') and by_time[at].get('population_complete',True)
        for at in range(history_start,target+FIVE_NS,FIVE_NS))
    unique_times=len({e['anchor_ns'] for e in events})==len(events)
    if len(sequence)<300 or len(current_sequence)<10 or not context.get('target_events_complete') or not ordered_coverage:
        cold('service_sequence','sequence_statistics','INSUFFICIENT_ORDERED_HISTORY')
    else:
        split=len(sequence)*2//3;training=sequence[:split];validation=sequence[split:]
        singles=Counter(training);pairs=Counter(zip(training,training[1:]));vocabulary=len(singles)+1
        def surprise(values,order,predecessor=None):
            result=[]
            for value in values:
                probability=((pairs[(predecessor,value)]+1)/(singles[predecessor]+vocabulary) if order and predecessor is not None and singles[predecessor]>=10 else
                    (singles[value]+1)/(len(training)+vocabulary))
                result.append(-math.log(probability));predecessor=value
            return sum(result)/max(1,len(result))
        unigram=surprise(validation,0);bigram=surprise(validation,1,training[-1]);order=int(unique_times and bigram<unigram*.75)
        blocks=[validation[i:i+10] for i in range(0,len(validation)-9,10)]
        calibration=[surprise(block,order,validation[i*10-1] if i else training[-1]) for i,block in enumerate(blocks)]
        observed=surprise(current_sequence,order,sequence[-1]);upper=max(calibration) if calibration else float('inf')
        high=len(calibration)>=30 and observed>upper and rank(observed,calibration)<=.05
        emit('service_sequence','sequence_statistics','INSUFFICIENT_DATA' if len(calibration)<30 else 'CANDIDATE' if high else 'NO_DEVIATION_OBSERVED',
            'INSUFFICIENT_ORDER_VALIDATION' if len(calibration)<30 else 'ORDER_SURPRISE' if high else 'ORDER_WITHIN_RANGE',
            score=observed,upper=upper,model={'model_id':'ps1:'+digest([training,target,order]),'version':'adaptive-order-1',
                'family':'first_order' if order else 'unigram','cutoff_ns':target,'validation_scores':calibration},
            explanation_fa=f'ترتیب خدمات با مدل انتخاب‌شدهٔ مرتبهٔ {order} مقایسه شد؛ امتیاز {observed:.3f} است. مرز پنجره، توالی را قطع نمی‌کند.')
    past_times=[event['anchor_ns']/1e9 for event in past];current_times=[event['anchor_ns']/1e9 for event in current_events]
    gaps=[right-left for left,right in zip(past_times,past_times[1:]) if right>left]
    recent=[right-left for left,right in zip(current_times,current_times[1:]) if right>left]
    chunks=[gaps[i:i+20] for i in range(0,len(gaps)-19,20)]
    if len(recent)<20 or len(chunks)<30 or not context.get('target_events_complete') or not ordered_coverage:
        cold('timing_regularization','timing','INSUFFICIENT_INTERARRIVAL_HISTORY')
    else:
        cvs=[pstdev(chunk)/max(1e-12,sum(chunk)/len(chunk)) for chunk in chunks]
        cv=pstdev(recent)/max(1e-12,sum(recent)/len(recent));baseline=quantile(cvs,.05)
        high=cv<baseline*.25 and median(recent)<median(gaps)/3
        emit('timing_regularization','timing','CANDIDATE' if high else 'NO_DEVIATION_OBSERVED',
            'FASTER_AND_MORE_REGULAR' if high else 'TIMING_WITHIN_RANGE',score=1/(1+cv),observed_cv=cv,historical_lower_cv=baseline,
            explanation_fa=f'ضریب تغییر فاصلهٔ اجراها {cv:.3f} است؛ فقط منظم‌تر و هم‌زمان سریع‌تر شدن نسبت به سابقه، نامزد بررسی می‌شود؛ اثبات ربات نیست.')
    # Business result is source-qualified context, never HTTP/provider financial success.
    records=[]
    for record in details:
        fact=record.get('details') or {}
        quality=fact.get('quality',{})
        if not (fact.get('source_present') and quality.get('evidence_available') and not quality.get('conflicted')):continue
        values={observation['value'] for observation in fact.get('observations',[]) if observation.get('qualified') and observation.get('axis')=='service_dispatch.inquiry_result'
                and (record['at_ns']>=target or type(observation.get('at_ns')) is int and observation['at_ns']<target)}
        if len(values)==1:records.append((record['at_ns'],record['service_path'],next(iter(values))))
    before=[row for row in records if row[0]<target];now=[row for row in records if target<=row[0]<target+FIVE_NS]
    if len(before)<100 or len(now)<20:
        cold('business_result_change','context','INSUFFICIENT_QUALIFIED_BUSINESS_RESULTS')
    else:
        from .categorical import shift
        services=sorted({service for _,service,_ in now});contrasts=[]
        for service in services:
            old=[code for _,s,code in before if s==service];new=[code for _,s,code in now if s==service]
            if len(old)>=100 and len(new)>=20:
                contrasts.append(shift(old,new,comparisons=len(services))|{'service_path':service})
        high=any(c['high'] for c in contrasts)
        complete=len(contrasts)==len(services)
        emit('business_result_change','context','CANDIDATE' if high else 'NO_DEVIATION_OBSERVED' if complete else 'INSUFFICIENT_DATA',
            'BUSINESS_RESULT_DISTRIBUTION_CHANGE' if high else 'BUSINESS_RESULTS_WITHIN_REFERENCE' if complete else 'INSUFFICIENT_SAME_SERVICE_BUSINESS_RESULTS',
            score=max((c['score'] for c in contrasts),default=0),category_contrasts=contrasts,
            method_version='qualified-business-distribution-2',calibration_status='DESCRIPTIVE_SCREEN_NOT_PRODUCTION_ERROR_RATE_GUARANTEE',
            service_context='UNKNOWN_NOT_A_CUSTOMER_FRAUD_SIGNAL',
            explanation_fa='فراوانی کدهای نتیجهٔ تجاری با سابقهٔ همان خدمت و آزمون دقیق تعدیل‌شده مقایسه شد؛ کد قبلاً مشاهده‌شده نیز می‌تواند تغییر کند. علت عمومی خدمت هنوز نامعلوم است.')
    return decisions
