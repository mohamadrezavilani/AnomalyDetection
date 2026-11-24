"""Bounded, typed, multi-day input comparisons over authoritative Sessions.

Sets retain the smallest hashes, not an additive daily distinct count. When a
set fills, its size is a lower bound; it is never used as an exact peer value.
There is no identity inference from IP and no raw input value in this layer.
"""
import json
import statistics
import zlib
import time
from collections import defaultdict

from compact_behavior import FEATURES, FIVE, inquiry
from compact_behavior.extract import digest
from .engine import upper

VERSION = "compact-long-input-2"
METHOD = "long_target_enumeration"
DAY = 288 * FIVE
OFFSET = 210 * 60 * 10**9  # Tehran; event dates supported by this product.
SPANS = (3, 7, 30)
TARGET_CAP = 256
ACTOR_CAP = 50000
ENTRY_CAP = 250000
BYTE_CAP = 32 * 1024 * 1024


class CapacityExceeded(Exception):
    pass


def day_start(at):
    return ((at + OFFSET) // DAY) * DAY - OFFSET


def pack(value):
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    if len(raw) > BYTE_CAP:
        raise CapacityExceeded("longitudinal_payload_budget")
    return zlib.compress(raw, 3)


def unpack(blob):
    decoder = zlib.decompressobj()
    raw = decoder.decompress(bytes(blob), BYTE_CAP + 1)
    if len(raw) > BYTE_CAP or not decoder.eof or decoder.unused_data:
        raise CapacityExceeded("longitudinal_payload_budget")
    return json.loads(raw)


def projection(summary, actors):
    """Reuse the already-read window; no source or database lookups."""
    services = defaultdict(dict)
    for (session, service), a in actors.items():
        if service not in inquiry.ROUTES:
            continue
        fields = {}
        for path, field in a.get("target_fields", {}).items():
            tokens = sorted(field["tokens"])
            fields[path] = dict(tokens=tokens[:TARGET_CAP],
                                overflow=len(tokens) > TARGET_CAP,
                                covered=field["covered"])
        services[service][session] = dict(
            count=a["count"], fields=fields, days=1,
            invalid=bool(a["input_invalid"] or a.get('sequence_incomplete') or summary["content_resource_invalid"]),
            evidence=list(a["witnesses"])[:6],
        )
    return dict(services)


def merge(chunks, *, active_days=False):
    """Merge window chunks into a day, or day chunks into a span.

    Budgets are fail-closed for this service/cohort, never partial-normal. The
    caller streams one service at a time, so memory does not grow with history.
    """
    actors = {}
    entries = 0
    began=time.monotonic()
    visited=0
    for chunk in chunks:
        if '@capacity_limit' in chunk:
            raise CapacityExceeded('longitudinal_window_payload_budget')
        for session, row in chunk.items():
            visited+=1
            if visited % 1024 == 0 and time.monotonic()-began > 5:
                raise CapacityExceeded('longitudinal_merge_time_budget')
            a = actors.setdefault(session, dict(count=0, fields={}, days=0,
                                                 invalid=False, evidence=[]))
            if len(actors) > ACTOR_CAP:
                raise CapacityExceeded("longitudinal_actor_budget")
            a["count"] += row["count"]
            a["days"] = a["days"] + 1 if active_days else 1
            a["invalid"] |= row["invalid"]
            # Keep evidence from both the beginning and end of the span.
            evidence = list(dict.fromkeys(a["evidence"] + row["evidence"]))
            a["evidence"] = evidence if len(evidence) <= 12 else evidence[:6] + evidence[-6:]
            for path, field in row["fields"].items():
                dest = a["fields"].setdefault(path, dict(tokens=set(), overflow=False, covered=0))
                previous = len(dest["tokens"])
                union = dest["tokens"] | set(field["tokens"])
                dest["overflow"] |= field["overflow"] or len(union) > TARGET_CAP
                dest["tokens"] = set(sorted(union)[:TARGET_CAP])
                dest["covered"] += field["covered"]
                entries += len(dest["tokens"]) - previous
                if entries > ENTRY_CAP:
                    raise CapacityExceeded("longitudinal_target_budget")
    for a in actors.values():
        for f in a["fields"].values():
            f["tokens"] = sorted(f["tokens"])
    return actors


EVALUATION_POLICY = 'indexed-peer-distribution-1'


class ComparisonPending(Exception):
    def __init__(self, resume_index, results, diagnostics):
        self.resume_index, self.results, self.diagnostics = resume_index, results, diagnostics


def weighted_median(histogram):
    n=sum(histogram.values())
    positions=((n-1)//2,n//2)
    found=[];seen=0
    for value,count in sorted(histogram.items()):
        if count<=0:continue
        for position in positions[len(found):]:
            if seen<=position<seen+count:found.append(value)
            else:break
        seen+=count
        if len(found)==2:break
    return found[0] if n%2 else (found[0]+found[1])/2


def evaluate(actors, *, service, end, span, signature, diagnostics=None, resume_index=0, budget_seconds=5):
    """Indexed volume ranges and cached weighted leave-one-out distributions.

    The distribution is identical to the former expanded peer list. No peer
    identity list is rebuilt for each actor. A soft deadline yields a fenced
    actor cursor; publication waits until the whole comparison finishes.
    """
    from bisect import bisect_left, bisect_right
    from collections import Counter
    from functools import lru_cache
    import math
    results=[]
    diagnostics=diagnostics if diagnostics is not None else {}
    diagnostics.update(eligible_comparisons=0,insufficient_peer_comparisons=0,censored_peer_comparisons=0)
    began=time.monotonic()
    indexes=defaultdict(lambda:defaultdict(list))
    censored=defaultdict(list)
    for (session,a) in actors.items():
        if a['invalid']:continue
        for path,field in a['fields'].items():
            if field['covered']==a['count']:
                indexes[(path,a['days'])][len(field['tokens'])].append(a['count'])
                if field['overflow']:censored[(path,a['days'])].append(a['count'])
    for widths in indexes.values():
        for counts in widths.values():counts.sort()
    for counts in censored.values():counts.sort()
    comparisons=max(1,len({path for path,_ in indexes}))*len(SPANS)

    @lru_cache(maxsize=256)
    def matched(path,days,count):
        hist=Counter();limited=0
        for active in range(max(1,days-1),days+2):
            for width,counts in indexes.get((path,active),{}).items():
                n=bisect_right(counts,count*2)-bisect_left(counts,count/2)
                if n:hist[width]+=n
            values=censored.get((path,active),())
            limited+=bisect_right(values,count*2)-bisect_left(values,count/2)
        return hist,limited

    @lru_cache(maxsize=32)
    def population(path,days):
        hist=Counter();limited=0
        for (candidate,active),widths in indexes.items():
            if candidate==path:
                for width,counts in widths.items():hist[width*days/active]+=len(counts)
                limited+=len(censored.get((candidate,active),()))
        return hist,limited

    @lru_cache(maxsize=512)
    def distribution(path,days,count,width,overflow):
        hist,limited=matched(path,days,count)
        basis='VOLUME_AND_ACTIVITY_MATCHED'
        if sum(hist.values())-1<100:
            hist,limited=population(path,days)
            basis='SERVICE_POPULATION_ACTIVE_DAY_SCALED'
        hist=hist.copy();hist[width]-=1
        if hist[width]==0:del hist[width]
        limited-=int(overflow)
        n=sum(hist.values())
        if limited:return None,'censored'
        if n<100:return None,'insufficient'
        median=weighted_median(hist)
        deviations=Counter()
        for value,number in hist.items():deviations[abs(value-median)]+=number
        mad=weighted_median(deviations)
        maximum=max(hist)
        limit=max(20,5,median*3,median+6*1.4826*mad+4*math.sqrt(max(1,median)),maximum+1)
        values=sorted(hist);prefix=[0]
        for value in values:prefix.append(prefix[-1]+hist[value])
        return (n,median,maximum,limit,values,prefix,basis),None

    ordered=sorted(actors.items())
    for number,(session,a) in enumerate(ordered):
        if number<resume_index:continue
        if number>resume_index and number%100==0 and time.monotonic()-began>budget_seconds:
            raise ComparisonPending(number,results,dict(diagnostics))
        if a['invalid'] or a['days']<(3 if span<=7 else 7):continue
        for path,field in sorted(a['fields'].items()):
            if field['covered']!=a['count']:continue
            observed=len(field['tokens'])+int(field['overflow'])
            if observed<=20:continue
            stats,missing=distribution(path,a['days'],a['count'],len(field['tokens']),field['overflow'])
            if missing:
                diagnostics['censored_peer_comparisons' if missing=='censored' else 'insufficient_peer_comparisons']+=1
                continue
            diagnostics['eligible_comparisons']+=1
            n,median,maximum,limit,values,prefix,basis=stats
            tail=n-prefix[bisect_left(values,observed)]
            rank=min(1,comparisons*(1+tail)/(1+n))
            if observed<=limit or rank>.05:continue
            candidate=dict(method=METHOD,service=service,session_id=session,status='ANOMALY',
                observed=observed,observed_is_lower_bound=field['overflow'],baseline=median,threshold=limit,
                peer_count=n,peer_max=maximum,adjusted_tail_rank=rank,peer_basis=basis,
                comparisons=comparisons,active_days=a['days'],requests=a['count'],numeric_path=path,
                horizon_days=span,period_start_ns=end-span*DAY,period_end_ns=end,reference_windows=span*288,
                reference_cutoff_ns=end,reference_signature=signature,
                reference_policy='SAME_COMPLETED_PERIOD_TYPED_FIELD_VOLUME_ACTIVITY_PEERS',
                model_version=VERSION,feature_version=FEATURES,window_start_ns=end-FIVE,window_end_ns=end,
                evidence=a['evidence'],single_signal_review_eligible=True,reason='QUALIFIED_MULTI_DAY_TARGET_ENUMERATION',
                next_action='تنوع شناسه‌ها و درخواست‌های شاهد را بررسی کنید؛ رتبهٔ آماری احتمال تخلف نیست.')
            if len(set(candidate['evidence']))>=3:results.append(candidate)
    return results
