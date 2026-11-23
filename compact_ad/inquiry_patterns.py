"""Five-minute inquiry patterns over fully observed logical requests."""
from bisect import bisect_left
import math
from statistics import median
from compact_behavior import FIVE
from .seasonality import HORIZON, phase

POLICY = 'verified-inquiry-burst-1'


def reference_context(start, key, counts, temporal):
    hour = phase(start, 'daily')
    previous = []
    for row in temporal:
        at = row['start_ns']
        if (start-HORIZON*FIVE <= at < start and (start-at) % (12*FIVE) == 0
                and phase(at, 'daily') == hour and row['complete']):
            values = row['rates'].get(key)
            if values and values[2] and values[0] > 0:
                previous.append(values[1])
    return sorted(counts), sum(counts), previous


def qualify(result, *, requests, distinct, peak, successes, context, target_history_ready):
    """Require a directly measured pattern. Context can veto a routine volume."""
    repetition = result['method'] == 'repeated_target'
    if repetition:
        if requests < 30 or peak < 10 or (requests-distinct)*4 < requests*3:
            return
    elif distinct < 12 or distinct*5 < requests*4:
        return
    if successes != requests:
        return
    if target_history_ready and result['observed'] <= result['threshold']:
        return
    counts, total, previous = context
    peers = len(counts)-1
    peer_p95 = None
    if peers:
        position = math.ceil(.95*peers)-1
        # Exclude one observation belonging to this session.
        peer_p95 = counts[position + (bisect_left(counts, requests) <= position)]
    same_hour = median(previous) if previous else None
    if (peers >= 20 and requests <= 2*peer_p95
            or len(previous) >= 6 and requests <= 2*same_hour):
        return
    result.update(status='ANOMALY', single_signal_review_eligible=True, inquiry_pattern_policy=POLICY,
        reason='CONCENTRATED_SUCCESSFUL_INQUIRIES' if repetition else 'BROAD_SUCCESSFUL_INQUIRIES',
        requests=requests, covered_requests=requests, distinct_targets=distinct,
        most_frequent_count=peak, repeated_requests=requests-distinct, successful_requests=successes,
        peer_count=peers, peer_mean_requests=(total-requests)/peers if peers else None,
        peer_p95_requests=peer_p95, same_hour_windows=len(previous), same_hour_actor_p95_median=same_hour)
