"""Bounded refusal cohorts in the existing five-minute input pass."""
from collections import Counter
import statistics
from compact_behavior import FEATURES
from compact_behavior import security as evidence

POLICY = evidence.POLICY
METHODS = {'access_denied': 'access_denied_attempts', 'invalid_session': 'invalid_session_attempts'}
MAX_COHORTS = 512


class Aggregates:
    def __init__(self, cutoff_ns, max_cohorts=MAX_COHORTS):
        self.groups = {}
        self.cutoff_ns = cutoff_ns
        self.max_cohorts = max_cohorts
        self.complete = True
        self.missing_context = Counter()

    def observe(self, row):
        f = row['features']
        attempt = f.get(evidence.FIELD) or {}
        if (f.get('version') != FEATURES or attempt.get('policy') != POLICY
                or attempt.get('kind') not in METHODS or attempt.get('result_code') != row.get('result_code')
                or attempt.get('at_ns') != row.get('observed_at_ns')
                or self.cutoff_ns is not None and attempt['at_ns'] >= self.cutoff_ns):
            return False
        kind = attempt['kind']
        cohort = attempt.get('cohort_key')
        if not cohort:
            self.missing_context[kind] += 1
            return True
        # Invalid tokens across endpoints are one network cohort; never sessions.
        scope = attempt['scope'] if kind == 'access_denied' else '*'
        key = (kind, scope, cohort)
        group = self.groups.get(key)
        if group is None:
            if len(self.groups) >= self.max_cohorts:
                self.complete = False
                return True
            group = self.groups[key] = dict(count=0, tokens=set(), endpoints=set(), witnesses=[],
                                           first_ns=attempt['at_ns'], last_ns=attempt['at_ns'])
        group['count'] += 1
        if attempt.get('token_fingerprint'):
            group['tokens'].add(attempt['token_fingerprint'])
        group['endpoints'].add(attempt['api'])
        group['first_ns'] = min(group['first_ns'], attempt['at_ns'])
        group['last_ns'] = max(group['last_ns'], attempt['at_ns'])
        if len(group['witnesses']) < 12:
            group['witnesses'].append(row['behavior_id'])
        return True

    def summary(self):
        return dict(policy=POLICY, complete=self.complete, missing_context=dict(self.missing_context),
                    cohorts=[dict(kind=k, scope=s, key=c, count=g['count'],
                                  distinct_tokens=len(g['tokens']), first_ns=g['first_ns'], last_ns=g['last_ns'],
                                  endpoints=sorted(g['endpoints']), witnesses=g['witnesses'])
                             for (k, s, c), g in sorted(self.groups.items())])


def evaluate(summary, refs, add):
    from .engine import upper
    # Index retained counts once; never scan all references for each cohort.
    indexed = []
    for ref in refs:
        historical = ref['summary'].get('security', {})
        if historical.get('policy') == POLICY and historical.get('complete') is True:
            indexed.append((ref, historical, {(g['kind'], g['scope'], g['key']): g['count']
                                            for g in historical['cohorts']}))
    present = set()
    for group in summary['cohorts']:
        kind, scope, cohort = (group[k] for k in ('kind', 'scope', 'key'))
        method = METHODS[kind]
        present.add(method)
        floor = 20 if kind == 'access_denied' else 30 if group['distinct_tokens'] >= 5 else 100
        usable = [(r, counts.get((kind, scope, cohort), 0)) for r, s, counts in indexed
                  if not s['missing_context'].get(kind)]
        history = [v for _, v in usable]
        threshold = max(floor, upper(history, floor=floor)) if len(history) >= 12 else floor
        span = (group['last_ns'] - group['first_ns']) / 1e9
        eligible = (summary['complete'] and group['count'] >= threshold and span >= 30
                    and len(set(group['witnesses'])) >= 3)
        result = add(method, scope, cohort if kind == 'access_denied' else None,
                     'INVALID_INPUT' if not summary['complete'] else 'ANOMALY' if eligible else 'NORMAL',
                     group['count'], statistics.median(history) if history else None,
                     threshold, group['witnesses'],
                     reason='REPEATED_VERIFIED_ACCESS_DENIALS' if kind == 'access_denied' else 'REPEATED_INVALID_SESSIONS_FROM_IP',
                     path=('ip:' + cohort) if kind == 'invalid_session' else None,
                     used=[r for r, _ in usable])
        result.update(security_policy=POLICY, single_signal_review_eligible=eligible,
                      documentation=evidence.DOCUMENTS,
                      entity_type='session' if kind == 'access_denied' else 'ip',
                      entity_key=cohort, distinct_presented_tokens=group['distinct_tokens'],
                      endpoints=sorted(group['endpoints']), span_seconds=span,
                      threshold_basis='PAST_SAME_COHORT' if len(history) >= 12 else 'INITIAL_ENGINEERING_FLOOR',
                      next_action=('مجوز نشست، مقصد درخواستی و تکرارهای برنامه را بررسی کنید.' if kind == 'access_denied'
                                   else 'IP را در درخواست‌های شاهد بررسی کنید؛ نشست منقضی، خطای برنامه و IP مشترک را از تلاش برای حدس توکن تفکیک کنید.'))
    for kind, count in summary['missing_context'].items():
        present.add(METHODS[kind])
        add(METHODS[kind], '*', None, 'INVALID_INPUT', count, reason='REFUSAL_COHORT_CONTEXT_UNAVAILABLE', used=[])
    for method in set(METHODS.values()) - present:
        add(method, '*', None, 'INSUFFICIENT_DATA' if summary['complete'] else 'INVALID_INPUT',
            reason='NO_VERIFIED_REFUSALS' if summary['complete'] else 'SECURITY_COHORT_RESOURCE_LIMIT', used=[])
