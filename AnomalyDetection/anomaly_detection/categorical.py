"""Past/current categorical enrichment, rather than novelty-only detection.

Uses the existing exact-table screen and explicit multiplicity. This is a
descriptive statistical screen; session clustering and production false-alarm
calibration still require independent labelled/temporal evaluation.
"""
from collections import Counter
from .scenario_models import fisher_greater


def shift(past, current, *, comparisons=1):
    before, now = Counter(past), Counter(current)
    n, m = sum(now.values()), sum(before.values())
    categories = before.keys() | now.keys()
    multiplicity = max(1, comparisons) * max(1, len(categories))
    changes = []
    largest = 0.
    for value in categories:
        a, c = now[value], before[value]
        if not n or not m or a/n <= c/m:
            continue
        effect = a/n-c/m
        largest = max(largest, effect)
        probability = min(1., fisher_greater(a,n-a,c,m-c)*multiplicity)
        if probability <= .01:
            # Category values may contain private identifiers. Persist counts,
            # effects and probabilities only; the source witness provides detail.
            changes.append({'current_count':a,'current_total':n,'reference_count':c,
                            'reference_total':m,'share_increase':effect,
                            'comparison_count':multiplicity,'adjusted_p':probability})
    changes.sort(key=lambda x:(x['adjusted_p'],-x['share_increase']))
    return {'high':bool(changes),'score':largest,'changed_categories':changes,
            'test_policy':'categorical_enrichment_fisher_bonferroni_0.01',
            'calibration_status':'DESCRIPTIVE_SCREEN_NOT_PRODUCTION_ERROR_RATE_GUARANTEE'}
