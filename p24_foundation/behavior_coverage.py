"""LC2C read-only, full-index *request classification* coverage audit.

This is NOT a count of manual gestures, confirmed payments, or global ES completeness.
Root API family proposals are review candidates, not historical enablement proof.
"""
from __future__ import annotations

from collections import defaultdict
from .coverage_triage import REVIEW_TYPES, unanchored_review_queue
import re
from .service_journey import (semantic_execution_kind, source_family,
    OWNER_AUTOMATIC_ROOT_PATHS, _root_role)

VERSION = 'p24-behavior-coverage-LC2E'
# Only show syntactically innocuous API route names, never arbitrary log text.
SAFE_ROOT = re.compile(
    r'(?:Core|Services|Public|Ewano|Files|PaymentRedirect|PaymentCallback|Webhook|JobsQueue)'
    r'\.(?:v[0-9]+/)?[A-Za-z][A-Za-z0-9_]{0,80}\Z'
)


def safe_api_root(raw):
    root = str(raw or '').split(' Line:', 1)[0].strip()
    if root == 'ClientAyanCoTopUp.ProductReserve':
        return root
    return root if SAFE_ROOT.fullmatch(root) else '[unrecognized_or_missing_root]'


class BehaviorCoverageMixin:
    def behavior_coverage(self, *, top=30):
        """Aggregate all indexed Viewer requests without reading raw PII.

        Query is read-only, runs on SQLite and guarded PostgreSQL. All counts
        reflect the *currently built read model* (not whole Elasticsearch).
        """
        top = int(top)
        if not 1 <= top <= 200:
            raise ValueError('invalid_top_limit')
        grouped = self.all('''SELECT r.root_call,a.label,a.category,a.initiation,r.conflicted,
                CASE WHEN r.session_key IS NULL THEN 0 ELSE 1 END AS has_session,
                COUNT(*) AS n
            FROM viewer_requests r
            LEFT JOIN viewer_actions a ON a.action_key=r.request_key
            GROUP BY r.root_call,a.label,a.category,a.initiation,r.conflicted,
                     CASE WHEN r.session_key IS NULL THEN 0 ELSE 1 END''')
        meta = self.one('''SELECT COUNT(*) AS total,
                COALESCE(SUM(CASE WHEN conflicted<>0 THEN 1 ELSE 0 END),0) AS conflicts,
                COALESCE(SUM(CASE WHEN root_call IS NULL THEN 1 ELSE 0 END),0) AS missing_root,
                COALESCE(SUM(CASE WHEN root_call IS NULL AND root_count>1
                         AND session_key IS NOT NULL THEN 1 ELSE 0 END),0) AS multi_root_ambiguous
                FROM viewer_requests''')
        totals = defaultdict(int)
        families = defaultdict(lambda: {'request_executions': 0,
                                        'service_execution_candidates': 0,
                                        'user_management_candidates': 0})
        unresolved = defaultdict(int)
        technical_facades = defaultdict(int)
        unknown_role_roots = defaultdict(int)
        unknown_role_nonsemantic_roots = defaultdict(int)
        triage_counts = defaultdict(int)
        triage_roots = defaultdict(lambda: defaultdict(int))
        rooted_with_session = 0
        from .service_dispatch import TRANSPORT,api_path,dispatch_catalog
        reviewed_unknowns=self._reviewed_unknown_service_paths()
        for row in grouped:
            n = int(row['n'])
            if row['conflicted']:
                totals['conflicted_request_keys'] += n
                continue
            if api_path(row['root_call'])==TRANSPORT and row['label'] in dispatch_catalog()['routes']:
                row['root_call']=row['label']
                totals['dispatcher_requests_with_selected_service']+=n
            root = safe_api_root(row['root_call'])
            role_reviewed=api_path(row['root_call']) in reviewed_unknowns
            kind = semantic_execution_kind(row['root_call'], row['category'],role_reviewed=role_reviewed)
            if root != '[unrecognized_or_missing_root]' and row['has_session']:
                rooted_with_session += n
            if kind:
                totals['root_semantic_execution_candidates'] += n
                if row['has_session']:
                    totals['session_scoped_root_semantic_candidates'] += n
                totals['semantic_' + kind] += n
            # ProductReserve may be a meaningful facet of a payment RequestID.
            # It cannot be inferred from root alone; report as unassessed.
            if root.startswith('Services.v'):
                totals['service_facade_requests'] += n
                family = source_family(row['root_call'])
                if root in OWNER_AUTOMATIC_ROOT_PATHS:
                    totals['owner_confirmed_automatic_facade_requests'] += n
                    continue
                totals['nonautomatic_facade_candidate_requests'] += n
                if family.get('family_id'):
                    totals['source_catalog_mapped_facade_requests'] += n
                    # Family proposal is a contextual domain mapping, NOT proof
                    # that the endpoint is a distinct customer service action.
                    families[family['family_id']]['request_executions'] += n
                    if kind == 'service_execution':
                        families[family['family_id']]['service_execution_candidates'] += n
                    if kind == 'user_management_execution':
                        families[family['family_id']]['user_management_candidates'] += n
                else:
                    totals['source_catalog_unmapped_facade_requests'] += n
                    unresolved[root] += n
                if kind is None:
                    totals['facade_without_semantic_anchor'] += n
                    technical_role = _root_role(row['root_call'], row['category'],role_reviewed=role_reviewed)
                    if technical_role in ('support_catalog_lookup', 'support_status_lookup',
                                           'support', 'system_followup'):
                        totals['known_technical_facade_requests'] += n
                        technical_facades[(root,technical_role)] += n
                    else:
                        totals['unresolved_nonsemantic_facade_requests'] += n
            if root == '[unrecognized_or_missing_root]':
                totals['unrecognized_or_missing_root_requests'] += n
            if row['category'] in ('unknown','unresolved',None):
                totals['unknown_viewer_role_requests'] += n
                unknown_role_roots[root] += n
                if kind is None:
                    totals['unknown_role_without_semantic_anchor_requests'] += n
                    unknown_role_nonsemantic_roots[root] += n
                    review = unanchored_review_queue(root)
                    triage_counts[review] += n
                    triage_roots[review][root] += n
        proposals = sorted(
            (dict(family_id=key,**item) for key,item in families.items()),
            key=lambda x: (-x['request_executions'], x['family_id']))
        unresolved_sorted = sorted(unresolved.items(),key=lambda x:(-x[1],x[0]))
        technical_sorted = sorted(technical_facades.items(),key=lambda x:(-x[1],x[0]))
        unknown_sorted = sorted(unknown_role_roots.items(),key=lambda x:(-x[1],x[0]))
        unknown_no_anchor_sorted = sorted(unknown_role_nonsemantic_roots.items(),
                                          key=lambda x:(-x[1],x[0]))
        # Every unknown, unanchored Viewer request goes to exactly one queue.
        # The queue is diagnostic; it never promotes a human-action count.
        triage = [dict(queue=queue, request_executions=triage_counts[queue],
            meaning=REVIEW_TYPES[queue],
            api_roots=[dict(api=api, request_executions=n)
                       for api,n in sorted(triage_roots[queue].items(),
                                           key=lambda item:(-item[1], item[0]))[:top]],
            api_roots_omitted_request_executions=sum(n for _,n in sorted(
                triage_roots[queue].items(), key=lambda item:(-item[1],item[0]))[top:]))
            for queue in sorted(triage_counts, key=lambda q:(-triage_counts[q],q))]
        assert sum(entry['request_executions'] for entry in triage) == (
            totals['unknown_role_without_semantic_anchor_requests'])
        return dict(version=VERSION,
            population='unconflicted_viewer_requests_in_current_read_model',
            indexed_requests=int(meta['total']),
            conflicted_request_keys=int(meta['conflicts']),
            missing_root_request_keys=int(meta['missing_root']),
            multi_root_ambiguous_requests=int(meta['multi_root_ambiguous']),
            rooted_with_session_request_keys=rooted_with_session,
            counts=dict(sorted(totals.items())),
            facade_mapping_fraction=(round(totals['source_catalog_mapped_facade_requests'] /
                  totals['nonautomatic_facade_candidate_requests'], 6)
                  if totals['nonautomatic_facade_candidate_requests'] else None),
            unmapped_or_ambiguous_facades=[{'api':key,'request_executions':n}
                for key,n in unresolved_sorted[:top]],
            unmapped_other_request_executions=sum(n for _,n in unresolved_sorted[top:]),
            mapped_technical_facade_roots=[dict(api=root, technical_role=role,
                request_executions=n) for (root,role),n in technical_sorted[:top]],
            mapped_technical_facades_omitted=sum(n for (_,n) in technical_sorted[top:]),
            unknown_viewer_role_roots=[dict(api=root,request_executions=n)
                for root,n in unknown_sorted[:top]],
            unknown_role_roots_omitted=sum(n for _,n in unknown_sorted[top:]),
            unknown_role_without_semantic_anchor_roots=[dict(api=root,request_executions=n)
                for root,n in unknown_no_anchor_sorted[:top]],
            unknown_role_without_semantic_anchor_omitted=sum(n for _,n in unknown_no_anchor_sorted[top:]),
            unanchored_unknown_review_queues=triage,
            unanchored_unknown_triage_total=sum(triage_counts.values()),
            family_proposals=proposals[:top],
            family_proposals_omitted=max(0,len(proposals)-top),
            manual_actions_confirmed=None,
            fully_reconstructed_behaviors=None,
            notes=['counts_request_executions_not_human_clicks',
                   'source_catalog_fraction_excludes_owner_confirmed_automatic_facades',
                   'catalog_mapping_does_not_prove_semantic_behavior_recognition',
                   'unmapped_family_vs_mapped_technical_lookup_are_separate_queues',
                   'unknown_viewer_role_is_not_equivalent_to_unknown_customer_behavior',
                   'review_queue_is_not_behavior_classification_or_manual_initiation',
                   'service_catalog_is_source_proposal_not_runtime_confirmation',
                   'multi_root_request_is_not_a_proven_behavior_count',
                   'payment_and_provider_facets_not_in_root_aggregation',
                   'not_whole_elasticsearch_completeness',
                   'data_without_observed_root_cannot_be_assumed_non_behavior',
                   'no_financial_settlement_inferred'],
            read_only=True)
