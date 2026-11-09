"""LC2A: read-only, cursor-paged customer-session behavioral executions.

Do NOT merge independent queries sharing Session, target, invoice, or cache;
request execution identity survives ES five-minute windows and IP changes.
Financial steps and background callbacks are never counted as user gestures.
Only observed service/funding/reservation *executions* enter this list;
initiation remains unknown absent authoritative evidence. Cross-session
webhooks remain in service_journey via typed evidence, not session ownership.
"""
from __future__ import annotations
import re
from .service_journey import semantic_execution_kind, source_family, stable_behavior_occurrence_key
from .behavior_coverage import safe_api_root

VERSION = 'p24-session-behavior-LC2D'
SESSION_KEY_RE = re.compile(r'[0-9a-f]{64}\Z')
MAX_SCAN = 500
FACET_SCAN_CAP = 5000


class SessionBehaviorMixin:
    def session_behavior(self, session_key, *, after_ns=None, after_key=None,
                         scan_limit=150, from_ns=None, to_ns=None):
        """Read-only stable cursor scan of candidate semantic service executions.

        Completeness is explicitly bound to indexed records and this scan.
        Unknown human initiation, anonymous followups and unobserved events
        cannot be reported as explicit clicks or nonoccurrence.
        """
        if not isinstance(session_key,str) or not SESSION_KEY_RE.fullmatch(session_key):
            raise ValueError('invalid_internal_session_key')
        scan_limit=int(scan_limit)
        if not 1 <= scan_limit <= MAX_SCAN:
            raise ValueError('invalid_scan_limit')
        if (after_ns is None) != (after_key is None):
            raise ValueError('cursor_requires_time_and_key')
        if after_key is not None and (not isinstance(after_key,str) or
                                       not SESSION_KEY_RE.fullmatch(after_key)):
            raise ValueError('invalid_after_request_key')
        for value in (after_ns,from_ns,to_ns):
            if value is not None and (not isinstance(value,int) or value<0):
                raise ValueError('invalid_time_boundary')
        if from_ns is not None and to_ns is not None and from_ns >= to_ns:
            raise ValueError('invalid_time_range')
        anchor_ts='COALESCE(r.root_ns,r.started_ns,r.ended_ns,0)'
        where=['r.session_key=?',
              '(r.conflicted=0 OR (r.conflicted=1 AND r.root_call IS NULL AND r.root_count>1))',
              "(a.category IN ('business','user_management') OR r.root_call LIKE ? "
              "OR r.root_call LIKE ? OR EXISTS "
              "(SELECT 1 FROM viewer_events e WHERE e.request_key=r.request_key "
              "AND e.callpath LIKE ?) OR (r.root_call IS NULL AND r.root_count>1 "
              "AND EXISTS(SELECT 1 FROM viewer_events e WHERE e.request_key=r.request_key "
              "AND e.kind='client' AND e.callpath LIKE ?)))"]
        args=[session_key,'%/UserWalletCharge%',
              'Services.v%/%', 'ClientAyanCoTopUp.ProductReserve%', 'Services.v%/%']
        if after_ns is not None:
            where.append(f'({anchor_ts}>? OR ({anchor_ts}=? AND r.request_key>?))')
            args.extend([after_ns,after_ns,after_key])
        if from_ns is not None:
            where.append(f'{anchor_ts}>=?');args.append(from_ns)
        if to_ns is not None:
            where.append(f'{anchor_ts}<?');args.append(to_ns)
        query=f"""SELECT r.request_key,r.root_call,r.root_code,r.root_count,r.started_ns,
                    r.ended_ns,{anchor_ts} AS anchor_ns,r.event_count,
                    a.category,a.initiation,
                    CASE WHEN EXISTS(SELECT 1 FROM viewer_events e
                       WHERE e.request_key=r.request_key AND e.callpath LIKE ?)
                       THEN 1 ELSE 0 END AS provider_reservation
            FROM viewer_requests r LEFT JOIN viewer_actions a ON a.action_key=r.request_key
            WHERE {' AND '.join(where)}
            ORDER BY {anchor_ts},r.request_key LIMIT ?"""
        # The extra candidate detects a *true* pending next page; never
        # claim a complete session when a cap exhausted indexed candidates.
        rows=self.all(query,['ClientAyanCoTopUp.ProductReserve%']+args+[scan_limit+1])
        has_more=len(rows)>scan_limit
        scanned=rows[:scan_limit]
        self.apply_service_contexts(scanned)
        reviewed_unknowns=self._reviewed_unknown_service_paths()
        role_sources={row['service_path']:row['source'] for row in self.all('SELECT service_path,source FROM viewer_service_roles')}
        # A single RequestID may contain multiple service/provider operations.
        # Observe secondary callpaths, but NEVER promote them to additional
        # independent human actions without a separate semantic anchor.
        facets_by_request = {}
        facets_complete = True
        if scanned:
            keys = [r['request_key'] for r in scanned]
            facets = self.all(f'''SELECT DISTINCT request_key,callpath,kind
                FROM viewer_events
                WHERE request_key IN ({','.join('?' for _ in keys)})
                  AND (kind='client' OR (kind='provider' AND callpath LIKE ?))
                ORDER BY request_key,kind,callpath LIMIT ?''',
                keys + ['ClientAyanCoTopUp.ProductReserve%', FACET_SCAN_CAP+1])
            if len(facets) > FACET_SCAN_CAP:
                facets_complete = False
                facets = facets[:FACET_SCAN_CAP]
            for facet in facets:
                api = safe_api_root(facet['callpath'])
                if api == '[unrecognized_or_missing_root]':
                    continue
                # Provenance is this request's own indexed event. A service
                # callpath may be automatic even when the root is meaningful.
                if api.startswith('Services.v') or api.startswith('ClientAyanCoTopUp.ProductReserve'):
                    facets_by_request.setdefault(facet['request_key'],set()).add(
                        (api,facet['kind']))
        occurrences=[]
        ambiguous_multi_root=[]
        seen=set()
        unresolved_facades=0
        for row in scanned:
            # Unknown facade roots enter a review queue rather than silently
            # disappearing. Source-catalog service candidates count as observed
            # executions, NOT confirmed human actions.
            kind=semantic_execution_kind(row['root_call'],row['category'],
                product_reservation_observed=bool(row['provider_reservation']),
                role_reviewed=str(row['root_call'] or '').split(' Line:',1)[0].strip() in reviewed_unknowns)
            if not kind:
                if not row['root_call'] and row['root_count']>1:
                    paths=sorted({api for api,typ in facets_by_request.get(row['request_key'],set())
                                  if typ=='client' and api.startswith('Services.v')})
                    if paths:
                        ambiguous_multi_root.append(dict(
                            request_key=row['request_key'],
                            anchor_ns=row['anchor_ns'],
                            observed_service_roots=paths[:12],
                            candidate_roots_complete=facets_complete and len(paths)<=12,
                            attribution='multiple_facade_roots_no_independent_operation_anchor',
                            counted_as_behavior=False))
                if str(row['root_call'] or '').startswith('Services.v'):
                    unresolved_facades+=1
                continue
            ident=stable_behavior_occurrence_key(kind,row['root_call'] or
                    'HTTP root not observed',row['request_key'])
            if ident in seen:
                continue
            seen.add(ident)
            catalog=source_family(row['root_call'])
            root_api = safe_api_root(row['root_call'])
            related_facets = sorted((api, evidence_kind)
                  for api,evidence_kind in facets_by_request.get(row['request_key'],set())
                  if api != root_api)
            occurrences.append(dict(occurrence_key=ident,
                kind=kind,anchor_request_key=row['request_key'],
                root_call=row['root_call'] or 'HTTP root not observed',
                root_code=row['root_code'],category=row['category'],
                initiation=row['initiation'] or 'unknown',
                customer_initiation_confirmed=(row['initiation']=='confirmed_manual'),
                started_ns=row['started_ns'],ended_ns=row['ended_ns'],
                anchor_ns=row['anchor_ns'],event_count=row['event_count'],
                family_id=catalog.get('family_id'),
                family_label_fa=catalog.get('family_label_fa'),
                catalog_authority=catalog.get('authority'),
                # Secondary paths are evidence of technical suboperations,
                # NOT separate proven behaviors or manual actions.
                observed_secondary_operations=[dict(api=api,evidence_kind=evidence_kind,
                    attribution='same_request_suboperation_independent_action_unproven')
                    for api,evidence_kind in related_facets[:12]],
                secondary_operation_list_complete=facets_complete and len(related_facets)<=12,
                product_reservation_in_request=bool(row['provider_reservation']),
                root_classification_authority=('source_proposal_only_runtime_unverified'
                    if row['category'] not in ('business','user_management') or
                       role_sources.get(str(row['root_call'] or '').split(' Line:',1)[0].strip())=='source_backed'
                    else 'viewer_action_role'),
                role_classification_source=role_sources.get(str(row['root_call'] or '').split(' Line:',1)[0].strip()),
                financial_finality='NOT_INFERRED',
                evidence_scope='indexed_request_root_or_provider_execution'))
        cursor=(dict(after_ns=scanned[-1]['anchor_ns'],
                     after_key=scanned[-1]['request_key']) if has_more and scanned else None)
        return dict(version=VERSION,session_key=session_key,
            observed_occurrences=occurrences,
            ambiguous_multi_root_requests=ambiguous_multi_root,
            ambiguous_multi_root_count=len(ambiguous_multi_root),
            observed_semantic_execution_count=len(occurrences),
            confirmed_manual_action_count=None,
            candidate_requests_scanned=len(scanned),
            candidate_requests_skipped=len(scanned)-len(occurrences),
            unclassified_facade_candidates=unresolved_facades,
            candidate_secondary_operations_observed=sum(len(x['observed_secondary_operations']) for x in occurrences),
            secondary_operation_evidence_complete=facets_complete,
            observed_service_execution_count=sum(x['kind']=='service_execution' for x in occurrences),
            observed_user_management_execution_count=sum(x['kind']=='user_management_execution' for x in occurrences),
            observed_wallet_funding_execution_count=sum(x['kind']=='wallet_funding_execution' for x in occurrences),
            observed_product_reservation_execution_count=sum(x['kind']=='product_reservation_execution' for x in occurrences),
            next_cursor=cursor,has_more=has_more,
            candidate_scan_complete=(not has_more and after_ns is None and
                                     from_ns is None and to_ns is None),
            all_session_history_loaded=False,
            completeness_scope='indexed_viewer_session_candidate_scan',
            caveats=["not_a_manual_click_count",
                     "payment_and_callbacks_are_technical_details_not_new_service_occurrences",
                     "missing_logs_or_bridges_cannot_prove_no_activity",
                     "source_family_catalog_is_not_historical_enablement_proof",
                     "secondary_suboperations_are_observed_facets_not_separate_manual_actions"]
                     + (["candidate_scan_budget_continue_with_cursor"] if has_more else [])
                     + (["facet_scan_budget_incomplete"] if not facets_complete else []),
            read_only=True)
