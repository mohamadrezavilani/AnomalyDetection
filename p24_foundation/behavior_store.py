"""Explicit, atomic candidate-to-incident binding in the guarded design database."""
from collections import defaultdict
from fractions import Fraction
import uuid

from .behavior import VERSION, publication_window, score
from .behavior_binding import VERSION as BINDING_VERSION, heads_digest, window_key
from .errors import FoundationError
from .incidents import IncidentRegistry, ISSUE_IDENTITY_VERSION
from .publication import ObservationPublisher
from .store import stable_id, jsonb, floor_ns, execute_many


def persist_candidates(store, *, target_spec, reference_specs, rank_cutoff, expected_generation):
    """Recompute trusted inputs under the publication fence; never accept report JSON.

    Findings describe observed deviations, not fraud or detector usefulness.
    Each run partition cites its entire target-group and baseline selection so
    partial changes invalidate every partition of that evaluation together.
    """
    if isinstance(expected_generation,bool) or not isinstance(expected_generation,int) or expected_generation<1:
        raise FoundationError('invalid_behavior_publication_generation')
    if not 1<=len(reference_specs)<=128:
        raise FoundationError('behavior_reference_limit')
    publisher=ObservationPublisher(store)
    registry=IncidentRegistry(store)
    with store.c.transaction():
        store._lock()
        current,generation=publisher._current()
        if generation!=expected_generation or str(current)!=str(uuid.UUID(target_spec['publication_id'])):
            raise FoundationError('stale_behavior_publication')
        tokenize=lambda route:store.keys.token(store.namespace,'behavior_service',route)
        target=publication_window(store.c,store.namespace_id,current,target_spec['start'],target_spec['end'],route_token=tokenize)
        references=[];reference_requests=0
        for spec in reference_specs:
            item=publication_window(store.c,store.namespace_id,spec['publication_id'],spec['start'],spec['end'],route_token=tokenize)
            reference_requests+=sum(map(len,item['groups'].values()))
            if reference_requests>100000:raise FoundationError('behavior_reference_request_limit')
            references.append(item)
        report=score(target,references,rank_cutoff=rank_cutoff)
        header=publisher._header(current)
        selected=header['input_manifest']['effective_sources']
        reference_snapshots=sorted({ref['capture_snapshot_id'] for ref in references})
        if not set(reference_snapshots)<=set(selected):
            raise FoundationError('behavior_reference_selection_changed')
        heads=publisher._heads(current)
        parts=[]
        for evaluation in report['evaluations']:
            group=(evaluation['session_key'],evaluation['service_key'])
            partitions=defaultdict(list)
            for request in target['groups'][group]:partitions[heads[request]].append(request)
            parts.append((evaluation,partitions))
        if sum(map(lambda item:len(item[1]),parts))>10000:
            raise FoundationError('behavior_finding_limit')
        persisted=[]
        for evaluation,partitions in parts:
            subject,service=evaluation['session_key'],evaluation['service_key']
            pattern='behavior.volume.'+service.rsplit(':',1)[-1]
            identity=store.keys.token(store.namespace,'issue_identity',[ISSUE_IDENTITY_VERSION,'session',subject,pattern,None])
            incident=stable_id(store.namespace,'incident',identity)
            old=store.c.execute('''SELECT h.generation,r.result FROM p24_next.foundation_incident_head h
                JOIN p24_next.foundation_incident_revision r USING(namespace_id,incident_id,revision_id)
                WHERE h.namespace_id=%s AND h.incident_id=%s''',(store.namespace_id,incident)).fetchone()
            selector=window_key(target['start_ns'],target['end_ns'])
            evaluation_id=stable_id(store.namespace,'behavior_evaluation',report['evidence_manifest_sha256'],subject,service)
            binding=dict(version=BINDING_VERSION,evaluation_id=str(evaluation_id),start_ns=str(target['start_ns']),
                end_ns=str(target['end_ns']),service_key=service,reference_snapshots=reference_snapshots,
                target_heads_sha256=heads_digest(target['groups'][(subject,service)],heads))
            if old and old[1].get('behavior_evaluation_selection',{}).get(selector)!=str(evaluation_id):
                existing=store.c.execute('SELECT 1 FROM p24_next.finding WHERE namespace_id=%s AND finding_id=ANY(%s) LIMIT 1',
                    (store.namespace_id,[stable_id(evaluation_id,str(run),'finding') for run in partitions])).fetchone()
                if existing:raise FoundationError('behavior_historical_reselection_requires_review')
            finding_ids=[]
            for run,requests in sorted(partitions.items(),key=lambda item:str(item[0])):
                detector=stable_id(evaluation_id,str(run),'detector')
                finding=stable_id(evaluation_id,str(run),'finding')
                abstained=evaluation['status']=='abstained'
                reasons={evaluation['reason']:1} if abstained else {}
                store.c.execute('''INSERT INTO p24_next.detector_run(namespace_id,detector_run_id,run_id,detector_key,detector_version,
                    target_start,target_end,status,applicable_units,evaluated_units,unsupported_units,reason_counts)
                    VALUES(%s,%s,%s,'session_service_volume',%s,%s,%s,%s,1,%s,%s,%s) ON CONFLICT DO NOTHING''',
                    (store.namespace_id,detector,run,VERSION,floor_ns(target['start_ns']),floor_ns(target['end_ns']),
                     'partial' if abstained else 'complete',0 if abstained else 1,1 if abstained else 0,jsonb(reasons)))
                measurements=dict(evaluation=evaluation,behavior_binding=binding,evidence_manifest=report['evidence_manifest'],
                    candidate_only=True,calibrated_error_rate=False,priority='unrated',fraud_verdict='not_established',
                    unit='one_session_route_window; partition_records_are_not_extra_units')
                rank=Fraction(evaluation['rank_numerator'],evaluation['rank_denominator']) if not abstained else None
                store.c.execute('''INSERT INTO p24_next.finding(namespace_id,finding_id,detector_run_id,finding_key,scope_kind,
                    subject_key,score_numeric,score_unit,evidence_manifest_sha256,measurements,assessment_state)
                    VALUES(%s,%s,%s,%s,'session',%s,%s,'empirical_upper_tail_rank',%s,%s,%s) ON CONFLICT DO NOTHING''',
                    (store.namespace_id,finding,detector,pattern,subject,float(rank) if rank is not None else None,
                     report['evidence_manifest_sha256'],jsonb(measurements),
                     'supported_deviation' if evaluation['status']=='candidate' else 'observation'))
                execute_many(store.c,'''INSERT INTO p24_next.finding_request(namespace_id,finding_id,run_id,request_key,role_key,proof)
                        VALUES(%s,%s,%s,%s,'target_partition',%s) ON CONFLICT DO NOTHING''',
                        [(store.namespace_id,finding,run,request,jsonb(dict(evaluation_id=str(evaluation_id),binding_version=BINDING_VERSION)))
                         for request in requests])
                finding_ids.append(str(finding))
            if evaluation['status']=='candidate' or old:
                saved=registry.refresh(current,scope_kind='session',subject_key=subject,pattern_key=pattern,
                    finding_ids=finding_ids,expected_generation=old[0] if old else 0,
                    behavior_selection_updates={selector:str(evaluation_id)})
                persisted.append(dict(**saved,evaluation_status=evaluation['status']))
        report.update(input_kind='committed_observed_publications',persisted_incidents=persisted,
                      publication_generation=expected_generation,automatic_priority_changed=False)
    return report
