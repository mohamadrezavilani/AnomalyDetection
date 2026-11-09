"""Bounded incident recurrence and explicit operator review over sealed evidence.

Finding adapters supply reviewed machine-pattern/subject identities. This layer
neither detects deviations nor authenticates an upstream service. No score or
priority is derived from an operator verdict.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone

from .errors import FoundationError
from .privacy import canonical
from .publication import ObservationPublisher, checked_limit
from .store import jsonb, stable_id, execute_many
from .time import parse_time

VERSION='p24-incident-review.2t.1'
GROUPING='request-evidence-gap-900s.1'
ISSUE_IDENTITY_VERSION='typed-subject-pattern-family.1'
KINDS={'session','user','service','entity','network','data_quality','observability'}
LABEL=re.compile(r'^[A-Za-z0-9_.:-]{1,160}$')
TOKEN=re.compile(r'^[A-Za-z0-9_]+:[A-Za-z0-9_-]{1,40}:[a-f0-9]{64}$')
MAX_FINDINGS=10000
REASONS={'expected_workflow','detector_error','test_activity','operator_review'}


def ref(value):
    try:return uuid.UUID(str(value))
    except (ValueError,TypeError,AttributeError):raise FoundationError('invalid_incident_reference') from None


def digest(value):return hashlib.sha256(canonical(value)).hexdigest()


class IncidentRegistry:
    def __init__(self,store,*,clock=None):
        self.store,self.c,self.n=store,store.c,store.namespace_id
        self.pub=ObservationPublisher(store)
        self.clock=clock or (lambda:datetime.now(timezone.utc))

    def _contract(self,incident):
        row=self.c.execute('''SELECT i.scope_kind,i.subject_key,c.pattern_key,i.failure_family,c.grouping_version
            FROM p24_next.incident i JOIN p24_next.foundation_incident_contract c USING(namespace_id,incident_id)
            WHERE i.namespace_id=%s AND i.incident_id=%s''',(self.n,ref(incident))).fetchone()
        if row is None:raise FoundationError('incident_not_available')
        return row

    def refresh(self,publication_id,*,scope_kind,subject_key,pattern_key,finding_ids=(),failure_family=None,expected_generation=0,
                behavior_selection_updates=None):
        """Internal, atomic adapter; does not expose an unverified finding write API.

        Existing memberships are retained for audit. Only findings whose entire
        RequestID support is still pinned to their detector run count as active.
        """
        if scope_kind not in KINDS or not isinstance(subject_key,str) or not TOKEN.fullmatch(subject_key):
            raise FoundationError('invalid_incident_subject')
        if not isinstance(pattern_key,str) or not LABEL.fullmatch(pattern_key):raise FoundationError('invalid_incident_pattern')
        if failure_family is not None and (not isinstance(failure_family,str) or not LABEL.fullmatch(failure_family)):
            raise FoundationError('invalid_failure_family')
        if isinstance(expected_generation,bool) or not isinstance(expected_generation,int) or expected_generation<0:
            raise FoundationError('invalid_incident_generation')
        if behavior_selection_updates is not None:
            if (not isinstance(behavior_selection_updates,dict) or len(behavior_selection_updates)>128
                    or any(not isinstance(key,str) or not re.fullmatch(r'-?\d{1,30}:-?\d{1,30}',key)
                           for key in behavior_selection_updates)):
                raise FoundationError('invalid_behavior_evaluation_selection')
            behavior_selection_updates={key:str(ref(value)) for key,value in behavior_selection_updates.items()}
        incoming=sorted({ref(x) for x in finding_ids})
        if len(incoming)>MAX_FINDINGS:raise FoundationError('incident_finding_limit')
        identity=self.store.keys.token(self.store.namespace,'issue_identity',[ISSUE_IDENTITY_VERSION,scope_kind,subject_key,pattern_key,failure_family])
        incident=stable_id(self.store.namespace,'incident',identity)
        with self.c.transaction():
            self.store._lock()
            header=self.pub._header(publication_id);p=header['publication_id'];heads=self.pub._heads(p)
            old=self.c.execute('SELECT revision_id,generation FROM p24_next.foundation_incident_head WHERE namespace_id=%s AND incident_id=%s',
                               (self.n,incident)).fetchone()
            generation=old[1] if old else 0
            candidates={r[0] for r in self.c.execute('SELECT finding_id FROM p24_next.incident_finding WHERE namespace_id=%s AND incident_id=%s',
                                                  (self.n,incident)).fetchall()}|set(incoming)
            if len(candidates)>MAX_FINDINGS:raise FoundationError('incident_finding_limit')
            rows=self.c.execute('''SELECT f.finding_id,f.scope_kind,f.subject_key,f.finding_key,f.assessment_state,
                f.score_numeric,f.score_unit,f.supersedes_finding_id,d.run_id,d.status,r.state,f.measurements->>'failure_family',f.measurements
                FROM p24_next.finding f JOIN p24_next.detector_run d USING(namespace_id,detector_run_id)
                JOIN p24_next.projection_run r ON r.namespace_id=d.namespace_id AND r.run_id=d.run_id
                WHERE f.namespace_id=%s AND f.finding_id=ANY(%s) ORDER BY f.finding_id''',(self.n,sorted(candidates))).fetchall() if candidates else []
            if len(rows)!=len(candidates):raise FoundationError('finding_not_available')
            selections={}
            if old and (behavior_selection_updates is not None or any(isinstance(row[-1],dict) and 'behavior_binding' in row[-1] for row in rows)):
                prior=self.c.execute('SELECT result FROM p24_next.foundation_incident_revision WHERE namespace_id=%s AND revision_id=%s',
                                     (self.n,old[0])).fetchone()[0]
                selections=dict(prior.get('behavior_evaluation_selection',{}))
            selections.update(behavior_selection_updates or {})
            if len(selections)>128:raise FoundationError('behavior_selection_limit')
            behavior_summaries=None
            behavior_digests={}
            superseded={r[7] for r in rows if r[7] is not None}
            active=[];excluded=[];request_summaries={};bounds=[];supports=[]
            for f in rows:
                fid,kind,subject,pattern,assessment,score,unit,_,run,status,sealed,family,measurements=f
                if (kind,subject,pattern)!=(scope_kind,subject_key,pattern_key) or family!=failure_family:raise FoundationError('incident_scope_mismatch')
                if sealed!='sealed' or status not in {'complete','partial'}:raise FoundationError('finding_run_not_ready')
                request_rows=self.c.execute('''SELECT fr.request_key,fr.run_id,s.summary FROM p24_next.finding_request fr
                    JOIN p24_next.foundation_request_summary s ON s.namespace_id=fr.namespace_id AND s.run_id=fr.run_id AND s.request_key=fr.request_key
                    WHERE fr.namespace_id=%s AND fr.finding_id=%s ORDER BY fr.request_key,fr.role_key''',(self.n,fid)).fetchall()
                reason='superseded' if fid in superseded else 'not_supported_deviation' if assessment!='supported_deviation' else None
                if not request_rows:reason=reason or 'no_request_support_in_this_adapter'
                if any(heads.get(key)!=run_id for key,run_id,_ in request_rows):reason=reason or 'evidence_revision_not_current_in_publication'
                binding=measurements.get('behavior_binding') if isinstance(measurements,dict) else None
                if binding is not None:
                    from .behavior_binding import binding_reason,heads_digest
                    from .behavior import window
                    from .store import floor_ns
                    try:
                        start,end=int(binding['start_ns']),int(binding['end_ns'])
                        if start%1000 or end%1000 or end-start!=300_000_000_000:raise ValueError()
                        cache=(start,end,subject,binding['service_key'])
                        if cache not in behavior_digests:
                            if behavior_summaries is None:
                                behavior_summaries=[row[0] for row in self.c.execute('''SELECT s.summary
                                    FROM p24_next.foundation_observation_heads(%s,%s,NULL) h
                                    JOIN p24_next.foundation_request_summary s ON s.namespace_id=%s AND s.run_id=h.run_id AND s.request_key=h.request_key
                                    LIMIT 100001''',(self.n,p,self.n)).fetchall()]
                            current=window(floor_ns(start).isoformat(),floor_ns(end).isoformat(),int(header['input_manifest']['knowledge_at_ns']),
                                p,behavior_summaries,route_token=lambda value:self.store.keys.token(self.store.namespace,'behavior_service',value))
                            keys=current['groups'].get((subject,binding['service_key']),[])
                            behavior_digests[cache]=heads_digest(keys,heads) if keys else None
                        reason=reason or binding_reason(binding,selections,header['input_manifest']['effective_sources'],behavior_digests[cache])
                    except (KeyError,ValueError,TypeError,FoundationError):
                        reason=reason or 'behavior_binding_invalid'
                if reason:
                    excluded.append(dict(finding_id=str(fid),reason=reason));continue
                evidence={key:summary for key,_,summary in request_rows}
                if scope_kind=='session' and any(s.get('identity_state')!='known' or s.get('session_key')!=subject_key for s in evidence.values()):
                    raise FoundationError('finding_subject_not_supported_by_request')
                times=[int(s[k]) for s in evidence.values() for k in ('first_time_ns','last_time_ns') if s.get(k) is not None]
                if not times:
                    excluded.append(dict(finding_id=str(fid),reason='source_time_unavailable'));continue
                first,last=min(times),max(times)
                request_summaries.update(evidence)
                for summary in evidence.values():
                    observed=[int(summary[k]) for k in ('first_time_ns','last_time_ns') if summary.get(k) is not None]
                    if observed:bounds.append((min(observed),max(observed),str(fid)))
                active.append(dict(finding_id=str(fid),score=str(score) if score is not None else None,score_unit=unit,
                                   first_event_ns=str(first),last_event_ns=str(last)))
                if binding is not None:
                    observation=measurements.get('evaluation',{})
                    allowed=('target_requests','reference_active_windows','reference_median','reference_max','rank_numerator','rank_denominator','explanation_fa')
                    active[-1]['behavior_observation']={key:observation[key] for key in allowed if key in observation}
                    active[-1]['behavior_evaluation_id']=binding['evaluation_id']
                supports.extend(dict(finding_id=str(fid),request_key=key,run_id=str(run)) for key in sorted(evidence))
            occurrences=[]
            for first,last,fid in sorted(bounds):
                if not occurrences or first-int(occurrences[-1]['last_event_ns'])>900_000_000_000:
                    occurrences.append(dict(first_event_ns=str(first),last_event_ns=str(last),finding_ids=[fid]))
                else:
                    occurrences[-1]['last_event_ns']=str(max(last,int(occurrences[-1]['last_event_ns'])))
                    if fid not in occurrences[-1]['finding_ids']:occurrences[-1]['finding_ids'].append(fid)
            requests=[dict(request_key=key,client_http=s.get('client_completion_state')=='observed',
                           first_event_ns=s.get('first_time_ns'),last_event_ns=s.get('last_time_ns'))
                      for key,s in sorted(request_summaries.items())]
            result=dict(version=VERSION,publication_id=str(p),grouping_policy=GROUPING,scope_kind=scope_kind,subject_key=subject_key,
                pattern_key=pattern_key,failure_family=failure_family,active_findings=active,excluded_findings=excluded,
                request_support=supports,requests=requests,distinct_supported_requests=len(requests),
                distinct_client_http_requests=sum(x['client_http'] for x in requests),occurrences=occurrences,
                occurrence_count=len(occurrences),first_event_ns=occurrences[0]['first_event_ns'] if occurrences else None,
                last_event_ns=occurrences[-1]['last_event_ns'] if occurrences else None,
                priority='unrated',priority_basis='no_priority_policy_decision',root_cause='not_established',
                coverage='explicit finding memberships supported by this pinned publication; no traffic-wide completeness claim')
            if selections:result['behavior_evaluation_selection']=selections
            result_digest=digest(result)
            if old:
                previous=self.c.execute('SELECT input_sha256 FROM p24_next.foundation_incident_revision WHERE namespace_id=%s AND revision_id=%s',
                                        (self.n,old[0])).fetchone()[0]
                if previous==result_digest:return dict(incident_id=str(incident),revision_id=str(old[0]),generation=generation,reused=True)
            if generation!=expected_generation:raise FoundationError('stale_incident_generation')
            self.c.execute('''INSERT INTO p24_next.incident(namespace_id,incident_id,issue_identity,scope_kind,subject_key,failure_family)
                VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING''',(self.n,incident,identity,scope_kind,subject_key,failure_family))
            self.c.execute('INSERT INTO p24_next.foundation_incident_contract VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING',
                           (self.n,incident,pattern_key,GROUPING))
            execute_many(self.c,'INSERT INTO p24_next.incident_finding VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING',
                         [(self.n,incident,fid,'exact_typed_subject_and_machine_pattern') for fid in incoming])
            revision=stable_id(incident,str(generation+1),result_digest)
            self.c.execute('''INSERT INTO p24_next.foundation_incident_revision(namespace_id,revision_id,incident_id,publication_id,generation,parent_revision_id,input_sha256,result)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s)''',(self.n,revision,incident,p,generation+1,old[0] if old else None,result_digest,jsonb(result)))
            execute_many(self.c,'INSERT INTO p24_next.foundation_incident_revision_finding VALUES(%s,%s,%s,%s)',
                         [(self.n,incident,revision,ref(x['finding_id'])) for x in active])
            if old:
                self.c.execute('UPDATE p24_next.foundation_incident_head SET revision_id=%s,generation=%s WHERE namespace_id=%s AND incident_id=%s',
                               (revision,generation+1,self.n,incident))
            else:
                self.c.execute('INSERT INTO p24_next.foundation_incident_head VALUES(%s,%s,%s,%s)',(self.n,incident,revision,1))
        return dict(incident_id=str(incident),revision_id=str(revision),generation=generation+1,reused=False)

    def _authorize(self,action,resource,token):
        _,principal=self.store._authorize_access(action,'incident',str(resource),token)
        return principal

    def _review(self,contract,now=None):
        kind,subject,pattern,_,_=contract;now=now or self.clock()
        rows=self.c.execute('''SELECT d.verdict,d.expires_at,d.decision_id,h.pattern_key,h.generation,d.effective_from
            FROM p24_next.foundation_review_head h JOIN p24_next.operator_decision d USING(namespace_id,decision_id)
            WHERE h.namespace_id=%s AND h.subject_kind=%s AND h.subject_key=%s AND h.pattern_key=ANY(%s)''',
            (self.n,kind,subject,[pattern,'*'])).fetchall()
        valid=[r for r in rows if r[0]!='undo' and r[5]<=now and (r[1] is None or now<r[1])]
        chosen=next((r for r in valid if r[3]==pattern),next(iter(valid),None))
        return dict(verdict=chosen[0] if chosen else 'unmarked',visibility='reviewed' if chosen and chosen[0] in {'benign','false_positive'} else 'active',
                    decision_id=str(chosen[2]) if chosen else None,scope='pattern' if chosen and chosen[3]==pattern else 'subject' if chosen else None,
                    evaluated_at=now.isoformat(),detectors_retrained=False,priority_changed=False)

    def read(self,publication_id,incident_id,*,revision_id=None,access_token=None):
        principal=self._authorize('read_incidents',incident_id,access_token)
        p=self.pub._header(publication_id)['publication_id'];incident=ref(incident_id)
        contract=self._contract(incident)
        if revision_id:
            row=self.c.execute('''SELECT revision_id,generation,result,input_sha256 FROM p24_next.foundation_incident_revision
                WHERE namespace_id=%s AND incident_id=%s AND publication_id=%s AND revision_id=%s''',
                (self.n,incident,p,ref(revision_id))).fetchone()
        else:
            row=self.c.execute('''SELECT revision_id,generation,result,input_sha256 FROM p24_next.foundation_incident_revision
                WHERE namespace_id=%s AND incident_id=%s AND publication_id=%s ORDER BY generation DESC LIMIT 1''',(self.n,incident,p)).fetchone()
        if row is None:raise FoundationError('incident_revision_not_available')
        if digest(row[2])!=row[3]:raise FoundationError('incident_result_digest_mismatch')
        self.pub._audit(p,'publication',self.store.keys.token(self.store.namespace,'incident_resource',str(incident)),principal)
        return dict(incident_id=str(incident),revision_id=str(row[0]),generation=row[1],result=row[2],review=self._review(contract),
                    review_scope='current operator policy; evidence revision remains pinned')

    def revision_status(self,incident_id,revision_id,*,access_token=None):
        """Tell whether a pinned incident revision is still the latest revision."""
        incident=ref(incident_id);revision=ref(revision_id)
        self._authorize('read_incidents',incident,access_token)
        row=self.c.execute("SELECT revision_id,generation FROM p24_next.foundation_incident_head WHERE namespace_id=%s AND incident_id=%s",
                           (self.n,incident)).fetchone()
        if row is None:raise FoundationError('incident_not_available')
        return dict(incident_id=str(incident),revision_id=str(revision),latest_revision_id=str(row[0]),
                    latest_generation=row[1],is_latest=row[0]==revision)

    def list(self,publication_id,*,limit=25,cursor=None,access_token=None):
        checked_limit(limit);principal=self._authorize('read_incidents',publication_id,access_token)
        with self.c.transaction():
            self.store._lock()
            p=self.pub._header(publication_id)['publication_id']
            position=self.pub._read_cursor(cursor,p,VERSION,'incidents')
            if position is None:
                last=None;at=self.c.execute('SELECT clock_timestamp()').fetchone()[0]
            else:
                try:
                    last=ref(position['after']);at=parse_time(position['as_of']).floor
                except (KeyError,TypeError,FoundationError):raise FoundationError('invalid_page_cursor') from None
            rows=self.c.execute('''SELECT DISTINCT ON(incident_id) incident_id,revision_id,generation,result FROM p24_next.foundation_incident_revision
                WHERE namespace_id=%s AND publication_id=%s AND created_at<=%s AND (%s::uuid IS NULL OR incident_id>%s::uuid)
                ORDER BY incident_id,generation DESC LIMIT %s''',(self.n,p,at,last,last,limit+1)).fetchall()
            items=[dict(incident_id=str(i),revision_id=str(r),generation=g,result={k:v for k,v in result.items()
                        if k not in {'requests','request_support','active_findings','excluded_findings','occurrences'}},
                        review=self._review(self._contract(i))) for i,r,g,result in rows[:limit]]
            following=self.pub._cursor(p,VERSION,'incidents',dict(after=str(rows[limit-1][0]),as_of=at.isoformat())) if len(rows)>limit else None
            self.pub._audit(p,'publication',self.store.keys.token(self.store.namespace,'incident_list',str(p)),principal)
        return dict(publication_id=str(p),items=items,next_cursor=following,listing_at=at.isoformat(),
                    coverage='incident revisions explicitly built for this publication; evidence list frozen at listing time; operator policy is current')

    def evidence(self,publication_id,incident_id,*,revision_id=None,limit=25,cursor=None,access_token=None):
        checked_limit(limit)
        saved=self.read(publication_id,incident_id,revision_id=revision_id,access_token=access_token)
        p=ref(publication_id);revision=saved['revision_id']
        last=self.pub._read_cursor(cursor,p,VERSION,'incident_requests:'+revision)
        if last is not None and (not isinstance(last,str) or not TOKEN.fullmatch(last)):raise FoundationError('invalid_page_cursor')
        rows=[row for row in saved['result']['requests'] if last is None or row['request_key']>last]
        following=self.pub._cursor(p,VERSION,'incident_requests:'+revision,rows[limit-1]['request_key']) if len(rows)>limit else None
        return dict(publication_id=str(p),revision_id=revision,total=saved['result']['distinct_supported_requests'],items=rows[:limit],next_cursor=following)

    def _scope(self,incident,scope):
        if scope not in {'pattern','subject'}:raise FoundationError('invalid_review_scope')
        contract=self._contract(incident);kind,subject,pattern,_,_=contract
        return contract,pattern if scope=='pattern' else '*'

    def _preview(self,incident,scope,now):
        contract,pattern=self._scope(incident,scope);kind,subject,_,_,_=contract
        head=self.c.execute('SELECT generation,decision_id FROM p24_next.foundation_review_head WHERE namespace_id=%s AND subject_kind=%s AND subject_key=%s AND pattern_key=%s',
                            (self.n,kind,subject,pattern)).fetchone()
        rows=self.c.execute('''SELECT i.incident_id,h.generation,h.revision_id FROM p24_next.incident i
            JOIN p24_next.foundation_incident_contract c USING(namespace_id,incident_id)
            JOIN p24_next.foundation_incident_head h USING(namespace_id,incident_id)
            WHERE i.namespace_id=%s AND i.scope_kind=%s AND i.subject_key=%s AND (%s='*' OR c.pattern_key=%s)
            ORDER BY i.incident_id LIMIT %s''',(self.n,kind,subject,pattern,pattern,MAX_FINDINGS+1)).fetchall()
        if len(rows)>MAX_FINDINGS:raise FoundationError('review_scope_limit')
        payload=dict(version=VERSION,scope=scope,subject_kind=kind,subject_key=subject,pattern_key=pattern,
                     generation=head[0] if head else 0,decision_id=str(head[1]) if head else None,
                     affected=[dict(incident_id=str(i),generation=g,revision_id=str(r),
                        effective_policy={k:v for k,v in self._review(self._contract(i),now).items() if k in {'decision_id','verdict','visibility'}}) for i,g,r in rows])
        return dict(payload,preview_sha256=digest(payload),affected_records=len(rows),current=self._review(contract,now))

    def preview(self,incident_id,*,scope='pattern',access_token=None):
        self._authorize('review_incidents',incident_id,access_token)
        with self.c.transaction():
            self.store._lock()
            return self._preview(ref(incident_id),scope,self.clock())

    def decide(self,incident_id,*,scope,verdict,reason_key,preview_sha256,command_id,expires_at=None,access_token=None):
        principal=self._authorize('review_incidents',incident_id,access_token)
        if verdict not in {'confirmed','benign','false_positive','undo'} or reason_key not in REASONS:
            raise FoundationError('invalid_review_decision')
        incident=ref(incident_id);command=ref(command_id);now=self.clock()
        expiry=parse_time(expires_at).floor if expires_at is not None else None
        request_hash=digest([str(incident),scope,verdict,reason_key,preview_sha256,expires_at,principal])
        with self.c.transaction():
            self.store._lock()
            prior=self.c.execute('SELECT decision_id,request_sha256 FROM p24_next.foundation_review_receipt WHERE namespace_id=%s AND command_id=%s',
                                 (self.n,command)).fetchone()
            if prior:
                if prior[1]!=request_hash:raise FoundationError('review_command_conflict')
                return dict(decision_id=str(prior[0]),reused=True)
            if expiry is not None and expiry<=now:raise FoundationError('review_expiry_must_be_future')
            preview=self._preview(incident,scope,now)
            if preview_sha256!=preview['preview_sha256']:raise FoundationError('stale_review_preview')
            if verdict=='undo' and preview['decision_id'] is None:raise FoundationError('no_review_to_undo')
            decision=stable_id(self.store.namespace,'review_command',str(command))
            self.c.execute('''INSERT INTO p24_next.operator_decision(namespace_id,decision_id,incident_id,subject_kind,subject_key,pattern_key,
                verdict,scope_contract,reason,actor_key,taxonomy_compatibility,effective_from,expires_at,supersedes_decision_id)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                (self.n,decision,incident,preview['subject_kind'],preview['subject_key'],preview['pattern_key'],verdict,
                 jsonb(dict(version=VERSION,scope=scope,preview_sha256=preview_sha256,precedence='active narrow overrides active broad; undo/expiry removes that scope only')),
                 reason_key,principal,VERSION,now,expiry,ref(preview['decision_id']) if preview['decision_id'] else None))
            if preview['generation']:
                self.c.execute('''UPDATE p24_next.foundation_review_head SET generation=%s,decision_id=%s
                    WHERE namespace_id=%s AND subject_kind=%s AND subject_key=%s AND pattern_key=%s''',
                    (preview['generation']+1,decision,self.n,preview['subject_kind'],preview['subject_key'],preview['pattern_key']))
            else:
                self.c.execute('INSERT INTO p24_next.foundation_review_head VALUES(%s,%s,%s,%s,1,%s)',
                    (self.n,preview['subject_kind'],preview['subject_key'],preview['pattern_key'],decision))
            self.c.execute('INSERT INTO p24_next.foundation_review_receipt VALUES(%s,%s,%s,%s)',(self.n,command,decision,request_hash))
        return dict(decision_id=str(decision),reused=False)
