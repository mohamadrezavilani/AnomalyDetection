"""Versioned investigation read models over immutable observed publications.

No detector, parser, source record or sealed projection is changed. SessionID
is the platform continuity key; a conflicting RequestID remains review context
and is never silently assigned to one of its candidate Sessions.
"""
from collections import Counter

from .errors import FoundationError
from .publication import ObservationPublisher, checked_limit
from .lifecycle import request_lifecycle

VIEW_VERSION = "p24-investigation.2r.1"
UNKNOWN_TIME = "999999999999999999999999999999"
OUTCOME_GROUPS = {
    ("client_http", "platform_log"): "client_log",
    ("sql", "sql_result"): "sql_execution",
    ("provider", "platform_log"): "provider_log",
    ("provider", "provider_http_envelope"): "provider_transport",
    ("provider", "provider_body"): "provider_application",
}
LABELS_FA = {
    "client_log": "نتیجهٔ ثبت‌شدهٔ درخواست کلاینت",
    "sql_execution": "نتیجهٔ اجرای SQL",
    "provider_log": "نتیجهٔ ثبت‌شده در لاگ عملیات سرویس‌دهنده",
    "provider_transport": "وضعیت HTTP سرویس‌دهنده",
    "provider_application": "نتیجه در بدنهٔ پاسخ سرویس‌دهنده",
    "workflow_stage": "نتیجهٔ مرحلهٔ فرایند",
    "unclassified": "نتیجه با دامنهٔ نامشخص",
}
PHASE_LABELS_FA = {
    "session_establishment": "درخواست ایجاد نشست",
    "otp_generation": "درخواست تولید رمز یک‌بارمصرف",
    "otp_verification": "درخواست بررسی رمز یک‌بارمصرف",
    "credential_authentication": "درخواست ورود با اطلاعات کاربری",
    "application_support": "پشتیبانی برنامه",
    "direct_inquiry": "فراخوانی مستقیم استعلام",
    "context_dependent": "مرحله نیازمند بررسی",
    "unknown": "مرحلهٔ نامشخص",
}
def outcome_group(observation):
    if observation.get("layer") == "workflow_body":
        return "workflow_stage"
    return OUTCOME_GROUPS.get((observation.get("role"),observation.get("layer")),"unclassified")


def scoped_outcome(observation):
    """Keep meanings and code bindings separate; do not infer new meanings."""
    fields=("code","path","layer","role","outcome","meaning_fa","validation")
    result={name:observation.get(name) for name in fields}
    source=observation.get("meaning_source")
    result["meaning_source"]={k:source.get(k) for k in ("entry_id","source_sha256")} if isinstance(source,dict) else None
    result["interpretation_state"]=observation.get("interpretation_state","legacy_unscoped")
    result["resolver_version"]=observation.get("resolver_version")
    rule=observation.get("applied_rule")
    result["applied_rule"]={k:rule.get(k) for k in ("id","revision","evidence_ref")} if isinstance(rule,dict) else None
    result["meaning_candidates"]=[{k:row.get(k) for k in (
        "entry_id","code_system","source_file","source_sha256","definition_state")}
        for row in observation.get("meaning_candidates",[])[:20] if isinstance(row,dict)]
    result["meaning_candidate_count"]=len(observation.get("meaning_candidates",[]))
    group=outcome_group(observation)
    return dict(result,group=group,label_fa=LABELS_FA[group])


def request_card(summary, *, projection_run_id=None, identity_scope="assigned"):
    """A small card; operation bodies are expanded through the paginated API."""
    classification=summary.get("classification") or {}
    phase=classification.get("phase","unknown")
    observed=Counter(outcome_group(row.get("observation",{})) for row in summary.get("outcomes",[]))
    return dict(
        view_version=VIEW_VERSION,projection_run_id=projection_run_id,request_key=summary["request_key"],
        identity_scope=identity_scope,identity_state=summary["identity_state"],session_key=summary.get("session_key"),
        endpoint=summary.get("endpoint"),phase=phase,phase_label_fa=PHASE_LABELS_FA.get(phase,PHASE_LABELS_FA["unknown"]),
        activity_group=classification.get("activity_group","unknown"),classification_state=classification.get("state","unknown"),
        access_check_context=dict(actions=list(summary.get("access_check_actions",[])),
                                  sql_observations=int(summary.get("access_check_action_observations",0)),
                                  omitted_distinct=int(summary.get("access_check_action_omitted_distinct",0)),
                                  meaning="observed_access_check_parameter; not_verified_service_mapping_or_execution"),
        security_relevant=bool(classification.get("security_relevant",False)),initiation=summary.get("initiation","unknown"),
        first_time_ns=summary.get("first_time_ns"),last_time_ns=summary.get("last_time_ns"),activity_time_ns=summary.get("activity_time_ns"),
        client_result=dict(completion_state=summary["client_completion_state"],outcome=summary["final_outcome"],
                           code=summary.get("outcome_code"),duration_ms=summary.get("client_duration_ms"),duration_unit="ms"),
        counts=dict(client_http_requests=summary["distinct_client_request_count"],selected_log_events=summary["selected_event_count"],
                    sql_observations=summary["sql_observation_count"],provider_observations=summary["provider_observation_count"],
                    conflicting_origin_events=summary.get("ambiguous_event_count",0),outcome_observations_by_scope=dict(sorted(observed.items()))),
        network_context=dict(ip_keys=list(summary.get("ip_keys",[])),reported_client_context_keys=list(summary.get("client_contexts",[]))),
        lifecycle=request_lifecycle(summary),
        order_basis="source timestamps; equal timestamps do not establish causal order",
        evidence_scope="immutable observed projection; request, SQL and provider counts use different units")


def operation_card(item):
    retained=item.get("descriptor") or {}
    descriptor=retained.get("descriptor",retained)
    is_access_check=((item.get("role") or item.get("source_role"))=="sql" and
                     (item.get("endpoint") or "").rsplit(".",1)[-1]=="ud_prc_userSessionHasAccess")
    return dict(origin_key=item["origin_key"],event_version_id=item["event_version_id"],
                selection_state=item["selection_state"],selection_reason=item["selection_reason"],
                time_ns=item.get("source_time_epoch_ns"),timestamp_precision=item.get("timestamp_precision"),
                endpoint=item.get("endpoint"),source_role=item.get("source_role"),event_kind=item.get("event_kind"),
                access_check_action=(descriptor.get("caller_sql_action") if is_access_check else None),
                access_check_action_state=("observed_unverified_context" if is_access_check and descriptor.get("caller_sql_action") else "not_observed" if is_access_check else "not_applicable"),
                duration_ms=descriptor.get("duration_ms"),duration_unit="ms",
                recorded_operation_outcome=descriptor.get("operation_outcome","unknown"),
                outcomes=[scoped_outcome(o) for o in descriptor.get("outcomes",[])],
                output_coverage=descriptor.get("output_coverage","unknown"),issues=list(descriptor.get("issues",[])),
                provenance=item.get("provenance",[]),
                identity=dict(state="conflicting" if descriptor.get("identity_conflict") else "known" if descriptor.get("session_candidates") else "missing",
                              session_candidates=list(descriptor.get("session_candidates",[]))),
                operation_identity="source observation; not necessarily a distinct physical attempt")


class InvestigationReader:
    def __init__(self, store):
        self.store=store
        self.publisher=ObservationPublisher(store)

    def request(self, publication_id, raw_request_id, *, access_token=None):
        result=self.publisher.request(publication_id,raw_request_id,access_token=access_token)
        return dict(publication_id=result["publication_id"],view_version=VIEW_VERSION,
                    item=request_card(result["summary"],projection_run_id=result["projection_run_id"],
                                      identity_scope="request_evidence"))

    def operations(self, publication_id, raw_request_id, *, limit=100,cursor=None,access_token=None):
        # Reuse the evidence cursor: it already binds the publication, request,
        # selected/ambiguous versions, ordering and frozen source provenance.
        page=self.publisher.request_evidence(publication_id,raw_request_id,limit=limit,cursor=cursor,access_token=access_token)
        return self._operation_page(page)

    def request_by_key(self, publication_id, key, *, access_token=None):
        result=self.publisher.request_by_key(publication_id,key,access_token=access_token)
        return dict(publication_id=result['publication_id'],view_version=VIEW_VERSION,
                    item=request_card(result['summary'],projection_run_id=result['projection_run_id'],identity_scope='request_evidence'))

    def operations_by_key(self, publication_id, key, *, limit=100,cursor=None,access_token=None):
        return self._operation_page(self.publisher.request_evidence_by_key(publication_id,key,limit=limit,cursor=cursor,access_token=access_token))

    @staticmethod
    def _operation_page(page):
        return dict(publication_id=page["publication_id"],request_key=page["request_key"],view_version=VIEW_VERSION,
                    total_event_versions=page["total_event_versions"],items=[operation_card(i) for i in page["items"]],
                    next_cursor=page["next_cursor"],coverage=page["evidence_scope"],
                    unit="retained event versions, including explicit ambiguous variants; not HTTP request count")

    def _relevant(self):
        return """WITH relevant AS MATERIALIZED (
            SELECT s.request_key,s.run_id,s.summary,
              coalesce(s.summary->>'identity_state'='known' AND s.summary->>'session_key'=%s,false) AS assigned
            FROM p24_next.foundation_observation_heads(%s,%s) h
            JOIN p24_next.foundation_request_summary s
              ON s.namespace_id=%s AND s.request_key=h.request_key AND s.run_id=h.run_id
            WHERE (s.summary->>'identity_state'='known' AND s.summary->>'session_key'=%s)
               OR (s.summary->>'identity_state'='conflicting' AND s.summary->'session_candidates' ? %s)) """

    def registration_context(self, publication_id, raw_session_id, *, limit=100,cursor=None,access_token=None):
        return self.publisher.candidates(publication_id,session_key=self.store.session_key(raw_session_id),
                                         limit=limit,cursor=cursor,access_token=access_token)

    def _service_groups(self, publication):
        # Aggregate in PostgreSQL; do not transfer every retained request into
        # the web process. The explicit catalog bound fails rather than losing
        # endpoints silently. NULL is an explicit unknown-endpoint bucket.
        rows=self.store.c.execute("""SELECT s.summary->>'endpoint',count(*),
            sum((s.summary->>'distinct_client_request_count')::int),
            coalesce(sum((s.summary->>'distinct_client_request_count')::int) FILTER(WHERE s.summary->>'final_outcome'='success'),0),
            coalesce(sum((s.summary->>'distinct_client_request_count')::int) FILTER(WHERE s.summary->>'final_outcome'='failure'),0),
            coalesce(sum((s.summary->>'distinct_client_request_count')::int) FILTER(WHERE s.summary->>'final_outcome' NOT IN ('success','failure')),0),
            sum((s.summary->>'sql_observation_count')::int),sum((s.summary->>'provider_observation_count')::int),
            count(DISTINCT s.summary->>'session_key') FILTER(WHERE s.summary->>'identity_state'='known'),
            count(*) FILTER(WHERE s.summary->>'identity_state'='conflicting'),
            count(*) FILTER(WHERE s.summary->>'identity_state'='missing'),
            min((s.summary->>'first_time_ns')::numeric),max((s.summary->>'last_time_ns')::numeric)
            FROM p24_next.foundation_observation_heads(%s,%s) h
            JOIN p24_next.foundation_request_summary s ON s.namespace_id=%s AND s.request_key=h.request_key AND s.run_id=h.run_id
            GROUP BY s.summary->>'endpoint' LIMIT 10001""",(self.store.namespace_id,publication,self.store.namespace_id)).fetchall()
        if len(rows)>10000:raise FoundationError('service_catalog_limit_requires_narrower_publication')
        return [dict(service_key=self.store.keys.token(self.store.namespace,'service_endpoint',r[0]),endpoint=r[0],
                     request_projections=int(r[1]),client_http_requests=int(r[2]),client_outcomes=dict(success=int(r[3]),failure=int(r[4]),unknown_or_conflicting=int(r[5])),
                     sql_observations=int(r[6]),provider_observations=int(r[7]),known_sessions=int(r[8]),conflicting_identity_requests=int(r[9]),missing_identity_requests=int(r[10]),
                     first_time_ns=str(r[11]) if r[11] is not None else None,last_time_ns=str(r[12]) if r[12] is not None else None,
                     mapping_state='observed_endpoint_only') for r in rows]

    def services(self, publication_id, *, limit=100,cursor=None,access_token=None):
        checked_limit(limit)
        _,principal=self.store._authorize_access('read_requests','requests',['service_catalog',str(publication_id)],access_token)
        p=self.publisher._header(publication_id)['publication_id']
        scope=self.store.keys.token(self.store.namespace,'service_catalog',str(p));kind='service_catalog:'+VIEW_VERSION
        offset=self.publisher._read_cursor(cursor,p,kind,scope)
        if offset is None:offset=0
        if isinstance(offset,bool) or not isinstance(offset,int) or not 0<=offset<=10000:raise FoundationError('invalid_page_cursor')
        groups=sorted(self._service_groups(p),key=lambda g:(g['endpoint'] is not None,g['endpoint'] or ''))
        following=self.publisher._cursor(p,kind,scope,offset+limit) if offset+limit<len(groups) else None
        self.publisher._audit(p,'requests',scope,principal)
        return dict(publication_id=str(p),view_version=VIEW_VERSION,total_endpoints=len(groups),items=groups[offset:offset+limit],next_cursor=following,
                    scope='all retained request projections in pinned publication; observed endpoints, not authoritative business services')

    def service(self, publication_id, key, *, limit=100,cursor=None,access_token=None):
        checked_limit(limit)
        _,principal=self.store._authorize_access('read_requests','requests',['service_endpoint',key],access_token)
        if not isinstance(key,str) or len(key)>200:raise FoundationError('invalid_service_reference')
        p=self.publisher._header(publication_id)['publication_id']
        group=next((g for g in self._service_groups(p) if g['service_key']==key),None)
        if group is None:raise FoundationError('service_not_available')
        kind='service_requests:'+VIEW_VERSION;last=self.publisher._read_cursor(cursor,p,kind,key)
        if last is not None:
            if not isinstance(last,list) or len(last)!=2 or not all(isinstance(v,str) for v in last):raise FoundationError('invalid_page_cursor')
            try:int(last[0])
            except ValueError:raise FoundationError('invalid_page_cursor') from None
        args=[self.store.namespace_id,p,self.store.namespace_id,group['endpoint']]
        at="coalesce((s.summary->>'activity_time_ns')::numeric,"+UNKNOWN_TIME+"::numeric)"
        where=" AND s.summary->>'endpoint' IS NOT DISTINCT FROM %s::text"
        if last is not None:where+=' AND ('+at+',s.request_key)>(%s::numeric,%s)';args.extend(last)
        rows=self.store.c.execute("""SELECT s.request_key,s.run_id,s.summary FROM p24_next.foundation_observation_heads(%s,%s) h
            JOIN p24_next.foundation_request_summary s ON s.namespace_id=%s AND s.request_key=h.request_key AND s.run_id=h.run_id
            WHERE true"""+where+' ORDER BY '+at+',s.request_key LIMIT %s',(*args,limit+1)).fetchall()
        following=None
        if len(rows)>limit:
            tail=rows[limit-1];following=self.publisher._cursor(p,kind,key,[tail[2].get('activity_time_ns') or UNKNOWN_TIME,tail[0]])
        self.publisher._audit(p,'requests',key,principal)
        return dict(publication_id=str(p),view_version=VIEW_VERSION,service=group,
                    items=[request_card(r[2],projection_run_id=str(r[1]),identity_scope='service_context') for r in rows[:limit]],next_cursor=following,
                    scope='exact observed endpoint; SQL/provider counts are supporting observations, not client requests')

    def session(self, publication_id, raw_session_id, *, identity_scope="assigned",limit=100,cursor=None,access_token=None):
        checked_limit(limit)
        if not isinstance(identity_scope,str) or identity_scope not in {"assigned","conflicting"}:
            raise FoundationError("invalid_session_identity_scope")
        # Check permission before looking up the publication or its metadata.
        _,principal=self.store._authorize_access("read_session","session",raw_session_id,access_token)
        session=self.store.session_key(raw_session_id)
        header=self.publisher._header(publication_id);p=header["publication_id"]
        kind="session_journey:"+VIEW_VERSION+":"+identity_scope
        last=self.publisher._read_cursor(cursor,p,kind,session)
        if last is not None:
            if not isinstance(last,list) or len(last)!=2 or not all(isinstance(x,str) for x in last):
                raise FoundationError("invalid_page_cursor")
            try:int(last[0])
            except ValueError:raise FoundationError("invalid_page_cursor") from None
        args=[session,self.store.namespace_id,p,self.store.namespace_id,session,session]
        stats=self.store.c.execute(self._relevant()+"""SELECT
            count(*) FILTER(WHERE assigned),count(*) FILTER(WHERE NOT assigned),
            coalesce(sum((summary->>'distinct_client_request_count')::int) FILTER(WHERE assigned),0),
            coalesce(sum((summary->>'selected_event_count')::int) FILTER(WHERE assigned),0),
            coalesce(sum((summary->>'sql_observation_count')::int) FILTER(WHERE assigned),0),
            coalesce(sum((summary->>'provider_observation_count')::int) FILTER(WHERE assigned),0),
            coalesce(sum((summary->>'distinct_client_request_count')::int) FILTER(WHERE assigned AND summary->>'final_outcome'='success'),0),
            coalesce(sum((summary->>'distinct_client_request_count')::int) FILTER(WHERE assigned AND summary->>'final_outcome'='failure'),0),
            coalesce(sum((summary->>'distinct_client_request_count')::int) FILTER(WHERE assigned AND summary->>'final_outcome' NOT IN ('success','failure')),0),
            min((summary->>'first_time_ns')::numeric) FILTER(WHERE assigned),
            max((summary->>'last_time_ns')::numeric) FILTER(WHERE assigned),
            (SELECT count(DISTINCT ip) FROM relevant r CROSS JOIN LATERAL jsonb_array_elements_text(r.summary->'ip_keys') AS t(ip) WHERE r.assigned),
            count(*) FILTER(WHERE assigned AND summary->'classification'->>'activity_group'='application_support'),
            count(*) FILTER(WHERE assigned AND summary->'classification'->>'activity_group'='security'),
            count(*) FILTER(WHERE assigned AND summary->'classification'->>'activity_group'='business_candidate'),
            count(*) FILTER(WHERE assigned AND coalesce(summary->'classification'->>'activity_group','unknown') NOT IN ('application_support','security','business_candidate'))
            FROM relevant""",args).fetchone()
        where="WHERE assigned" if identity_scope=="assigned" else "WHERE NOT assigned"
        at="coalesce((summary->>'activity_time_ns')::numeric,"+UNKNOWN_TIME+"::numeric)"
        page_args=list(args)
        if last is not None:
            where+=" AND ("+at+",request_key)>(%s::numeric,%s)";page_args.extend(last)
        page_args.append(limit+1)
        rows=self.store.c.execute(self._relevant()+"SELECT request_key,run_id,summary FROM relevant "+where+
                                  " ORDER BY "+at+",request_key LIMIT %s",page_args).fetchall()
        following=None
        if len(rows)>limit:
            tail=rows[limit-1];following=self.publisher._cursor(p,kind,session,[tail[2].get("activity_time_ns") or UNKNOWN_TIME,tail[0]])
        self.publisher._audit(p,"session",session,principal)
        totals=dict(assigned_request_projections=int(stats[0]),conflicting_context_request_projections=int(stats[1]),
                    assigned_client_http_requests=int(stats[2]),assigned_log_events=int(stats[3]),
                    assigned_sql_observations=int(stats[4]),assigned_provider_observations=int(stats[5]),
                    client_http_outcomes=dict(success=int(stats[6]),failure=int(stats[7]),unknown_or_conflicting=int(stats[8])),
                    first_observed_time_ns=str(stats[9]) if stats[9] is not None else None,
                    last_observed_time_ns=str(stats[10]) if stats[10] is not None else None,
                    assigned_distinct_network_sources=int(stats[11]),
                    activity_groups=dict(application_support_request_projections=int(stats[12]),security_request_projections=int(stats[13]),
                                         business_candidate_request_projections=int(stats[14]),unknown_request_projections=int(stats[15])))
        return dict(publication_id=str(p),view_version=VIEW_VERSION,session_key=session,identity_scope=identity_scope,
                    totals=totals,totals_scope="entire pinned Session view; conflicting context excluded from assigned totals",
                    items=[request_card(r[2],projection_run_id=str(r[1]),identity_scope=identity_scope) for r in rows[:limit]],
                    next_cursor=following,has_more=following is not None,
                    event_cutoff_ns=header["input_manifest"]["event_cutoff_ns"],knowledge_at_ns=header["input_manifest"]["knowledge_at_ns"],
                    input_manifest_sha256=header["input_sha256"],request_heads_sha256=header["request_heads_sha256"],
                    lifecycle_coverage="observed request phases and SQL execution; account authentication and logout boundaries are not established",
                    identity_policy="platform Session continuity across IP changes; IP candidates do not assign identity")
