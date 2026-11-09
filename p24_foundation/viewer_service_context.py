"""Bounded service context; transport, RequestID and OTP attempts stay separate."""
from collections import defaultdict
from .service_dispatch import PREFIX,TRANSPORT,api_path,dispatch_catalog
from .viewer_service_catalog import role_proposal

AXES=tuple(PREFIX+x for x in ('access','invoice_request','inquiry_result','otp_request',
    'otp_required','otp_validation','under_covered'))
FACT_LIMIT=128


class ServiceContextMixin:
    def dispatched_request_keys(self,service):
        from .viewer_contract import typed_id
        identity=typed_id('pishkhan24','dispatcher_service',service.rsplit('/',1)[-1],scope=service)
        return [r['request_key'] for r in self.all('''SELECT DISTINCT c.request_key FROM viewer_contract_identifiers c
            JOIN viewer_requests r ON r.request_key=c.request_key
            WHERE c.identity_key=? AND c.kind='dispatcher_service'
              AND (r.root_call=? OR r.root_call LIKE ?)
              AND (SELECT COUNT(*) FROM viewer_events v WHERE v.origin_key=c.origin_key)=1
              AND (SELECT COUNT(*) FROM viewer_events v WHERE v.origin_key=c.origin_key AND v.version_key=c.version_key)=1''',
            (identity,TRANSPORT,TRANSPORT+' Line:%'))]

    def service_contexts(self,request_keys,*,roles=None):
        keys=sorted(set(request_keys));result={}
        for begin in range(0,len(keys),200):
            batch=keys[begin:begin+200]
            if not batch:continue
            marks=','.join('?' for _ in batch)
            roots=self.all('SELECT request_key,root_call,root_code,root_ns,ended_ns,conflicted FROM viewer_requests WHERE request_key IN ('+marks+')',batch)
            candidates={r['request_key']:r for r in roots if api_path(r['root_call'])==TRANSPORT}
            if not candidates:continue
            if roles is None:roles={r['service_path']:r for r in self.all('SELECT * FROM viewer_service_roles')}
            ids=sorted(candidates);marks=','.join('?' for _ in ids)
            facts=self.all('''SELECT o.* FROM viewer_contract_observations o
                WHERE o.request_key IN ('''+marks+') AND o.axis IN ('+','.join('?' for _ in AXES)+''')
                  AND (SELECT COUNT(*) FROM viewer_events v WHERE v.origin_key=o.origin_key)=1
                  AND (SELECT COUNT(*) FROM viewer_events v WHERE v.origin_key=o.origin_key AND v.version_key=o.version_key)=1
                ORDER BY o.request_key,o.at_ns,o.origin_key,o.axis LIMIT ?''',ids+list(AXES)+[len(ids)*FACT_LIMIT+1])
            by_request=defaultdict(list)
            for f in facts:by_request[f['request_key']].append(f)
            capped=len(facts)>len(ids)*FACT_LIMIT
            for key,root in candidates.items():
                rows=by_request[key]
                if root['conflicted'] or capped or len(rows)>FACT_LIMIT:continue
                def values(axis):return {r['value'] for r in rows if r['axis']==PREFIX+axis}
                services=values('access');service_ids=values('invoice_request')
                if len(services)!=1 or len(service_ids)!=1:continue
                service=next(iter(services))
                if service not in dispatch_catalog()['routes']:continue
                role=roles.get(service)
                if role is None or (role['role']=='unknown' and not role.get('reviewed') and role.get('source')=='unclassified'):
                    proposal=role_proposal(service) or {}
                    role=dict(role=proposal.get('role','unknown'),initiation=proposal.get('initiation','unknown'),
                              reviewed=0,source='source_backed')
                reports=values('inquiry_result');by_event=defaultdict(dict)
                for f in rows:by_event[(f['origin_key'],f['version_key'])][f['axis']]=f['value']
                required={e[PREFIX+'otp_required'] for e in by_event.values()
                          if e.get(PREFIX+'otp_request')=='G00000' and PREFIX+'otp_required' in e}
                validations=values('otp_validation');under=values('under_covered')
                phase=('inquiry_result_reported' if reports else
                       'prerequisite_conflict' if len(required)>1 or len(validations)>1 else
                       'selection_pending' if under=={'G00000'} else
                       'otp_verified_result_pending' if validations=={'G00000'} else
                       'otp_verification_failed' if validations else
                       'otp_required' if required=={'true'} else
                       'otp_not_required_result_pending' if required=={'false'} else 'service_stage_unknown')
                category=role['role']
                if category=='business' and phase!='inquiry_result_reported':category='support'
                code=next(iter(reports)) if len(reports)==1 else None
                result[key]=dict(service_path=service,service_id=next(iter(service_ids)),
                    transport_api=TRANSPORT,transport_status_code=root['root_code'],phase=phase,result_code=code,
                    result_conflicting=len(reports)>1,category=category,service_role=role['role'],
                    initiation=role['initiation'],role_reviewed=bool(role.get('reviewed') or role.get('source')=='operator'),
                    authority='source_dispatch_switch_and_same_request_sql_action',
                    otp_required_values=sorted(required),otp_validation_codes=sorted(validations),
                    inquiry_result_codes=sorted(reports),cross_request_otp_link='NOT_ESTABLISHED',
                    evidence=[dict(origin_key=f['origin_key'],version_key=f['version_key'],
                        callpath=f['callpath'],at_ns=f['at_ns'],axis=f['axis'].removeprefix(PREFIX),
                        value=f['value'],field_path=f['field_path']) for f in rows])
        return result

    def apply_service_contexts(self,rows):
        """Overlay in memory; the actual HTTP transport stays in retained rows."""
        candidates=[r for r in rows if api_path(r.get('root_call'))==TRANSPORT]
        if not candidates:return rows
        contexts=self.service_contexts([r.get('request_key') or r.get('root_request_key') or r.get('action_key') for r in candidates])
        for row in candidates:
            key=row.get('request_key') or row.get('root_request_key') or row.get('action_key')
            context=contexts.get(key)
            if context:
                row['transport_root_call']=row['root_call'];row['service_context']=context
                row['root_call']=context['service_path'];row['service_result_code']=context['result_code']
                row['category']=context['category'];row['initiation']=context['initiation']
                row['role_reviewed']=context['role_reviewed']
        return rows

    def reconcile_service_dispatches(self,request_keys=None):
        """Derived actions only; the caller owns commit/rollback and write lock."""
        from .viewer_data import core_name
        count=0
        roles=None
        if request_keys is not None:
            keys=sorted(set(request_keys));batches=[keys[i:i+200] for i in range(0,len(keys),200)]
        else:
            statement='SELECT request_key FROM viewer_requests WHERE root_call=? OR root_call LIKE ? ORDER BY request_key'
            params=(TRANSPORT,TRANSPORT+' Line:%')
            if not self.sqlite and callable(getattr(self.conn,'pipeline',None)):
                import uuid
                cursor=self.conn.cursor(name='viewer_dispatch_'+uuid.uuid4().hex)
                cursor.execute(statement.replace('?',self.param),params)
            else:cursor=self.sql(statement,params)
            def stream():
                try:
                    while True:
                        rows=cursor.fetchmany(200)
                        if not rows:return
                        yield [r['request_key'] for r in rows]
                finally:cursor.close()
            batches=stream()
        for batch in batches:
            if not batch:continue
            marks=','.join('?' for _ in batch)
            actions=self.all('''SELECT a.*,r.root_call,r.root_code FROM viewer_actions a JOIN viewer_requests r
                ON r.request_key=a.action_key WHERE a.action_key IN ('''+marks+')',batch)
            candidates=[r['action_key'] for r in actions if api_path(r['root_call'])==TRANSPORT]
            if not candidates:continue
            if roles is None:roles={r['service_path']:r for r in self.all('SELECT * FROM viewer_service_roles')}
            contexts=self.service_contexts(candidates,roles=roles)
            self.ensure_service_roles({c['service_path'] for c in contexts.values()})
            updates=[]
            for row in actions:
                if api_path(row['root_call'])!=TRANSPORT:continue
                c=contexts.get(row['action_key'])
                if c:
                    outcome=('unknown' if c['result_code'] is None or c['transport_status_code'] is None else
                             'success' if c['result_code']=='G00000' and c['transport_status_code']=='G00000' else 'failure')
                    values=(c['service_path'],core_name(c['service_path']),c['category'],c['initiation'],outcome)
                else:
                    values=('InvoiceRegister','InvoiceRegister','support','confirmed_automatic',
                            'unknown' if not row['root_code'] else 'success' if row['root_code']=='G00000' else 'failure')
                if values!=tuple(row[k] for k in ('label','name','category','initiation','current_outcome')):
                    updates.append((*values,row['action_key']))
            self.many('UPDATE viewer_actions SET label=?,name=?,category=?,initiation=?,current_outcome=? WHERE action_key=?',updates)
            count+=len(updates)
        return dict(actions_changed=count)

    def service_context_card(self,request_key):
        return self.service_contexts([request_key]).get(request_key)
