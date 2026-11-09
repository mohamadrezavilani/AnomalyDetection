"""Atomic, one-time reclassification of retained Viewer projections only."""
from __future__ import annotations
from datetime import datetime,timezone
import uuid
from .viewer_service_catalog import catalog_fingerprint,role_proposal


class ServiceCatalogSyncMixin:
    def service_catalog_status(self):
        from .viewer_data import OWNER_CONFIRMED,CANDIDATE_ROLES
        target=catalog_fingerprint(OWNER_CONFIRMED,CANDIDATE_ROLES)
        self.sql('SAVEPOINT catalog_status_probe')
        try:row=self.one('SELECT * FROM viewer_service_catalog_state WHERE id=1')
        except Exception as exc:
            self.sql('ROLLBACK TO SAVEPOINT catalog_status_probe');self.sql('RELEASE SAVEPOINT catalog_status_probe')
            if type(exc).__name__=='UndefinedTable' or (type(exc).__name__=='OperationalError' and 'no such table' in str(exc).lower()):row=None
            else:raise
        else:self.sql('RELEASE SAVEPOINT catalog_status_probe')
        return dict(status='CURRENT' if row and row['fingerprint']==target else 'UPDATE_PENDING',
                    target_fingerprint=target,last_sync=row)

    def sync_service_catalog(self,*,commit=True,fault=None):
        from .viewer_data import OWNER_CONFIRMED,CANDIDATE_ROLES,initial_service_role,service_path
        from .service_dispatch import TRANSPORT,PREFIX
        target=catalog_fingerprint(OWNER_CONFIRMED,CANDIDATE_ROLES)
        def stage(name,**counts):
            self.progress(name,**counts)
            if fault:fault(name)
        try:
            stage('catalog_sync',phase='waiting_for_writer')
            self.write_lock()
            self.sql('''CREATE TABLE IF NOT EXISTS viewer_service_catalog_state(
                id INTEGER PRIMARY KEY CHECK(id=1),fingerprint TEXT NOT NULL,
                updated_at TEXT NOT NULL,changed_paths INTEGER NOT NULL,
                changed_requests INTEGER NOT NULL,semantic_changes INTEGER NOT NULL)''')
            existing=self.one('SELECT * FROM viewer_service_catalog_state WHERE id=1')
            if existing and existing['fingerprint']==target:
                if commit:self.conn.commit()
                return dict(status='CURRENT',changed_paths=0,changed_requests=0,semantic_changes=0)
            stage('catalog_sync',phase='roles')
            before={row['service_path']:row for row in self.all('SELECT * FROM viewer_service_roles')}
            calls=[row['root_call'] for row in self.all('SELECT DISTINCT root_call FROM viewer_requests WHERE root_call IS NOT NULL')]
            paths=set(before)|{service_path(call) for call in calls}
            self.ensure_service_roles(paths=paths)
            now=datetime.now(timezone.utc).isoformat();changes=[];history=[]
            for path in sorted(paths):
                old=before.get(path)
                if old and (old['reviewed'] or old['source']=='operator'):continue
                role,initiation,source=initial_service_role(path)
                if role=='unknown':continue
                if old is not None and (old['role'],old['initiation'],old['source'])==(role,initiation,source):continue
                changes.append((role,initiation,source,now,path))
                if old is not None and (old['role'],old['initiation'])!=(role,initiation):
                    history.append((uuid.uuid4().hex,path,old['role'],role,old['initiation'],initiation,
                                    'source_catalog_sync:'+target[:16],now))
            self.many('UPDATE viewer_service_roles SET role=?,initiation=?,source=?,changed_at=? WHERE service_path=?',changes)
            self.many('INSERT INTO viewer_service_role_history VALUES(?,?,?,?,?,?,?,?)',history)
            stage('catalog_sync_after_roles',changed_paths=len(changes))
            roles={row['service_path']:row for row in self.all('SELECT * FROM viewer_service_roles')}
            self.sql('''CREATE TEMP TABLE IF NOT EXISTS viewer_catalog_routes(
                root_call TEXT PRIMARY KEY,category TEXT NOT NULL,initiation TEXT NOT NULL,
                reviewed INTEGER NOT NULL,semantic_role TEXT)''')
            self.sql('DELETE FROM viewer_catalog_routes')
            mapping=[]
            for call in calls:
                path=service_path(call);row=roles[path];proposal=role_proposal(path) or {}
                # InvoiceRegister is the HTTP transport, not the selected
                # service's role. Its actions are reconciled from fenced,
                # same-request dispatch facts below, including OTP phases.
                if path==TRANSPORT:continue
                mapping.append((call,row['role'],row['initiation'],int(bool(row['reviewed'] or row['source']=='operator')),proposal.get('semantic_role')))
            self.many('INSERT INTO viewer_catalog_routes VALUES(?,?,?,?,?)',mapping)
            if not self.sqlite:self.sql('ANALYZE viewer_catalog_routes')
            self.sql('''CREATE TEMP TABLE IF NOT EXISTS viewer_catalog_actions(
                action_key TEXT PRIMARY KEY,request_key TEXT NOT NULL,
                category TEXT NOT NULL,initiation TEXT NOT NULL)''')
            self.sql('DELETE FROM viewer_catalog_actions')
            self.sql('''CREATE TEMP TABLE IF NOT EXISTS viewer_catalog_requests(
                request_key TEXT PRIMARY KEY,category TEXT NOT NULL,initiation TEXT NOT NULL)''')
            self.sql('DELETE FROM viewer_catalog_requests')
            checkpoint=self.semantic_checkpoint()
            force_semantic=(' OR EXISTS (SELECT 1 FROM viewer_semantic_occurrences s WHERE s.request_key=r.request_key '+
                "AND s.state='active' AND (m.semantic_role IS NOT NULL OR (m.reviewed=1 AND m.category='unknown')))" if checkpoint else '')
            stage('catalog_sync',phase='selecting_affected_actions')
            self.sql('''INSERT INTO viewer_catalog_actions
                SELECT a.action_key,r.request_key,m.category,m.initiation
                FROM viewer_requests r JOIN viewer_catalog_routes m ON m.root_call=r.root_call
                JOIN viewer_actions a ON a.root_request_key=r.request_key
                WHERE a.category<>m.category OR a.initiation<>m.initiation'''+force_semantic)
            if not self.sqlite:self.sql('ANALYZE viewer_catalog_actions')
            self.sql('''INSERT INTO viewer_catalog_requests
                SELECT DISTINCT request_key,category,initiation FROM viewer_catalog_actions''')
            if not self.sqlite:self.sql('ANALYZE viewer_catalog_requests')
            changed_requests=self.one('SELECT COUNT(*) AS n FROM viewer_catalog_requests')['n']
            stage('catalog_sync',phase='updating_changed_actions',affected_requests=changed_requests)
            changed_actions=self.sql('''UPDATE viewer_actions AS a
                SET category=c.category,initiation=c.initiation
                FROM viewer_catalog_actions AS c
                WHERE a.action_key=c.action_key AND a.root_request_key=c.request_key
                  AND (a.category<>c.category OR a.initiation<>c.initiation)''').rowcount
            stage('catalog_sync_after_actions',changed_requests=changed_requests,changed_actions=changed_actions)
            dispatch_keys=set()
            for change in changes:
                dispatch_keys.update(self.dispatched_request_keys(change[4]))
            # Repair retained selected-service actions if an earlier generic
            # transport sync overwrote them. This only selects candidates;
            # reconcile_service_dispatches revalidates their origin versions,
            # access/service facts and prerequisite/result phase before writing.
            transport_calls=[call for call in calls if service_path(call)==TRANSPORT]
            if transport_calls:
                dispatch_keys.update(row['request_key'] for row in self.all('''
                    SELECT r.request_key FROM viewer_requests r
                    JOIN viewer_actions a ON a.action_key=r.request_key
                    JOIN viewer_service_roles m ON m.service_path=a.label
                    WHERE r.root_call IN ('''+','.join('?' for _ in transport_calls)+''')
                      AND (a.category<>m.role OR a.initiation<>m.initiation)
                      AND (m.role<>'business' OR EXISTS
                        (SELECT 1 FROM viewer_contract_observations o
                         WHERE o.request_key=r.request_key AND o.axis=?))''',
                    transport_calls+[PREFIX+'inquiry_result']))
            stage('catalog_sync',phase='reconciling_selected_services',affected_requests=len(dispatch_keys))
            if dispatch_keys:self.reconcile_service_dispatches(dispatch_keys)
            semantic_changes=0
            if checkpoint:
                keys=[row['request_key'] for row in self.all('''SELECT c.request_key FROM viewer_catalog_requests c
                    WHERE c.category IN ('business','user_management') OR EXISTS
                    (SELECT 1 FROM viewer_semantic_occurrences s WHERE s.request_key=c.request_key)''')]
                keys=sorted(set(keys)|dispatch_keys)
                if keys:semantic_changes=self.reconcile_semantic_requests(keys,commit=False)['changed']
            stage('catalog_sync_after_semantics',semantic_changes=semantic_changes)
            self.sql('''INSERT INTO viewer_service_catalog_state VALUES(1,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET fingerprint=excluded.fingerprint,updated_at=excluded.updated_at,
                changed_paths=excluded.changed_paths,changed_requests=excluded.changed_requests,semantic_changes=excluded.semantic_changes''',
                (target,now,len(changes),changed_requests,semantic_changes))
            stage('catalog_sync_before_commit')
            if commit:self.conn.commit()
            return dict(status='UPDATED',changed_paths=len(changes),changed_requests=changed_requests,
                        changed_actions=changed_actions,dispatch_requests=len(dispatch_keys),
                        semantic_changes=semantic_changes,live_capture_cursor_unchanged=True)
        except BaseException:
            self.conn.rollback();raise
