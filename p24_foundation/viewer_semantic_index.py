"""Stable-anchor, revisable semantic read model for isolated Viewer.

This is a materialized read projection, not proof of human actions.
It is explicitly maintained (full bootstrap or affected RequestIDs) and never
silently invents a service relationship from Session, IP, amount or time.
"""
from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from datetime import datetime, timezone

from .service_journey import semantic_execution_kind, source_family, stable_behavior_occurrence_key

SCHEMA_VERSION = 'p24-semantic-index-2'


def anchor_key(request_key):
    """Immutable identity of one evidenced request anchor across late revisions.

    bo1 remains a versioned *classification* identifier: it may change when a
    late HTTP root changes semantic kind. This stable key enables replace and
    withdrawal rather than appending an accidental extra customer execution.
    """
    if not isinstance(request_key, str) or len(request_key) != 64 or any(x not in '0123456789abcdef' for x in request_key):
        raise ValueError('invalid_request_key')
    return 'ba1:' + hashlib.sha256(('p24-anchor-v1:'+request_key).encode()).hexdigest()


class SemanticIndexMixin:
    def init_semantic_index(self,*,commit=True):
        self.write_lock()
        self.sql('''CREATE TABLE IF NOT EXISTS viewer_semantic_occurrences(
          request_key TEXT PRIMARY KEY, anchor_key TEXT NOT NULL UNIQUE,
          session_key TEXT, anchor_ns BIGINT, kind TEXT, occurrence_key TEXT,
          root_call TEXT, root_code TEXT, family_id TEXT, family_label_fa TEXT,
          category TEXT, initiation TEXT, state TEXT NOT NULL,
          revision INTEGER NOT NULL, updated_at TEXT NOT NULL)''')
        self.sql('''CREATE INDEX IF NOT EXISTS vso_session_latest
          ON viewer_semantic_occurrences(session_key,anchor_ns DESC,request_key DESC)''')
        self.sql('''CREATE INDEX IF NOT EXISTS vso_latest
          ON viewer_semantic_occurrences(state,anchor_ns DESC,request_key DESC)''')
        self.sql('''CREATE TABLE IF NOT EXISTS viewer_semantic_transitions(
          request_key TEXT NOT NULL, revision INTEGER NOT NULL,
          old_kind TEXT, new_kind TEXT, old_occurrence_key TEXT,
          new_occurrence_key TEXT, transition TEXT NOT NULL,
          changed_at TEXT NOT NULL, PRIMARY KEY(request_key,revision))''')
        self.sql('''CREATE TABLE IF NOT EXISTS viewer_semantic_checkpoint(
          id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL,
          updated_at TEXT NOT NULL, indexed_requests INTEGER NOT NULL,
          state TEXT NOT NULL)''')
        self.sql('''CREATE TABLE IF NOT EXISTS viewer_semantic_session_heads(
          session_key TEXT PRIMARY KEY,request_key TEXT NOT NULL,anchor_ns BIGINT NOT NULL)''')
        self.sql('''CREATE INDEX IF NOT EXISTS vssh_latest
          ON viewer_semantic_session_heads(anchor_ns DESC,request_key DESC)''')
        if (not self.one('SELECT 1 AS n FROM viewer_semantic_session_heads LIMIT 1') and
            self.one("SELECT 1 AS n FROM viewer_semantic_occurrences WHERE state='active' LIMIT 1")):
            self._refresh_semantic_session_heads()
        if commit:self.conn.commit()

    def _refresh_semantic_session_heads(self,sessions=None):
        """Maintain home summaries inside the same publication/role transaction."""
        condition=''
        if sessions is None:
            self.sql('DELETE FROM viewer_semantic_session_heads')
        else:
            keys=sorted(set(s for s in sessions if s))
            if not keys:return
            self.sql('CREATE TEMP TABLE IF NOT EXISTS viewer_semantic_session_scope(session_key TEXT PRIMARY KEY)')
            self.sql('DELETE FROM viewer_semantic_session_scope')
            self.many('INSERT INTO viewer_semantic_session_scope VALUES (?)',[(key,) for key in keys])
            condition=' AND session_key IN (SELECT session_key FROM viewer_semantic_session_scope)'
            self.sql('DELETE FROM viewer_semantic_session_heads WHERE session_key IN (SELECT session_key FROM viewer_semantic_session_scope)')
            # vso_session_latest already orders each session by these keys.
            # Only its first active occurrence is needed, not a rank/sort of
            # that session's entire retained history on every new behavior.
            if not self.sqlite:
                self.sql('''INSERT INTO viewer_semantic_session_heads(session_key,request_key,anchor_ns)
                    SELECT s.session_key,o.request_key,o.anchor_ns FROM viewer_semantic_session_scope s
                    CROSS JOIN LATERAL (SELECT request_key,anchor_ns FROM viewer_semantic_occurrences
                        WHERE session_key=s.session_key AND state='active'
                        ORDER BY anchor_ns DESC,request_key DESC LIMIT 1) o''')
            else:
                self.sql('''INSERT INTO viewer_semantic_session_heads(session_key,request_key,anchor_ns)
                    SELECT o.session_key,o.request_key,o.anchor_ns FROM viewer_semantic_session_scope s
                    JOIN viewer_semantic_occurrences o ON o.request_key=(SELECT c.request_key
                        FROM viewer_semantic_occurrences c WHERE c.session_key=s.session_key AND c.state='active'
                        ORDER BY c.anchor_ns DESC,c.request_key DESC LIMIT 1)''')
            return
        self.sql('''INSERT INTO viewer_semantic_session_heads(session_key,request_key,anchor_ns)
                SELECT session_key,request_key,anchor_ns FROM (
                  SELECT session_key,request_key,anchor_ns,ROW_NUMBER() OVER (
                    PARTITION BY session_key ORDER BY anchor_ns DESC,request_key DESC) AS nr
                  FROM viewer_semantic_occurrences WHERE state='active' AND session_key IS NOT NULL'''+condition+
                  ''') AS ranked WHERE nr=1''')

    def semantic_checkpoint(self):
        # A SAVEPOINT allows a missing optional table to be probed without
        # aborting the surrounding PostgreSQL transaction (or role update).
        self.sql('SAVEPOINT viewer_semantic_probe')
        try:
            row=self.one('SELECT * FROM viewer_semantic_checkpoint WHERE id=1')
        except Exception as exc:
            self.sql('ROLLBACK TO SAVEPOINT viewer_semantic_probe')
            self.sql('RELEASE SAVEPOINT viewer_semantic_probe')
            name=type(exc).__name__
            if name in ('OperationalError','UndefinedTable') and (
               'no such table' in str(exc).lower() or name=='UndefinedTable'):
                return None
            raise
        else:
            self.sql('RELEASE SAVEPOINT viewer_semantic_probe')
            return row

    def _semantic_candidate(self,row,reviewed_unknowns=()):
        """Exactly the shared Session/ServiceJourney semantic classifier."""
        if not row or row.get('conflicted') or not row.get('session_key'):
            return None
        kind=semantic_execution_kind(row.get('root_call'),row.get('category'),
             product_reservation_observed=bool(row.get('product_reservation')),
             role_reviewed=str(row.get('root_call') or '').split(' Line:',1)[0].strip() in reviewed_unknowns)
        if not kind:return None
        root=row.get('root_call') or 'HTTP root not observed'
        family=source_family(row.get('root_call'))
        return dict(request_key=row['request_key'], anchor_key=anchor_key(row['request_key']),
            session_key=row['session_key'],
            anchor_ns=row.get('anchor_ns') or 0,kind=kind,
            occurrence_key=stable_behavior_occurrence_key(kind,root,row['request_key']),
            root_call=row.get('root_call'),root_code=row.get('root_code'),
            family_id=family.get('family_id'),family_label_fa=family.get('family_label_fa'),
            category=row.get('category'), initiation=row.get('initiation'))

    def _read_semantic_batch(self,after_key='',limit=1000,request_keys=None):
        """Safe bounded lookup; the condition only observes an in-request facet."""
        if request_keys is not None and not request_keys:
            return []
        condition=('r.request_key IN ('+','.join('?' for _ in request_keys)+')'
                   if request_keys is not None else 'r.request_key>?')
        args=list(request_keys) if request_keys is not None else [after_key]
        if request_keys is None:args.append(limit)
        return self.all('''SELECT r.request_key,r.session_key,r.conflicted,r.root_call,r.root_code,
          r.started_ns,r.root_ns,r.ended_ns,
          COALESCE(r.root_ns,r.started_ns,r.ended_ns,0) AS anchor_ns,
          a.category,a.initiation,
          CASE WHEN EXISTS(SELECT 1 FROM viewer_events e
            WHERE e.request_key=r.request_key AND e.callpath LIKE ?)
            THEN 1 ELSE 0 END AS product_reservation
          FROM viewer_requests r LEFT JOIN viewer_actions a ON a.action_key=r.request_key
          WHERE '''+condition+''' ORDER BY r.request_key'''+(' LIMIT ?' if request_keys is None else ''),
          ['ClientAyanCoTopUp.ProductReserve%']+args)

    @contextmanager
    def _semantic_bootstrap_batches(self,batch_size):
        # One query/snapshot for the entire bootstrap. Re-running a joined
        # LIMIT query and refreshing growing session summaries per 750 rows
        # caused increasingly expensive scans on the owner's large history.
        previous_fields=('request_key','session_key','anchor_ns','kind','occurrence_key',
                         'root_call','root_code','category','initiation','state','revision')
        query='''SELECT r.request_key,r.session_key,r.conflicted,r.root_call,r.root_code,
          r.started_ns,r.root_ns,r.ended_ns,
          COALESCE(r.root_ns,r.started_ns,r.ended_ns,0) AS anchor_ns,
          a.category,a.initiation,
          CASE WHEN p.request_key IS NOT NULL THEN 1 ELSE 0 END AS product_reservation,'''+','.join(
              'o.'+field+' AS previous_'+field for field in previous_fields)+'''
          FROM viewer_requests r LEFT JOIN viewer_actions a ON a.action_key=r.request_key
          LEFT JOIN (SELECT DISTINCT request_key FROM viewer_events
                     WHERE callpath LIKE ? AND request_key IS NOT NULL) p
            ON p.request_key=r.request_key
          LEFT JOIN viewer_semantic_occurrences o ON o.request_key=r.request_key
          ORDER BY r.request_key'''
        if not self.sqlite and callable(getattr(self.conn,'pipeline',None)):
            import uuid
            cursor=self.conn.cursor(name='viewer_semantic_'+uuid.uuid4().hex)
            cursor.execute(query.replace('?',self.param),('ClientAyanCoTopUp.ProductReserve%',))
        else:cursor=self.sql(query,('ClientAyanCoTopUp.ProductReserve%',))
        def batches():
            while True:
                batch=cursor.fetchmany(batch_size)
                if not batch:return
                rows=[dict(row) for row in batch]
                previous=[{field:row['previous_'+field] for field in previous_fields}
                          for row in rows if row['previous_request_key'] is not None]
                yield rows,previous
        try:yield batches()
        finally:cursor.close()

    def _write_semantic_batch(self,rows,*,previous=None,refresh_heads=True,session_updates=None,reviewed_unknowns=None):
        """Reconcile by immutable request anchor, never append by mutable bo1.

        All writes remain part of the caller's transaction. A missing or newly
        automatic root withdraws a previous anchor; raw forensic data is kept.
        """
        changed=added=withdrawn=0
        self.apply_service_contexts(rows)
        changed_sessions=set()
        now=datetime.now(timezone.utc).isoformat()
        keys=[r['request_key'] for r in rows]
        if not keys:return dict(changed=0,added=0,withdrawn=0)
        if reviewed_unknowns is None:reviewed_unknowns=self._reviewed_unknown_service_paths()
        if previous is None:
            previous=self.all('SELECT * FROM viewer_semantic_occurrences WHERE request_key IN ('
                              +','.join('?' for _ in keys)+')',keys)
        old_by_key={r['request_key']:r for r in previous}
        upserts=[];withdrawals=[];transitions=[]
        for row in rows:
            key=row['request_key']
            new=self._semantic_candidate(row,reviewed_unknowns)
            old=old_by_key.get(key)
            if not new and old is None:continue
            state='active' if new else 'withdrawn'
            if old and (old['state'],old['kind'],old['occurrence_key'],old['session_key'],old['anchor_ns'],old['root_call'],old['root_code'],old['category'],old['initiation']) == (
                state,new['kind'] if new else old['kind'],new['occurrence_key'] if new else old['occurrence_key'],
                new['session_key'] if new else old['session_key'],new['anchor_ns'] if new else old['anchor_ns'],
                new['root_call'] if new else old['root_call'],new['root_code'] if new else old['root_code'],
                new['category'] if new else old['category'],new['initiation'] if new else old['initiation']):
                continue
            revision=(old['revision']+1) if old else 1
            if old:changed_sessions.add(old['session_key'])
            if new:changed_sessions.add(new['session_key'])
            if new:
                upserts.append((key,new['anchor_key'],new['session_key'],new['anchor_ns'],new['kind'],
                     new['occurrence_key'],new['root_call'],new['root_code'],new['family_id'],
                     new['family_label_fa'],new['category'],new['initiation'],state,revision,now))
            else:
                withdrawals.append((revision,now,key));withdrawn+=1
            if not old and new:added+=1
            transitions.append((key,revision,old['kind'] if old else None,
                  new['kind'] if new else None,old['occurrence_key'] if old else None,
                  new['occurrence_key'] if new else None,
                  'withdraw' if not new else 'add' if not old else 'restore' if old['state']=='withdrawn' else 'replace',now))
            changed+=1
        def many(sql,values):
            if not values:return
            statement=sql if self.sqlite else sql.replace('?',self.param)
            cursor=self.conn.cursor()
            try:
                cursor.executemany(statement,values)
            finally:
                cursor.close()
        many('''INSERT INTO viewer_semantic_occurrences
           (request_key,anchor_key,session_key,anchor_ns,kind,occurrence_key,
            root_call,root_code,family_id,family_label_fa,category,initiation,state,revision,updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(request_key) DO UPDATE SET
             session_key=excluded.session_key,anchor_ns=excluded.anchor_ns,
             kind=excluded.kind,occurrence_key=excluded.occurrence_key,
             root_call=excluded.root_call,root_code=excluded.root_code,
             family_id=excluded.family_id,family_label_fa=excluded.family_label_fa,
             category=excluded.category,initiation=excluded.initiation,
             state=excluded.state,revision=excluded.revision,updated_at=excluded.updated_at''',upserts)
        many("UPDATE viewer_semantic_occurrences SET state='withdrawn',revision=?,updated_at=? WHERE request_key=?",withdrawals)
        many('''INSERT INTO viewer_semantic_transitions
          (request_key,revision,old_kind,new_kind,old_occurrence_key,new_occurrence_key,transition,changed_at)
          VALUES(?,?,?,?,?,?,?,?)''',transitions)
        if session_updates is not None:session_updates.update(changed_sessions)
        if refresh_heads:self._refresh_semantic_session_heads(changed_sessions)
        return dict(changed=changed,added=added,withdrawn=withdrawn)

    def build_semantic_index(self, *, batch_size=750, commit=True):
        """Explicit one-time bootstrap on isolated Viewer only, no raw changes.

        Reading all requests is a maintenance operation; never call per page.
        """
        if not 50 <= int(batch_size) <= 2000:raise ValueError('invalid_batch_size')
        self.init_semantic_index(commit=commit)
        total=changes=0
        candidates=self.one('SELECT COUNT(*) AS n FROM viewer_requests')['n']
        self.progress('semantic_index',processed=0,total=candidates)
        reviewed_unknowns=self._reviewed_unknown_service_paths()
        try:
            with self._semantic_bootstrap_batches(batch_size) as batches:
                for batch,previous in batches:
                    info=self._write_semantic_batch(batch,previous=previous,refresh_heads=False,reviewed_unknowns=reviewed_unknowns)
                    total+=len(batch);changes+=info['changed']
                    if total%7500==0:self.progress('semantic_index',processed=total,total=candidates)
            self.progress('semantic_session_heads',processed=total)
            self._refresh_semantic_session_heads()
            now=datetime.now(timezone.utc).isoformat()
            self.sql('''INSERT INTO viewer_semantic_checkpoint VALUES(1,1,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET generation=viewer_semantic_checkpoint.generation+1,
                    updated_at=excluded.updated_at,indexed_requests=excluded.indexed_requests,state='ready' ''',
                     (now,total,'ready'))
            if commit:self.conn.commit()
            self.progress('semantic_index_complete',processed=total)
        except Exception:
            self.conn.rollback();raise
        return dict(version=SCHEMA_VERSION,request_candidates_scanned=total,
                    changed_anchors=changes,read_only_raw=True)

    def reconcile_semantic_requests(self,request_keys,*,commit=True):
        """Update only affected anchors; used by future *atomic* publisher."""
        keys=sorted(set(request_keys))
        if any(not isinstance(k,str) or len(k)!=64 for k in keys):
            raise ValueError('invalid_request_keys')
        summary=dict(changed=0,added=0,withdrawn=0)
        sessions=set()
        reviewed_unknowns=self._reviewed_unknown_service_paths()
        try:
            for begin in range(0,len(keys),500):
                rows=self._read_semantic_batch(request_keys=keys[begin:begin+500])
                present={r['request_key'] for r in rows}
                # Removed request/withdrawal is only legal after a real read model
                # revision, never because a bounded query omitted the request.
                if present!=set(keys[begin:begin+500]):
                    raise ValueError('requested_read_model_anchor_missing')
                r=self._write_semantic_batch(rows,refresh_heads=False,session_updates=sessions,reviewed_unknowns=reviewed_unknowns)
                for k,v in r.items():summary[k]+=v
            if summary['changed']:
                self._refresh_semantic_session_heads(sessions)
                self.sql('''UPDATE viewer_semantic_checkpoint
                  SET generation=generation+1,updated_at=? WHERE id=1 AND state='ready' ''',
                  (datetime.now(timezone.utc).isoformat(),))
            if commit:self.conn.commit()
        except Exception:self.conn.rollback();raise
        return summary

    def semantic_sessions(self,limit=25,offset=0,search=None,ip=None,from_ns=None,to_ns=None):
        """Fast semantic-home rows; never sort on latest technical RequestID.

        Uses materialized *same* classifier as SessionBehavior and ServiceJourney.
        No graph traversal per home row; preserves unknown manual initiation.
        """
        ck=self.semantic_checkpoint()
        if not ck or ck['state']!='ready':
            return dict(items=[],total=0,limit=limit,offset=offset,
                        index_ready=False,generation=None)
        clauses=["s.state='active'",'s.session_key IS NOT NULL'];params=[]
        if search:
            from .viewer_data import token
            clauses.append('s.session_key=?');params.append(token(self.keys,'session',search))
        if from_ns is not None:
            clauses.append('s.anchor_ns>=?');params.append(from_ns)
        if to_ns is not None:
            clauses.append('s.anchor_ns<?');params.append(to_ns)
        if ip:
            from .viewer_data import token
            clauses.append('''EXISTS(SELECT 1 FROM viewer_events e
              WHERE e.request_key=s.request_key AND e.ip_key=?)''')
            params.append(token(self.keys,'ip',ip))
        q=' AND '.join(clauses)
        if not ip and from_ns is None and to_ns is None:
            # Ordinary live home reads one row per session; it never ranks the
            # full retained occurrence history or scans raw logs per refresh.
            condition=' WHERE s.session_key=?' if search else ''
            args=params if search else []
            count=self.one('SELECT COUNT(*) AS n FROM viewer_semantic_session_heads s'+condition,args)['n']
            rows=self.all('''SELECT o.* FROM viewer_semantic_session_heads s
               JOIN viewer_semantic_occurrences o ON o.request_key=s.request_key'''+condition+
               ' ORDER BY s.anchor_ns DESC,s.request_key DESC LIMIT ? OFFSET ?',args+[limit,offset])
            from .viewer_data import tehran
            for row in rows:
                row['raw_session_id']=self.raw_session_id(row['session_key'])
                row['alias']=row['raw_session_id'] or ('نشست '+row['session_key'][:10])
                row['when_fa']=tehran(row['anchor_ns'])
            return dict(items=rows,total=count,limit=limit,offset=offset,index_ready=True,generation=ck['generation'])
        ranked='''WITH ranked AS (SELECT s.*, ROW_NUMBER() OVER (
          PARTITION BY s.session_key ORDER BY s.anchor_ns DESC,s.request_key DESC) AS nr
          FROM viewer_semantic_occurrences s WHERE '''+q+''')'''
        count=self.one(ranked+' SELECT COUNT(*) AS n FROM ranked WHERE nr=1',params)['n']
        rows=self.all(ranked+''' SELECT session_key,anchor_ns,request_key,anchor_key,
           occurrence_key,root_call,root_code,kind,family_id,family_label_fa,
           initiation,revision FROM ranked WHERE nr=1
           ORDER BY anchor_ns DESC,request_key DESC LIMIT ? OFFSET ?''',params+[limit,offset])
        from .viewer_data import tehran
        for row in rows:
            row['raw_session_id']=self.raw_session_id(row['session_key'])
            row['alias']=row['raw_session_id'] or ('نشست '+row['session_key'][:10])
            row['when_fa']=tehran(row['anchor_ns'])
        return dict(items=rows,total=count,limit=limit,offset=offset,index_ready=True,
                    generation=ck['generation'])

    def indexed_session_behavior(self,session_key,*,after_ns=None,after_key=None,scan_limit=100,generation=None):
        """Newest-first, cursor-paged view that rejects a stale generation."""
        from .session_behavior import SESSION_KEY_RE
        from .viewer_data import tehran
        if not SESSION_KEY_RE.fullmatch(str(session_key)):
            raise ValueError('invalid_session_key')
        if not 1<=int(scan_limit)<=500:raise ValueError('invalid_limit')
        ck=self.semantic_checkpoint()
        if not ck or ck['state']!='ready':raise ValueError('semantic_index_not_ready')
        if generation is not None and int(generation)!=ck['generation']:
            raise ValueError('stale_generation')
        if (after_ns is None)!=(after_key is None):raise ValueError('invalid_cursor')
        where=['session_key=?',"state='active'"];params=[session_key]
        if after_ns is not None:
            if not isinstance(after_ns,int) or after_ns<0 or not SESSION_KEY_RE.fullmatch(str(after_key)):
                raise ValueError('invalid_cursor')
            where.append('(anchor_ns<? OR (anchor_ns=? AND request_key<?))')
            params.extend((after_ns,after_ns,after_key))
        rows=self.all('''SELECT * FROM viewer_semantic_occurrences WHERE '''+
          ' AND '.join(where)+''' ORDER BY anchor_ns DESC,request_key DESC LIMIT ?''',params+[scan_limit+1])
        more=len(rows)>scan_limit;visible=rows[:scan_limit]
        for row in visible:
            row['anchor_request_key']=row['request_key']
            row['customer_initiation_confirmed']=row['initiation']=='confirmed_manual'
            row['when_fa']=tehran(row['anchor_ns'])
            row['financial_finality']='NOT_INFERRED'
        return dict(session_key=session_key,version=SCHEMA_VERSION,
            generation=ck['generation'],observed_occurrences=visible,
            observed_semantic_execution_count=len(visible),
            confirmed_manual_action_count=None,
            ambiguous_multi_root_requests=[],ambiguous_multi_root_count=0,
            unclassified_facade_candidates=0,candidate_requests_scanned=len(visible),
            next_cursor=(dict(after_ns=visible[-1]['anchor_ns'],after_key=visible[-1]['request_key'],
                              generation=ck['generation']) if more and visible else None),
            has_more=more)
