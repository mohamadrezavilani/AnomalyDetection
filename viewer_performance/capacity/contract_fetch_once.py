"""C2 qualification: test raw-body cardinality in the body fetch itself.

The stock scoped payment reader first COUNTs the exact raw pair and then
retrieves that same pair in batches of 400. This source-pinned prototype keeps
the metadata selection, source-wide version conflict test, full pair equality,
order and body decoding, but tests cardinality during the existing body fetch.
Zero or multiple bodies are still excluded. No persistent schema is changed.
"""
from collections import Counter
from contextlib import contextmanager
import time
import uuid

from p24_foundation.viewer_contract import CONTRACT_PATTERNS
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.viewer_runtime import runtime_source_digest
from .origin_filter import EXPECTED_RUNTIME

COUNT_TAIL=' AND (SELECT COUNT(*) FROM viewer_raw_events b WHERE b.origin_key=e.origin_key AND b.version_key=e.version_key)=1'
EXISTS_TAIL=' AND EXISTS(SELECT 1 FROM viewer_raw_events b WHERE b.origin_key=e.origin_key AND b.version_key=e.version_key)'


class ContractFetchOnceDB(ViewerDB):
    def __init__(self,**kwargs):
        if kwargs.get('sqlite_path') is None:
            name=str((kwargs.get('config') or {}).get('dbname',''))
            if not (name.startswith('p24_design_capacity_') and name.endswith('_qualification')):
                raise ValueError('contract_candidate_is_qualification_only')
        super().__init__(**kwargs)
        self.fetch_once_stats=dict(scoped_calls=0,metadata_rows=0,body_pair_lookups=0,
            returned_bodies=0,missing_bodies=0,nonunique_bodies=0)

    def prepare_candidate(self):
        if runtime_source_digest()!=EXPECTED_RUNTIME:
            raise ValueError('contract_reader_source_pin_mismatch')
        return dict(status='READY',no_build_or_migration=True,production_enabled=False)

    def candidate_report(self):
        return dict(fetch_once=self.fetch_once_stats,runtime_changed=False,production_enabled=False)

    @contextmanager
    def contract_event_batches(self,*,scoped=False,timings=None,prepared_scope=False,reuse_projection_events=False):
        if not (scoped and reuse_projection_events):
            with super().contract_event_batches(scoped=scoped,timings=timings,
                    prepared_scope=prepared_scope,reuse_projection_events=reuse_projection_events) as batches:
                yield batches
            return
        if runtime_source_digest()!=EXPECTED_RUNTIME:
            raise ValueError('contract_reader_source_pin_mismatch')
        native=not self.sqlite and callable(getattr(self.conn,'pipeline',None))
        query=self._contract_read_query(scoped=True,payload=False,reuse_projection_events=True)
        tail=COUNT_TAIL if not self.sqlite else EXISTS_TAIL
        if not query.endswith(tail):raise ValueError('contract_reader_query_shape_changed')
        metadata=query[:-len(tail)]
        timings=timings if timings is not None else {}
        timings.update(metadata_seconds=0.0,fetch_seconds=0.0)
        began=time.monotonic()
        self.progress('contract_select_candidates',scope='incremental')
        if not prepared_scope:self.init_contract_candidate_scope()
        self.sql(('TRUNCATE TABLE ' if native and not prepared_scope else 'DELETE FROM ')+'viewer_contract_candidate_scope')
        if native:self.sql('ANALYZE viewer_projection_scope')
        self.sql('INSERT INTO viewer_contract_candidate_scope '+metadata,CONTRACT_PATTERNS)
        metadata_rows=self.one('SELECT COUNT(*) AS n FROM viewer_contract_candidate_scope')['n']
        # The exact body-presence count is not known before streaming. Do not
        # advertise an upper bound as the final number of processable events.
        timings['candidate_metadata_rows']=metadata_rows;timings['candidate_events']=None
        self.fetch_once_stats['scoped_calls']+=1
        self.fetch_once_stats['metadata_rows']+=metadata_rows
        query='SELECT * FROM viewer_contract_candidate_scope ORDER BY origin_key,version_key'
        if native:
            self.sql('SET LOCAL cursor_tuple_fraction=1.0')
            cursor=self.conn.cursor(name='capacity_contract_'+uuid.uuid4().hex)
            cursor.execute(query)
        else:cursor=self.sql(query)
        timings['metadata_seconds']=time.monotonic()-began

        def batches():
            while True:
                began=time.monotonic();batch=[dict(item) for item in cursor.fetchmany(400)]
                if not batch:return
                pairs=[(item['origin_key'],item['version_key']) for item in batch]
                if native:
                    query=('SELECT k.origin_key,k.version_key,body.payload FROM (VALUES '+
                        ','.join('(?,?)' for _ in pairs)+''') AS k(origin_key,version_key)
                        CROSS JOIN LATERAL (SELECT r.payload FROM viewer_raw_events r
                          WHERE r.origin_key=k.origin_key AND r.version_key=k.version_key OFFSET 0) body''')
                else:
                    where=' OR '.join('(origin_key=? AND version_key=?)' for _ in pairs)
                    query='SELECT origin_key,version_key,payload FROM viewer_raw_events WHERE '+where
                rows=self.all(query,[value for pair in pairs for value in pair])
                counts=Counter((item['origin_key'],item['version_key']) for item in rows)
                bodies={(item['origin_key'],item['version_key']):item['payload'] for item in rows}
                self.fetch_once_stats['body_pair_lookups']+=len(pairs)
                eligible=[]
                for item,pair in zip(batch,pairs):
                    count=counts[pair]
                    if count==0:self.fetch_once_stats['missing_bodies']+=1
                    elif count!=1:self.fetch_once_stats['nonunique_bodies']+=1
                    else:
                        item['payload']=bodies[pair];eligible.append(item)
                self.fetch_once_stats['returned_bodies']+=len(eligible)
                timings['fetch_seconds']+=time.monotonic()-began
                if eligible:yield eligible
        try:yield batches()
        finally:cursor.close()
