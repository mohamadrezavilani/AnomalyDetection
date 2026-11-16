"""C1 qualification only: fenced, bounded, negative-only Origin membership.

No bitset is persisted or exported. A positive result never supplies a version
or proves an Origin exists. Only a complete build under the Writer lock may
skip a negative lookup. All uncertain paths retain the original full lookup.
The copied iterator is pinned to the unchanged Viewer runtime, not installed
into the product. Only this disposable ViewerDB subclass uses it.
"""
from __future__ import annotations

import hashlib
import json
import struct
import time
import zlib

from p24_foundation.viewer_data import ViewerDB,source_identity,token
from p24_foundation.viewer_origin_storage import lookup_origins
from p24_foundation.viewer_runtime import runtime_source_digest

EXPECTED_RUNTIME='b7273437ea42c1aea7d0183c3020be133c84dba5735c68a01a6fd81a4b56d7c8'
EPOCH_CONTRACT='viewer-window-epochs-1'


class Membership:
    def __init__(self,bytes_limit=8*1024**2,hashes=9):
        if not 32<=bytes_limit<=64*1024**2 or bytes_limit&(bytes_limit-1):
            raise ValueError('membership_bytes_must_be_bounded_power_of_two')
        if not 1<=hashes<=16:raise ValueError('invalid_membership_hash_count')
        self.bits=bytearray(bytes_limit);self.mask=bytes_limit*8-1;self.hashes=hashes
        self.ready=False;self.seal=None;self.disabled_reason='not_built'
        self.negative_checks=0;self.positive_checks=0;self.add_calls=0

    def positions(self,value):
        digest=hashlib.blake2b(value.encode('utf-8'),digest_size=16,person=b'P24OriginBloomV1').digest()
        a,b=struct.unpack('<QQ',digest);b|=1
        for i in range(self.hashes):yield (a+i*b)&self.mask

    def add(self,value):
        for index in self.positions(value):self.bits[index>>3]|=1<<(index&7)
        self.add_calls+=1

    def maybe(self,value):
        if not self.ready:return True
        for index in self.positions(value):
            if not self.bits[index>>3]&(1<<(index&7)):
                self.negative_checks+=1;return False
        self.positive_checks+=1;return True

    def disable(self,reason):
        self.ready=False;self.disabled_reason=reason

    def report(self):
        return dict(ready=self.ready,disabled_reason=self.disabled_reason,
            bytes_allocated=len(self.bits),hashes=self.hashes,add_calls=self.add_calls,
            add_calls_are_not_distinct_origins=True,negative_checks=self.negative_checks,
            positive_checks=self.positive_checks,positive_hits_use_authoritative_versions=True)


class OriginFilteredDB(ViewerDB):
    def __init__(self,**kwargs):
        config=kwargs.get('config') or {}
        if kwargs.get('sqlite_path') is None:
            name=str(config.get('dbname',''))
            if not (name.startswith('p24_design_capacity_') and name.endswith('_qualification')):
                raise ValueError('origin_filter_is_qualification_only')
        super().__init__(**kwargs)
        self._qualification_origin_lookup='global_ordered'
        self.membership=None;self.build_details=None;self.guard_seconds=0.0
        self.lookup_stats=dict(requested_origins=0,authoritative_origins=0,skipped_negatives=0,
            authoritative_calls=0,fallback_publications=0)
        self._candidate_used=False

    def _membership_token(self):
        row=self.one('''SELECT s.stream_key,s.keys_fingerprint,s.generation,
            e.contract,e.maintenance_epoch FROM viewer_live_state s
            JOIN viewer_window_epoch_state e ON e.id=s.id WHERE s.id=1''')
        if not row:
            raise ValueError('membership_epoch_contract_unavailable')
        if self.sqlite:
            raw=getattr(self.conn,'raw',self.conn)
            identity=('sqlite',id(raw))
        else:
            info=self.one('''SELECT current_database() AS database,pg_backend_pid() AS pid,
                pg_postmaster_start_time()::text AS server_start,backend_start::text
                FROM pg_stat_activity WHERE pid=pg_backend_pid()''')
            identity=tuple(info[k] for k in ('database','pid','server_start','backend_start'))
        # The generation is deliberately last. Reconciliation may increment
        # the semantic generation too; acknowledge only the publisher's exact
        # committed generation, never an assumed +1 or an arbitrary new value.
        return (*identity,row['stream_key'],row['keys_fingerprint'],row['contract'],
            row['maintenance_epoch'],row['generation'])

    def prepare_candidate(self,*,bytes_limit=8*1024**2,fault=None):
        self.membership=Membership(bytes_limit)
        began=time.perf_counter();count=0
        try:
            if runtime_source_digest()!=EXPECTED_RUNTIME:
                raise ValueError('origin_iterator_source_pin_mismatch')
            # Same lock as supported Viewer writers; do not call write_lock()
            # here, because a read-only build must not increment maintenance.
            if self.sqlite:self.sql('BEGIN IMMEDIATE')
            else:self.sql('SELECT pg_advisory_xact_lock(240026,2)')
            seal=self._membership_token()
            if seal[-3]!=EPOCH_CONTRACT:
                raise ValueError('membership_epoch_contract_unavailable')
            if self.sqlite:
                cursor=self.conn.cursor();cursor.execute('SELECT origin_key FROM viewer_events')
            else:
                cursor=self.conn.cursor(name='capacity_membership_build')
                cursor.execute('SELECT origin_key FROM viewer_events')
            try:
                while True:
                    rows=cursor.fetchmany(2048)
                    if not rows:break
                    for row in rows:self.membership.add(row['origin_key'])
                    count+=len(rows)
                    if fault:fault(count)
            finally:cursor.close()
            if self._membership_token()!=seal:
                raise ValueError('membership_source_changed_during_build')
            self.conn.commit()
            self.membership.seal=seal;self.membership.ready=True;self.membership.disabled_reason=None
        except BaseException:
            self.membership.disable('build_incomplete');self.conn.rollback();raise
        self.build_details=dict(status='COMPLETE',rows_scanned=count,
            seconds=time.perf_counter()-began,bytes_allocated=len(self.membership.bits),
            no_source_rows_or_checkpoint_modified=True,filter_persisted=False)
        return self.build_details

    def _membership_guard(self):
        if self.membership is None or not self.membership.ready:return False
        began=time.perf_counter()
        try:
            if runtime_source_digest()!=EXPECTED_RUNTIME:
                self.membership.disable('runtime_pin_changed');return False
            try:observed=self._membership_token()
            except ValueError:
                self.membership.disable('source_fence_unavailable');return False
            if observed!=self.membership.seal:
                self.membership.disable('source_fence_changed');return False
            return True
        finally:self.guard_seconds+=time.perf_counter()-began

    def _ingest_batches(self,rows,digest,batch_size=500):
        self._candidate_used=False
        if self.membership and getattr(self,'_qualification_origin_lookup','global_ordered')!='global_ordered':
            self.membership.disable('lookup_strategy_changed')
        yield from super()._ingest_batches(rows,digest,batch_size=batch_size)

    def _ingest_batches_globally_ordered(self,rows,digest,batch_size=500,lookup_chunk=2048):
        if not self._membership_guard():
            self.lookup_stats['fallback_publications']+=1
            yield from super()._ingest_batches_globally_ordered(rows,digest,batch_size,lookup_chunk)
            return
        self._candidate_used=True
        if not 1<=lookup_chunk<=4096:raise ValueError('invalid_origin_lookup_chunk')
        prepared=[]
        for n,row in enumerate(rows):
            if not isinstance(row,dict):raise ValueError('non_object_record')
            index,doc_id=source_identity(row)
            origin=token(self.keys,'origin',[index,doc_id] if index else [digest,n])
            prepared.append((n,row,origin,token(self.keys,'version',row)))
        all_origins=sorted({record[2] for record in prepared})
        known={origin:[] for origin in all_origins};raw_lookup={}
        lookup_started=time.monotonic();positives=[]
        for origin in all_origins:
            if self.membership.maybe(origin):positives.append(origin)
            # Set bits before the publication can commit. Rollback leaves only
            # harmless false positives; never remove bits from a ready filter.
            self.membership.add(origin)
        self.lookup_stats['requested_origins']+=len(all_origins)
        self.lookup_stats['authoritative_origins']+=len(positives)
        self.lookup_stats['skipped_negatives']+=len(all_origins)-len(positives)
        for offset in range(0,len(positives),lookup_chunk):
            self.lookup_stats['authoritative_calls']+=1
            for old in lookup_origins(self,'viewer_events',positives[offset:offset+lookup_chunk]):
                known[old['origin_key']].append(old)
        self._ingest_timing['lookup_seconds']+=time.monotonic()-lookup_started
        # This is the pinned original iterator after its initial lookup. Keep
        # original row order, mutable known-version lists and raw compatibility.
        for offset in range(0,len(prepared),batch_size):
            self._flush_ingest_batch();batch=prepared[offset:offset+batch_size]
            candidates=sorted({origin for _,_,origin,sig in batch
                if known[origin] and not any(v['version_key']==sig for v in known[origin])
                and any((origin,v['version_key']) not in raw_lookup for v in known[origin])})
            if candidates:
                started=time.monotonic()
                for piece in range(0,len(candidates),lookup_chunk):
                    for raw in lookup_origins(self,'viewer_raw_events',candidates[piece:piece+lookup_chunk]):
                        raw_lookup[(raw['origin_key'],raw['version_key'])]=json.loads(
                            zlib.decompress(bytes(raw['payload'])).decode('utf-8'))
                self._ingest_timing['lookup_seconds']+=time.monotonic()-started
            for n,row,origin,sig in batch:yield n,row,origin,sig,known[origin],raw_lookup

    def candidate_after_publication(self,result):
        if self.membership is None or not self.membership.ready:return
        if result['new_events'] and not self._candidate_used:
            self.membership.disable('new_origins_not_accounted_for');return
        observed=self._membership_token();old=self.membership.seal
        if (observed[:-1]!=old[:-1] or observed[-1]!=result['generation']
                or observed[-1]<=old[-1]):
            self.membership.disable('unacknowledged_source_change');return
        self.membership.seal=observed

    def candidate_report(self):
        return dict(build=self.build_details,membership=self.membership.report() if self.membership else None,
            lookup=self.lookup_stats,guard_seconds=self.guard_seconds,
            runtime_changed=False,production_enabled=False)
