"""C6 storage-only experiment: build fresh indexed segments, publish a prefix.

Not a Viewer backend or a deployable storage migration. It measures the full
cost of a typed change-set representation, including both global directories.
All logical changes must already have been computed by the publisher. Source
acquisition, request reconstruction, actual AD and query-path performance are
separate, unqualified costs. No production database can be opened here.
"""
from contextlib import contextmanager
import hashlib
from tempfile import SpooledTemporaryFile
import time

FIELDS='kind,row_key,publication,request_key,actor_key,origin_key,version_key,body'
COLUMNS='kind SMALLINT NOT NULL,row_key BYTEA NOT NULL,publication BIGINT NOT NULL,request_key BYTEA,actor_key BYTEA,origin_key BYTEA,version_key BYTEA,body BYTEA NOT NULL'
INDEXES=('kind,row_key,publication','kind,request_key','kind,actor_key','kind,origin_key,version_key','publication')
MAX_ROWS=200000
MAX_BYTES=128*1024*1024


def guard(connection):
    name=connection.info.dbname
    if not (name.startswith('p24_design_segments_') and name.endswith('_qualification')):
        raise ValueError('segment_experiment_requires_owned_qualification_database')


def check_rows(rows):
    size=0;seen=set()
    if len(rows)>MAX_ROWS:raise ValueError('segment_row_budget_exceeded')
    for new,row in rows:
        if type(new)is not bool or len(row)!=8 or not 1<=row[0]<=16 or row[2]<1:
            raise ValueError('invalid_segment_change')
        key=(row[0],row[1],row[2])
        if key in seen:raise ValueError('duplicate_segment_change')
        seen.add(key)
        size+=sum(len(x) if isinstance(x,(bytes,bytearray)) else 8 for x in row)
        if size>MAX_BYTES:raise ValueError('segment_byte_budget_exceeded')
    return size


def source_hash(rows):
    digest=hashlib.sha256()
    for new,row in rows:
        digest.update(b'1' if new else b'0')
        for value in row:
            body=(b'N' if value is None else b'B'+bytes(value) if isinstance(value,(bytes,bytearray)) else b'I'+str(value).encode('ascii'))
            digest.update(len(body).to_bytes(8,'big'));digest.update(body)
    return digest.hexdigest()


def copy_rows(raw,table,rows,*,with_flag=False,with_part=None):
    columns=('part_id,' if with_part is not None else '')+('is_new,' if with_flag else '')+FIELDS
    with raw.cursor().copy('COPY '+table+'('+columns+') FROM STDIN') as copy:
        for new,row in rows:
            values=((with_part,) if with_part is not None else ())+((new,) if with_flag else ())+tuple(row)
            copy.write_row(values)


def binary_merge(raw,source,target):
    with SpooledTemporaryFile(max_size=8*1024**2) as spool:
        with raw.cursor().copy('COPY (SELECT '+FIELDS+' FROM '+source+
                ' WHERE is_new ORDER BY kind,row_key) TO STDOUT (FORMAT BINARY)') as copy:
            for block in copy:spool.write(block)
        spool.seek(0)
        with raw.cursor().copy('COPY '+target+'('+FIELDS+') FROM STDIN (FORMAT BINARY)') as copy:
            for block in iter(lambda:spool.read(1024**2),b''):copy.write(block)


class IndexedBaseline:
    """Strict native COPY of new rows plus indexed updates of changed rows."""
    def __init__(self,raw):
        guard(raw);self.raw=raw
        raw.execute('CREATE TABLE old_rows('+COLUMNS+',PRIMARY KEY(kind,row_key))')
        for n,columns in enumerate(INDEXES[1:]):raw.execute(f'CREATE INDEX old_idx_{n} ON old_rows('+columns+')')
        raw.execute('CREATE TABLE visible(id INT PRIMARY KEY,publication BIGINT NOT NULL)')
        raw.execute('INSERT INTO visible VALUES(1,0)');raw.commit()

    def publish(self,sequence,rows):
        began=time.perf_counter();check_rows(rows)
        try:
            self.raw.execute('CREATE TEMP TABLE IF NOT EXISTS changes(is_new BOOLEAN,'+COLUMNS+') ON COMMIT DELETE ROWS')
            copy_rows(self.raw,'changes',rows,with_flag=True)
            updates=','.join(k+'=s.'+k for k in FIELDS.split(',')[2:])
            changed=self.raw.execute('UPDATE old_rows t SET '+updates+' FROM changes s WHERE NOT s.is_new AND t.kind=s.kind AND t.row_key=s.row_key').rowcount
            if changed!=sum(not new for new,_ in rows):raise ValueError('unknown_segment_update_key')
            binary_merge(self.raw,'changes','old_rows')
            changed=self.raw.execute('UPDATE visible SET publication=%s WHERE id=1 AND publication=%s',(sequence,sequence-1)).rowcount
            if changed!=1:raise ValueError('noncontiguous_segment_publication')
            self.raw.commit()
        except BaseException:self.raw.rollback();raise
        return time.perf_counter()-began

    def snapshot(self):
        return self.raw.execute('SELECT '+FIELDS+' FROM old_rows ORDER BY kind,row_key').fetchall()


class BuiltSegments:
    """Fresh heap/index builds and two fully charged global exact-key indexes."""
    def __init__(self,raw):
        guard(raw);self.raw=raw
        raw.execute('CREATE TABLE segment_rows(part_id INT NOT NULL,'+COLUMNS+') PARTITION BY LIST(part_id)')
        raw.execute('CREATE TABLE key_catalog(kind SMALLINT,row_key BYTEA,PRIMARY KEY(kind,row_key))')
        raw.execute('CREATE TABLE directory(kind SMALLINT,row_key BYTEA,publication BIGINT,part_id INT NOT NULL,PRIMARY KEY(kind,row_key,publication))')
        raw.execute('CREATE TABLE segments(part_id INT PRIMARY KEY,first_publication BIGINT,last_publication BIGINT,rows BIGINT,source_sha256 TEXT)')
        raw.execute('CREATE TABLE visible(id INT PRIMARY KEY,publication BIGINT NOT NULL)')
        raw.execute('INSERT INTO visible VALUES(1,0)');raw.commit()

    def prepare(self,part_id,rows,*,first_publication=None,last_publication=None,fault=lambda stage:None):
        began=time.perf_counter();size=check_rows(rows);sequences=sorted({row[2] for _,row in rows});digest=source_hash(rows)
        first=first_publication if first_publication is not None else sequences[0] if sequences else None
        last=last_publication if last_publication is not None else sequences[-1] if sequences else None
        if (type(part_id)is not int or not 1<=part_id<=1000000 or type(first)is not int
                or type(last)is not int or first<1 or not 0<=last-first<12
                or any(not first<=s<=last for s in sequences)):
            raise ValueError('invalid_bounded_segment_batch')
        digest=hashlib.sha256((str(first)+':'+str(last)+':'+digest).encode()).hexdigest()
        raw=self.raw;table='segment_'+str(part_id);costs={}
        existing=raw.execute('SELECT source_sha256 FROM segments WHERE part_id=%s',(part_id,)).fetchone()
        if existing:
            raw.rollback()
            if existing[0]!=digest:raise ValueError('prepared_segment_source_changed')
            return dict(status='REUSED_PREPARED_SEGMENT',total_prepare_seconds=time.perf_counter()-began,rows=len(rows),bytes=size)
        try:
            t=time.perf_counter()
            raw.execute('CREATE TABLE '+table+'(part_id INT NOT NULL CHECK(part_id='+str(part_id)+'),is_new BOOLEAN,'+COLUMNS+')')
            with raw.cursor().copy('COPY '+table+'(part_id,is_new,'+FIELDS+') FROM STDIN') as copy:
                for new,row in rows:copy.write_row((part_id,new,*row))
            costs['heap_load_seconds']=time.perf_counter()-t;fault('after_load')
            t=time.perf_counter()
            for n,columns in enumerate(INDEXES):
                raw.execute('CREATE '+('UNIQUE ' if n==0 else '')+'INDEX '+table+'_idx_'+str(n)+' ON '+table+'('+columns+')')
            ready=raw.execute('SELECT bool_and(indisready AND indisvalid) FROM pg_catalog.pg_index WHERE indrelid=%s::regclass',(table,)).fetchone()[0]
            if ready is not True:raise ValueError('segment_indexes_not_ready')
            count=raw.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]
            if count!=len(rows):raise ValueError('segment_load_incomplete')
            costs['index_build_and_validation_seconds']=time.perf_counter()-t;fault('after_indexes')
            t=time.perf_counter()
            # This is a global exact-key uniqueness cost, not hidden staging.
            raw.execute('INSERT INTO key_catalog SELECT kind,row_key FROM '+table+' WHERE is_new ORDER BY kind,row_key')
            if raw.execute('SELECT 1 FROM '+table+' s WHERE NOT s.is_new AND NOT EXISTS(SELECT 1 FROM key_catalog k WHERE k.kind=s.kind AND k.row_key=s.row_key) LIMIT 1').fetchone():
                raise ValueError('unknown_segment_update_key')
            raw.execute('INSERT INTO directory SELECT kind,row_key,publication,part_id FROM '+table+' ORDER BY kind,row_key,publication')
            costs['global_directory_seconds']=time.perf_counter()-t
            t=time.perf_counter();raw.execute('ALTER TABLE '+table+' DROP COLUMN is_new')
            raw.execute('ALTER TABLE segment_rows ATTACH PARTITION '+table+' FOR VALUES IN ('+str(part_id)+')')
            raw.execute('INSERT INTO segments VALUES(%s,%s,%s,%s,%s)',(part_id,first,last,len(rows),digest))
            costs['attach_seconds']=time.perf_counter()-t;fault('before_prepare_commit')
            t=time.perf_counter();raw.commit();costs['prepare_commit_seconds']=time.perf_counter()-t;fault('after_prepare_commit')
        except BaseException:raw.rollback();raise
        return dict(costs,rows=len(rows),bytes=size,total_prepare_seconds=time.perf_counter()-began)

    def publish(self,sequence):
        began=time.perf_counter();raw=self.raw
        try:
            ready=raw.execute('SELECT 1 FROM segments WHERE first_publication<=%s AND last_publication>=%s',(sequence,sequence)).fetchone()
            if ready is None:raise ValueError('unprepared_segment_publication')
            changed=raw.execute('UPDATE visible SET publication=%s WHERE id=1 AND publication=%s',(sequence,sequence-1)).rowcount
            if changed!=1:raise ValueError('noncontiguous_segment_publication')
            raw.commit()
        except BaseException:raw.rollback();raise
        return time.perf_counter()-began

    def snapshot(self):
        # All retained revisions remain physically present. Only committed
        # five-minute visibility advances; a future prepared update cannot
        # overwrite the previous visible value or train an earlier model.
        return self.raw.execute('SELECT DISTINCT ON (r.kind,r.row_key) '+
            ','.join('r.'+k for k in FIELDS.split(','))+''' FROM directory d
            JOIN segment_rows r USING(part_id,kind,row_key,publication)
            WHERE d.publication<=(SELECT publication FROM visible WHERE id=1)
            ORDER BY r.kind,r.row_key,r.publication DESC''').fetchall()
