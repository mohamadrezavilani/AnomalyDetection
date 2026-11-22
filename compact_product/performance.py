"""Small, durable post-commit samples; never a throughput benchmark."""
import math
import time
from . import BUILD


def initialize(db, schema):
    db.execute(f'''CREATE TABLE IF NOT EXISTS {schema}.window_performance(
        stream_id TEXT NOT NULL,role TEXT NOT NULL,measured_ns BIGINT NOT NULL,
        start_ns BIGINT NOT NULL,mode TEXT NOT NULL,fresh BOOLEAN,
        seconds DOUBLE PRECISION NOT NULL,source_records BIGINT,
        read_seconds DOUBLE PRECISION,write_seconds DOUBLE PRECISION,build TEXT NOT NULL,
        PRIMARY KEY(stream_id,role,measured_ns))''')


def record(db, schema, stream, role, result, mode):
    if role == 'analysis' and not result.get('timing_confirmed'):
        return
    seconds = result.get('analysis_seconds' if role == 'analysis' else 'total_seconds')
    if type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds < 0:
        return
    now = time.time_ns()
    db.execute(f'''WITH saved AS (
        INSERT INTO {schema}.window_performance VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT DO NOTHING RETURNING 1)
        DELETE FROM {schema}.window_performance WHERE stream_id=%s AND role=%s
        AND measured_ns IN (SELECT measured_ns FROM {schema}.window_performance
        WHERE stream_id=%s AND role=%s ORDER BY measured_ns DESC OFFSET 255 LIMIT 32)''',
        (stream,role,now,result['start_ns'],mode,result.get('fresh_publication'),seconds,
         result.get('source_records'),result.get('read_extract_seconds'),result.get('database_seconds'),BUILD,
         stream,role,stream,role))


def recent(db, schema, stream):
    if not db.execute('SELECT to_regclass(%s) AS name',(schema+'.window_performance',)).fetchone()['name']:
        return {}
    output = {}
    for role in ('ingest','history','analysis','longitudinal'):
        rows = db.execute(f'''SELECT * FROM {schema}.window_performance WHERE stream_id=%s AND role=%s
            ORDER BY measured_ns DESC LIMIT 20''',(stream,role)).fetchall()
        values = sorted(r['seconds'] for r in rows)
        output[role] = dict(rows=rows, samples=len(rows),
            median_seconds=values[len(values)//2] if values else None,
            p95_seconds=values[math.ceil(.95*len(values))-1] if values else None)
    return output
