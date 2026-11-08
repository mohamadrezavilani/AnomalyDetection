"""Owned, versioned cache of delegated Viewer journeys; never an anchor resolver."""
import json
from . import FIVE_NS
from .snapshot import canonical,digest

DDL=[
 '''CREATE TABLE IF NOT EXISTS anomaly_detection.adp_journeys(request_key TEXT PRIMARY KEY,body TEXT NOT NULL,
 content_digest TEXT NOT NULL,semantic_revision BIGINT,observed_ns BIGINT NOT NULL,next_read_ns BIGINT NOT NULL)''',
 'CREATE INDEX IF NOT EXISTS adp_journey_due ON anomaly_detection.adp_journeys(next_read_ns,request_key)',
]

def next_key(store,now,*,oldest=False):
    row=store.raw.execute('SELECT f.request_key FROM anomaly_detection.adp_facts f '
        'LEFT JOIN anomaly_detection.adp_journeys j ON j.request_key=f.request_key '
        "WHERE f.eligible=TRUE AND f.source_present=TRUE AND (j.request_key IS NULL OR j.next_read_ns<=%s) "
        'ORDER BY CASE WHEN EXISTS(SELECT 1 FROM anomaly_detection.adp_findings v WHERE v.session_key=f.session_key '
        "AND v.target_ns=(f.at_ns/%s)*%s AND v.state='ACTIVE') THEN 0 ELSE 1 END,f.at_ns "+
        ('ASC' if oldest else 'DESC')+',f.request_key LIMIT 1',(now,FIVE_NS,FIVE_NS)).fetchone()
    return row['request_key'] if row else None

def save(store,key,packet):
    meta=packet['source'];semantic=packet.get('semantic');body={k:v for k,v in packet.items() if k!='source'}
    signature=digest(body);now=meta['captured_at_ns']
    with store.transaction():
        store.bind(meta)
        if semantic:store.apply_rows([semantic],meta)
        old=store.raw.execute('SELECT content_digest FROM anomaly_detection.adp_journeys WHERE request_key=%s',(key,)).fetchone()
        if old is None or old['content_digest']!=signature:
            fact=store.raw.execute('SELECT session_key,at_ns FROM anomaly_detection.adp_facts WHERE request_key=%s',(key,)).fetchone()
            if fact:
                store.invalidate(fact['session_key'],fact['at_ns'])
                from .product_dependencies import context_changed
                root=store.raw.execute('SELECT service_path FROM anomaly_detection.adp_facts WHERE request_key=%s',(key,)).fetchone()
                context_changed(store,root['service_path'],fact['at_ns'])
            store.raw.execute('INSERT INTO anomaly_detection.adp_versions(request_key,change_type,content_digest,body,observed_ns) VALUES(%s,%s,%s,%s,%s)',
                (key,'viewer_journey_change',signature,canonical(body),now))
        from .population import save_relations,enqueue
        save_relations(store,key,body,now)
        scope=store.raw.execute('SELECT at_ns FROM anomaly_detection.adp_facts WHERE request_key=%s',(key,)).fetchone()
        if scope:enqueue(store,[scope['at_ns']])
        store.raw.execute('INSERT INTO anomaly_detection.adp_journeys VALUES(%s,%s,%s,%s,%s,%s) '
            'ON CONFLICT(request_key) DO UPDATE SET body=excluded.body,content_digest=excluded.content_digest,'
            'semantic_revision=excluded.semantic_revision,observed_ns=excluded.observed_ns,next_read_ns=excluded.next_read_ns',
            (key,canonical(body),signature,semantic['revision'] if semantic else None,now,now+600_000_000_000))
    return {'status':'OBSERVED','changed':old is None or old['content_digest']!=signature}

def defer(store,key,now):
    # A bounded graph that times out stays unknown and is retried independently;
    # one large request cannot monopolize this lane.
    store.raw.execute('INSERT INTO anomaly_detection.adp_journeys VALUES(%s,%s,%s,NULL,%s,%s) ON CONFLICT(request_key) '
        'DO UPDATE SET next_read_ns=excluded.next_read_ns',
        (key,canonical({'quality':'WAITING_FOR_BOUNDED_READMODEL'}),digest(['unavailable',key]),now,now+60_000_000_000))
