"""Bounded SELECT-only delegation to the installed, digest-pinned Viewer.

No ViewerDB, factory, initializer, resolver copy, raw decryptor or SQLite import.
The payment proof wrapper omits display-only raw RequestID, keeping its exact
request/origin/version/field locator. Bill basket raw matching remains in Viewer.
"""
from pathlib import Path
import sys
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
from .snapshot import require

def reader(project,q):
    project=Path(project).resolve()
    if str(project) not in sys.path:sys.path.insert(0,str(project))
    from p24_foundation.service_journey import ServiceJourneyMixin
    from p24_foundation.viewer_service_context import ServiceContextMixin
    from p24_foundation.viewer_payment_journey import ServicePaymentJourneyMixin
    from p24_foundation.viewer_raw import RawEvidenceMixin
    import p24_foundation.service_journey as module
    require(Path(module.__file__).resolve().is_relative_to(project),'VIEWER_READMODEL_FROM_DIFFERENT_INSTALLATION')
    class ReadOnlyFacade(ServiceJourneyMixin,ServiceContextMixin,ServicePaymentJourneyMixin,RawEvidenceMixin):
        def all(self,statement,params=()):
            require(statement.lstrip().upper().startswith('SELECT '),'VIEWER_BRIDGE_NON_SELECT_REJECTED')
            return q('SELECT * FROM ('+statement.replace('?','%s')+') AS viewer_readmodel',tuple(params),cap=4096)
        def one(self,statement,params=()):
            rows=self.all(statement,params)
            return rows[0] if rows else None
        def raw_request_id(self,key):return None
        def _correlation_proof(self,row,*,edge=False):
            at=row['observed_ns'] if edge else row['at_ns']
            return {'origin_key':row['evidence_origin'] if edge else row['origin_key'],
                'version_key':row['evidence_version'] if edge else row['version_key'],
                'field_path':row['evidence_path'] if edge else row['field_path'],'request_key':row['request_key'],
                'raw_request_id':None,'at_ns':at,'when_fa':datetime.fromtimestamp(at/1e9,timezone.utc).astimezone(ZoneInfo('Asia/Tehran')).strftime('%Y-%m-%d %H:%M:%S'),
                'callpath':row.get('callpath')}
    facade=ReadOnlyFacade()
    facade._binary_origin_keys=bool(getattr(q,'origin_keys_active',lambda:False)())
    return facade

def read_journey(source,key):
    from .product_source import SELECT
    with source.snapshot() as q:
        meta=source.metadata(q);facade=reader(source.project,q)
        semantic=q(SELECT+'WHERE s.request_key=%s',(key,),cap=1)
        journey=facade.service_journey(key,max_requests=96)
        context=facade.service_context_card(key)
        payment=facade.service_payment_journey(key)
        # Preserve reported-state timelines as context. They are not promoted to
        # settled funds or independent manual actions by this adapter.
        return {'source':meta,'semantic':semantic[0] if semantic else None,
            'journey':journey,'service_context':context,'payment':payment,
            'raw_bill_basket_matching':'VIEWER_DRILLDOWN_ONLY','financial_finality':'NOT_INFERRED',
            'manual_actions':'NOT_INFERRED','source_scope':'BOUNDED_INDEXED_READMODELS'}
