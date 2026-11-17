"""Durable product scope, independent of evidence, identity and cursors.

Legacy databases are full-scope until explicitly changed under the writer
lease. Financial projections retained from an older scope are never advertised
as current in behavior mode. Request-local dispatcher facts remain shared.
"""
import time

FULL = 'viewer-full-relations-1'
BEHAVIOR = 'viewer-behavior-1'
DISABLED = ('payment_result_change', 'typed_target_diversity', 'journey_profile_change')
DDL = [
    '''CREATE TABLE IF NOT EXISTS viewer_product_scope(
       id INTEGER PRIMARY KEY, contract TEXT NOT NULL, epoch BIGINT NOT NULL,
       changed_ns BIGINT NOT NULL, generation BIGINT NOT NULL, state TEXT NOT NULL)''',
    '''CREATE TABLE IF NOT EXISTS viewer_publication_contracts(
       generation BIGINT PRIMARY KEY,input_contract TEXT NOT NULL,scope_epoch BIGINT NOT NULL)''',
    '''CREATE TABLE IF NOT EXISTS viewer_product_scope_history(
       epoch BIGINT PRIMARY KEY,contract TEXT NOT NULL,changed_ns BIGINT NOT NULL,
       generation BIGINT NOT NULL,state TEXT NOT NULL)''',
]


def read(db, *, refresh=False):
    if not refresh and getattr(db, '_product_scope', None) is not None:
        return db._product_scope
    exists = (db.one("SELECT name FROM sqlite_master WHERE type='table' AND name='viewer_product_scope'")
              if db.sqlite else db.one("SELECT to_regclass('public.viewer_product_scope') AS name"))
    row = db.one('SELECT * FROM viewer_product_scope WHERE id=1') if exists and exists['name'] else None
    value = row or dict(contract=FULL, epoch=0, state='READY', generation=0, changed_ns=0)
    if value['contract'] not in (FULL, BEHAVIOR) or value['state'] not in ('READY', 'RESTORING_FULL'):
        raise ValueError('unsupported_viewer_product_scope')
    db._product_scope = value
    return value


def financial_enabled(db):
    if getattr(db, '_financial_repair', False):
        return True
    value = read(db)
    return value['contract'] == FULL and value['state'] == 'READY'


def capabilities(value):
    contract = value.get('contract', FULL)
    return dict(input_contract=contract, scope_epoch=value.get('epoch', 0),
                behavioral_features='observed-behavior-features-1',
                financial_relations='COMPLETE' if contract == FULL and value.get('state', 'READY') == 'READY' else 'OUT_OF_SCOPE',
                scope_state=value.get('state', 'READY'))


def set_scope(db, contract, *, state='READY'):
    """Caller holds the session writer lease; no cursor reset or data deletion."""
    if contract not in (FULL, BEHAVIOR) or state not in ('READY', 'RESTORING_FULL'):
        raise ValueError('invalid_product_scope')
    db.write_lock()
    previous = read(db, refresh=True)
    for statement in DDL:
        db.sql(statement)
    live = db.one('SELECT generation FROM viewer_live_state WHERE id=1')
    value = dict(contract=contract, epoch=previous['epoch'] + 1,
                 changed_ns=time.time_ns(), generation=live['generation'] if live else 0, state=state)
    db.sql('INSERT INTO viewer_product_scope VALUES(1,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET '
           'contract=excluded.contract,epoch=excluded.epoch,changed_ns=excluded.changed_ns,'
           'generation=excluded.generation,state=excluded.state', tuple(value.values()))
    db.sql('INSERT INTO viewer_product_scope_history VALUES(?,?,?,?,?)',
           (value['epoch'], contract, value['changed_ns'], value['generation'], state))
    db._product_scope = value
    return capabilities(value)


def observed_dispatch(db, raw, origin, version, request):
    """Extract once from the new raw version; retain same-request service/OTP facts.

    The historical table name is shared with finance. These axes are not
    payment relationships and are required to resolve InvoiceRegister behavior.
    """
    if financial_enabled(db) or not request:
        return
    call=str(raw.get('CallPath') or '').split(' Line:',1)[0].strip()
    if not (call.endswith(('.ud_prc_userSessionHasAccess','.ud_prc_invoiceRequest','.ud_prc_inquiryInvoiceResult2')) or
            call in ('ClientAyanCoInquiry.MyGovRequestOtp','ClientAyanCoInquiry.MyGovLogin','ClientAyanCoInquiry.TaminUnderCoveredInquiry')):
        return
    from .service_dispatch import dispatch_facts
    from .viewer_data import utc_ns
    from .viewer_storage_keys import conflict_clause
    for axis, value, path in dispatch_facts(raw):
        db._ingest_insert('viewer_contract_observations',
            (origin, version, request, utc_ns(raw.get('@timestamp')),
             str(raw.get('CallPath') or 'Unknown')[:240], axis, value, path, 'reported'))


# These values describe the same request/service, not an attached payment.
OBSERVED_OUTCOMES=frozenset(('unknown','success','failure','no_payable_bill','not_found','provider_unavailable'))


def observed_outcome(row):
    current=row.get('current_outcome')
    if current in OBSERVED_OUTCOMES:return current
    code=row.get('service_result_code',row.get('root_code'))
    return 'unknown' if not code else 'success' if code=='G00000' else 'failure'


def out_of_scope():
    return dict(status='OUT_OF_SCOPE', input_contract=BEHAVIOR,
                reason='FINANCIAL_RELATIONS_DISABLED_BY_PRODUCT_SCOPE')
