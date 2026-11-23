"""Versioned provider contract facts reviewed for Compact. Page numbers are PDF pages."""
from psycopg.types.json import Jsonb

INQUIRY = ('Inquiry-V4.1.0.pdf', '2abcc44fa1f2587060d5d336871a7b8b5d928173d74c843b8c66134a0ccece60')
PAYMENT = ('Payment-V3.0.0.pdf', '5e773f3fcf253a77f5aa37192342cbd1a796f2e4334514d08a099419bd535767')
# These are provider-side inputs, not automatic bindings to a public API.
CONTRACTS = (
    (INQUIRY, 13, 'ElectricityBillInquiry', ['ElectricityBillID'], ['TraceNumber']),
    (INQUIRY, 15, 'GasBillInquiry', ['ParticipateCode'], ['TraceNumber']),
    (INQUIRY, 17, 'WaterBillInquiry', ['WaterBillID'], ['TraceNumber']),
    (INQUIRY, 19, 'FixedLineBillInquiry', ['FixedLineNumber'], ['TraceNumber']),
    (INQUIRY, 23, 'MCIMobileBillInquiry', ['MobileNumber'], ['TraceNumber']),
    (INQUIRY, 24, 'MtnMobileBillInquiry', ['MobileNumber'], ['TraceNumber']),
    (INQUIRY, 26, 'MtnMobileDebtInquiry', ['MobileNumber'], ['TraceNumber']),
    (INQUIRY, 27, 'RightelMobileBillInquiry', ['MobileNumber'], ['TraceNumber']),
    (PAYMENT, 14, 'BillPaymentInquiry', ['BillID', 'PaymentID'], ['TraceNumber']),
    (PAYMENT, 20, 'TopUpProductReserve', ['MobileNumber', 'ProductCode'], ['TraceNumber', 'UniqueKey']),
)
MCI = 'ClientAyanCoInquiry.MCIMobileBillInquiry'
NO_BILL = 'GD2048'


def initialize(db, schema):
    db.execute(f"""CREATE TABLE IF NOT EXISTS {schema}.provider_contracts(
        document text NOT NULL, document_sha256 text NOT NULL, pdf_page int NOT NULL,
        operation text NOT NULL, business_inputs text[] NOT NULL, tracking_inputs text[] NOT NULL,
        outcomes jsonb NOT NULL, PRIMARY KEY(document_sha256,operation))""")
    with db.cursor() as cur:
        cur.executemany(f"""INSERT INTO {schema}.provider_contracts VALUES (%s,%s,%s,%s,%s,%s,%s)
              ON CONFLICT(document_sha256,operation) DO NOTHING""", [
            (*doc, page, operation, business, tracking, Jsonb(
                {NO_BILL: {'class': 'SUCCESS_NO_PAYABLE_BILL', 'message_fa': 'هیچ قبض قابل پرداختی برای این شماره ثبت نشده است.'}}
                if operation == 'MCIMobileBillInquiry' else {}))
            for doc,page,operation,business,tracking in CONTRACTS])


def observed_no_bill(body, state):
    """Return a provider outcome only for an unambiguous, directly bound observation."""
    from compact_behavior import inquiry
    if (body['api'] != inquiry.CELL_SERVICE or body['service_key'] != body['api']
            or body['result_code'] != 'G00000' or not body['features']['result_eligible']
            or 'MobileNumber' not in body['features'].get(inquiry.POLICY, {})
            or state['parse_errors'] or state['issues'] or len(state['sessions']) != 1):
        return False
    outputs = state['outputs']
    if len(outputs) != 1 or outputs[0]['path'] != MCI or outputs[0].get('observed_at_ns') is None:
        return False
    value = outputs[0].get('value')
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        return False
    item = value[0]
    if 'Parameters' not in item or item['Parameters'] is not None or not isinstance(item.get('Status'), dict):
        return False
    inputs = [i for i in state['inputs'] if i['path'] == MCI]
    if len(inputs) != 1 or inputs[0].get('observed_at_ns') != outputs[0]['observed_at_ns']:
        return False
    provider = inquiry.subjects(body['api'], body['api'], 'reviewed_same_request_provider', inputs[0])
    return item['Status'].get('Code') == NO_BILL and provider.get('MobileNumber') == body['features'][inquiry.POLICY]['MobileNumber']
