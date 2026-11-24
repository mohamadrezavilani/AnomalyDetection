"""Reviewed provider-side field names and outcomes. Pages are physical PDF pages."""
import json
from pathlib import Path
from psycopg.types.json import Jsonb

INQUIRY = ('Inquiry-V4.1.0.pdf', '2abcc44fa1f2587060d5d336871a7b8b5d928173d74c843b8c66134a0ccece60')
PAYMENT = ('Payment-V3.0.0.pdf', '5e773f3fcf253a77f5aa37192342cbd1a796f2e4334514d08a099419bd535767')
DOCS = {'inq': INQUIRY, 'pay': PAYMENT}
CONTRACTS = json.loads(Path(__file__).with_name('provider_rules.json').read_text(encoding='utf-8'))
BY_CLIENT = {path: r for r in CONTRACTS for path in r.get('clients', ())}
MCI = 'ClientAyanCoInquiry.MCIMobileBillInquiry'
NO_BILL = 'GD2048'
MEANINGS = {
    'invalid': 'مقدار ورودی برای این عملیات معتبر نیست.',
    'mismatch': 'شناسه یا نوع اشتراک با این خدمت سازگار نیست.',
    'down': 'سرویس‌دهنده از اختلال یا برقرار نشدن ارتباط گزارش داده است.',
    'missing': 'رکورد در مرجع استعلام پیدا نشده است.',
    'empty': 'هیچ قبض قابل پرداختی ثبت نشده است.',
    'paid_no_new': 'قبض قبلی پرداخت شده و قبض جدید صادر نشده است.',
    'credit': 'اعتبار کیف پول برای این عملیات کافی نیست.',
    'paid': 'این قبض قبلاً پرداخت شده است.',
    'system': 'سرویس‌دهنده خطای سیستمی تراکنش گزارش کرده است.',
    'daily': 'سقف روزانهٔ تراکنش پر شده است.',
    'weekly': 'سقف هفتگی تراکنش پر شده است.',
    'monthly': 'سقف ماهانهٔ تراکنش پر شده است.',
    'failed': 'تراکنش ناموفق گزارش شده است.',
    'not_here': 'پرداخت این قبض از طریق این سامانه ثبت نشده است.',
    'not_gateway': 'پرداخت در درگاه‌های استعلام‌شده مشاهده نشده است.',
    'gateway': 'درگاه واردشده معتبر یا تحت پوشش نیست.',
}
NOTES = {
    'RightelMobileBillInquiry': 'MidTerm و FinalTerm شامل BillID، PaymentID، Amount و ExtraInfo هستند.',
    'NajiServiceDrivingLicenseValidateInquiry': 'StatusCode: صفر فاقد گواهینامه، یک ممنوعیت رانندگی، دو اعتبار منقضی، سه دارای گواهینامه تا تاریخ اعلام‌شده است.',
    'TopUpProductReserve': 'رزرو محصول انجام می‌شود. کلید خرید برای مرحلهٔ بعد صادر می‌شود.',
    'DoesBillAlreadyPaid': 'مقدار Paid وضعیت پرداخت در همین سامانه را گزارش می‌کند.',
    'BillPaymentInquiry': 'نتیجه به درگاه‌های استعلام‌شده محدود است.',
}


def initialize(db, schema):
    db.execute(f"""CREATE TABLE IF NOT EXISTS {schema}.provider_contracts(
        document text NOT NULL, document_sha256 text NOT NULL, pdf_page int NOT NULL,
        operation text NOT NULL, business_inputs text[] NOT NULL, tracking_inputs text[] NOT NULL,
        outcomes jsonb NOT NULL, PRIMARY KEY(document_sha256,operation))""")
    db.execute(f"""ALTER TABLE {schema}.provider_contracts
        ADD COLUMN IF NOT EXISTS documented_outputs text[] NOT NULL DEFAULT '{{}}',
        ADD COLUMN IF NOT EXISTS operation_note text""")
    with db.cursor() as cur:
        cur.executemany(f"""INSERT INTO {schema}.provider_contracts AS p
            (document,document_sha256,pdf_page,operation,business_inputs,tracking_inputs,outcomes,documented_outputs,operation_note)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT(document_sha256,operation) DO UPDATE SET
            (pdf_page,business_inputs,tracking_inputs,outcomes,documented_outputs,operation_note)=
            (excluded.pdf_page,excluded.business_inputs,excluded.tracking_inputs,excluded.outcomes,excluded.documented_outputs,excluded.operation_note)
            WHERE (p.pdf_page,p.business_inputs,p.tracking_inputs,p.outcomes,p.documented_outputs,p.operation_note)
            IS DISTINCT FROM (excluded.pdf_page,excluded.business_inputs,excluded.tracking_inputs,excluded.outcomes,excluded.documented_outputs,excluded.operation_note)""",
            [(*DOCS[r['document']], r['page'], r['operation'], r['business'], r['tracking'],
              Jsonb({code: dict(pdf_page=page, message_fa=MEANINGS[kind],
                                **{'class':'SUCCESS_NO_PAYABLE_BILL' if kind=='empty' else kind})
                     for code,(kind,page) in r['outcomes'].items()}), r['outputs'], NOTES.get(r['operation']))
             for r in CONTRACTS])


def observed_contract(body, state):
    """Match a provider exchange to its exact path. Outer success and provider result remain independent."""
    from compact_behavior import inquiry
    if state['issues']:
        return None
    candidates = [o for o in state['outputs'] if o['path'] in BY_CLIENT]
    if len(candidates) != 1:
        return None
    output = candidates[0]
    path = output['path']
    rule = BY_CLIENT.get(path)
    inputs = [i for i in state['inputs'] if i['path'] == path]
    if (not rule or len(inputs) != 1 or any(e['path']==path for e in state['parse_errors'])
            or output.get('observed_at_ns') is None
            or inputs[0].get('observed_at_ns') != output['observed_at_ns']):
        return None
    value = output.get('value')
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        return None
    item = value[0]
    status = item.get('Status')
    code = status.get('Code') if isinstance(status, dict) else None
    if not isinstance(code, str) or code not in rule['outcomes']:
        code = None
    if code and rule['outcomes'][code][0] in ('empty','paid_no_new'):
        # Keep the established no-bill proof: one session, successful public response,
        # matching subject, empty parameters and no conflicting binding.
        features = body['features']
        expected = features.get(inquiry.POLICY) or {}
        subjects = inquiry.subjects(body['service_key'],body['api'],'reviewed_same_request_provider',inputs[0])
        if (body['service_key'] != body['api'] or body['result_code'] != 'G00000'
                or not features['result_eligible'] or len(state['sessions']) != 1
                or 'Parameters' not in item or item['Parameters'] is not None or not subjects
                or any(expected.get(k) != v for k,v in subjects.items())):
            code = None
    return DOCS[rule['document']][1], rule['operation'], code


def observed_no_bill(body, state):
    match = observed_contract(body, state)
    return bool(match and match[1:] == ('MCIMobileBillInquiry', NO_BILL))
