"""Read-only presentation of an execution's observed steps and proven links.

No new relationships, roles or outcomes are persisted here. In particular,
Provider transport codes, inquiry results and payment reports stay separate.
"""
from __future__ import annotations

import json
import re
import zlib

from .service_dispatch import _block, api_path
from .viewer_data import tehran

EVENT_LIMIT = 240
PROVIDER_LIMIT = 32
INVOICE_LIMIT = 8
RELATED_LIMIT = 32
RAW_LIMIT = 2 * 1024 * 1024
COMPRESSED_LIMIT = 256 * 1024
CODE = re.compile(r'^G[A-Z0-9]{1,24}$')
STATUS_LABELS = dict(success='موفق', failure='ناموفق', unknown='نامشخص',
                     mixed='نیازمند بررسی', observed='ثبت شده')


def _status(code):
    return 'unknown' if not code else 'success' if code == 'G00000' else 'failure'


def _proof(row):
    return dict(origin_key=row['origin_key'], version_key=row['version_key'],
                callpath=row.get('callpath'), at_ns=row.get('at_ns'),
                value=row.get('value'), field_path=row.get('field_path'))


def _step(kind, title, at_ns, *, api='', code=None, status=None,
          description='', proofs=(), fields=()):
    state = status or _status(code)
    return dict(kind=kind, title=title, at_ns=at_ns, when=tehran(at_ns),
                api=api, code=code, status=state, status_label=STATUS_LABELS[state],
                description=description, proofs=list(proofs), fields=list(fields))


def _provider_body(payload):
    if payload is None:
        return {}
    try:
        decoder = zlib.decompressobj()
        data = decoder.decompress(bytes(payload), RAW_LIMIT + 1)
        if len(data) > RAW_LIMIT or not decoder.eof:
            return {}
        raw = json.loads(data.decode('utf-8'))
        message = raw.get('message')
        return dict(output=_block(message, 'Output:'), input=_block(message, 'Input:')) if isinstance(message, str) else {}
    except (ValueError, TypeError, UnicodeError, zlib.error):
        return {}


def execution_detail(db, card):
    """Compose one bounded page in the caller's read-only snapshot."""
    key = card['request_key']
    events = db.all('''SELECT e.origin_key,e.version_key,e.at_ns,e.kind,e.callpath,e.code,
        (SELECT COUNT(*) FROM viewer_events v WHERE v.origin_key=e.origin_key) AS variants
        FROM viewer_events e WHERE e.request_key=?
        ORDER BY e.at_ns,e.origin_key,e.version_key LIMIT ?''', (key, EVENT_LIMIT + 1))
    truncated = len(events) > EVENT_LIMIT
    events = events[:EVENT_LIMIT]
    conflicted = bool(card.get('conflicted'))
    context = card.get('service_context') or {}
    facts = context.get('evidence', []) if not conflicted else []
    report_facts = [f for f in facts if f['axis'] == 'inquiry_result']
    report_overflow = False
    if not context and not conflicted:
        observed = db.all('''SELECT o.* FROM viewer_contract_observations o
            WHERE o.request_key=? AND o.axis='service_dispatch.inquiry_result'
              AND (SELECT COUNT(*) FROM viewer_events v WHERE v.origin_key=o.origin_key)=1
              AND EXISTS(SELECT 1 FROM viewer_events v WHERE v.origin_key=o.origin_key
                         AND v.version_key=o.version_key)
            ORDER BY o.at_ns,o.origin_key LIMIT 129''', (key,))
        report_overflow = len(observed) > 128
        report_facts = [] if report_overflow else observed
        truncated = truncated or report_overflow
    reports = sorted({f['value'] for f in report_facts})
    transport = card.get('transport_root_call') or card.get('root_call') or ''
    api = api_path(card.get('root_call'))
    result_basis = 'نتیجهٔ استعلام' if reports or report_overflow else 'پاسخ API'
    result_codes = reports or ([card['root_code']] if card.get('root_code') and not report_overflow else [])
    result_status = ('mixed' if conflicted or len(result_codes) > 1 else
                     _status(result_codes[0] if result_codes else None))
    result_label = STATUS_LABELS[result_status]
    prerequisite_labels = {
        'otp_required': ('observed', 'نیاز به OTP'),
        'selection_pending': ('observed', 'فهرست افراد دریافت شده'),
        'otp_verified_result_pending': ('observed', 'OTP تأیید شده'),
        'otp_verification_failed': ('failure', 'تأیید OTP ناموفق'),
        'otp_not_required_result_pending': ('unknown', 'نتیجهٔ استعلام مشاهده نشده'),
        'prerequisite_conflict': ('mixed', 'شواهد متعارض'),
        'service_stage_unknown': ('unknown', 'مرحلهٔ نامشخص'),
    }
    if not reports and context.get('phase') in prerequisite_labels and not conflicted:
        result_status, result_label = prerequisite_labels[context['phase']]
        result_basis = 'مرحلهٔ مشاهده‌شدهٔ سرویس'
        result_codes = context.get('otp_validation_codes', [])

    invoice_rows = db.all('''SELECT DISTINCT c.raw_value
        FROM viewer_contract_identifiers c
        WHERE c.request_key=? AND c.issuer='pishkhan24' AND c.kind='invoice'
          AND (SELECT COUNT(*) FROM viewer_events v WHERE v.origin_key=c.origin_key)=1
          AND EXISTS(SELECT 1 FROM viewer_events v WHERE v.origin_key=c.origin_key
                     AND v.version_key=c.version_key)
        ORDER BY c.raw_value LIMIT ?''', (key, INVOICE_LIMIT + 1)) if not conflicted else []
    invoices = [r['raw_value'] for r in invoice_rows[:INVOICE_LIMIT]]
    truncated = truncated or len(invoice_rows) > INVOICE_LIMIT

    steps = []
    start_proofs = [_proof(f) for f in facts if f['axis'] in ('access', 'invoice_request')]
    if not start_proofs:
        start_proofs = [_proof(e) for e in events if e['kind'] == 'client'
                        and api_path(e['callpath']) == api_path(transport) and e['variants'] == 1][:4]
    if start_proofs:
        steps.append(_step('request', 'درخواست سرویس', card.get('started_ns'), api=api,
                           status='mixed' if conflicted else 'observed', proofs=start_proofs,
                           description='درخواست ثبت شده است؛ شروع دستی از این شاهد تعیین نمی‌شود.'))

    # One bounded indexed read, not a per-Provider raw lookup or a full raw scan.
    provider_rows = db.all('''SELECT e.origin_key,e.version_key,
        CASE WHEN length(r.payload)<=? THEN r.payload ELSE NULL END AS payload
        FROM viewer_events e LEFT JOIN viewer_raw_events r
          ON r.origin_key=e.origin_key AND r.version_key=e.version_key
        WHERE e.request_key=? AND e.kind='provider'
        ORDER BY e.at_ns,e.origin_key,e.version_key LIMIT ?''',
        (COMPRESSED_LIMIT, key, PROVIDER_LIMIT + 1))
    truncated = truncated or len(provider_rows) > PROVIDER_LIMIT
    bodies = {(r['origin_key'], r['version_key']): r['payload']
              for r in provider_rows[:PROVIDER_LIMIT]}
    methods = {
        'ClientAyanCoInquiry.MyGovRequestOtp': ('otp_request', 'بررسی نیاز به OTP'),
        'ClientAyanCoInquiry.MyGovLogin': ('otp_validation', 'تأیید OTP'),
        'ClientAyanCoInquiry.TaminUnderCoveredInquiry': ('under_covered', 'دریافت فهرست افراد تحت پوشش'),
    }
    highlights = []
    for event in events:
        if event['kind'] != 'provider' or (event['origin_key'], event['version_key']) not in bodies:
            continue
        method = api_path(event['callpath'])
        kind, title = methods.get(method, ('provider', 'فراخوانی سرویس‌دهنده'))
        clean = event['variants'] == 1 and not conflicted
        decoded = _provider_body(bodies[(event['origin_key'], event['version_key'])]) if clean else {}
        output = decoded.get('output', {})
        status = output.get('Status')
        code = status.get('Code') if isinstance(status, dict) else None
        if not isinstance(code, str) or not CODE.fullmatch(code):
            code = None
        description = ''
        parameters = output.get('Parameters')
        if kind == 'otp_request' and code == 'G00000' and isinstance(parameters, dict):
            required = parameters.get('OtpRequired')
            if type(required) is bool:
                description = 'نیاز به OTP گزارش شده است.' if required else 'در این مرحله OTP لازم نبوده است.'
        elif isinstance(status, dict) and isinstance(status.get('Description'), str) and code:
            description = status['Description'][:300]
        fields = [('پاسخ ارتباطی Provider', event['code'] or 'نامشخص'),
                  ('نتیجهٔ داخل پاسخ Provider', code or 'خوانده نشده / نامشخص')]
        # Exact source DTO mapping only. Postal fields never become join keys.
        if clean and api == 'Services.v1/PostPackagesStatus' and method == 'ClientAyanCoInquiry.PostTrackingInquiry':
            number = decoded.get('input', {}).get('PackageNumber')
            if isinstance(number, str) and re.fullmatch(r'[0-9A-Za-z]{1,28}', number):
                fields.append(('کد رهگیری در ورودی', number))
                if not any(h['value'] == number for h in highlights):
                    highlights.append(dict(label='کد رهگیری', value=number, proof=_proof(event)))
            if code == 'G00000' and isinstance(parameters, dict):
                for name, label in (('Source', 'مبدأ گزارش‌شده'), ('Destination', 'مقصد گزارش‌شده')):
                    value = parameters.get(name)
                    if isinstance(value, str) and value and len(value) <= 240:
                        fields.append((label, value))
        steps.append(_step(kind, title, event['at_ns'], api=method, code=code,
                           status='mixed' if not clean else None, description=description,
                           proofs=[_proof(event)], fields=fields))

    if report_facts:
        steps.append(_step('inquiry_result', 'نتیجهٔ استعلام', min(f['at_ns'] for f in report_facts),
                           code=reports[0] if len(reports) == 1 else None,
                           status='mixed' if len(reports) > 1 else None,
                           description=' · '.join(reports), proofs=[_proof(f) for f in report_facts],
                           fields=[('منبع نتیجه', 'ud_prc_inquiryInvoiceResult2')]))
    elif card.get('root_code'):
        roots = [_proof(e) for e in events if e['kind'] == 'client'
                 and api_path(e['callpath']) == api_path(transport)]
        steps.append(_step('api_response', 'پاسخ API', card.get('root_ns') or card.get('ended_ns'),
                           api=api_path(transport), code=card['root_code'],
                           status='mixed' if conflicted else None, proofs=roots,
                           description='نتیجهٔ همین فراخوانی API؛ نتیجهٔ مالی جدا بررسی می‌شود.'))
    for event in events:
        if event['kind']=='sql' and event['callpath'].endswith('.ud_prc_invoiceRegister'):
            steps.append(_step('invoice_register', 'ثبت Invoice در سرویس', event['at_ns'],
                status='mixed' if conflicted or event['variants']!=1 else 'observed',
                description='فراخوانی ثبت Invoice مشاهده شده است؛ این مرحله، گزارش پرداخت نیست.',
                proofs=[_proof(event)], fields=[('Invoice', ' · '.join(invoices) or 'نامشخص')]))
    steps.sort(key=lambda s: (s['at_ns'] is None, s['at_ns'] or 0,
                             1 if s['kind'] in ('inquiry_result', 'api_response') else 0))

    payments = card.get('service_payments') or {}
    related = []
    seen = set()

    def add_related(request_key, raw_id, label, basis, when=None, code=None, proof=None):
        if request_key == key or not request_key:
            return
        identity = (request_key, label, basis, code)
        if identity in seen:
            return
        seen.add(identity)
        related.append(dict(request_key=request_key, raw_request_id=raw_id,
                            label=label, basis=basis, when=when, code=code, proof=proof))

    fee_keys = set()
    bill_keys = set()
    for group in payments.get('invoices', []):
        for category, label, target in (('inquiry_payments', 'پرداخت هزینهٔ استعلام', fee_keys),
                                        ('bill_payments', 'پرداخت قبض', bill_keys)):
            for payment in group[category]:
                target.add(payment['identity_key'])
                for proof in payment['evidence']:
                    add_related(proof['request_key'], proof['raw_request_id'], label,
                                'Invoice / PaymentKey' if category == 'inquiry_payments' else 'BillUniqueID / PaymentKey',
                                proof['when_fa'], proof=proof)
                for observation in payment['statuses']:
                    proof = observation['evidence']
                    add_related(proof['request_key'], proof['raw_request_id'], 'گزارش وضعیت پرداخت',
                                'PaymentKey', proof['when_fa'], code=observation['value'], proof=proof)

    bill_journey = card.get('bill_item_journey') or {}
    for category, label in (('basket_additions', 'افزودن قلم به سبد'),
                             ('payment_attempts', 'مرحلهٔ پرداخت / خواندن سبد')):
        for item in bill_journey.get(category, []):
            basis = ('انتخاب صریح قلم' if item.get('relation') == 'explicit_item_selection'
                     else 'ارجاع به شناسهٔ قلم؛ فهرست نهایی پرداخت تأیید نشده')
            add_related(item['request_key'], item.get('raw_request_id'), label, basis,
                        item.get('when_fa'), item.get('root_code'), item.get('evidence'))
    for step in (card.get('service_journey') or {}).get('steps', []):
        add_related(step['request_key'], step.get('request_id'), step.get('api') or step.get('role'),
                    'اشتراک مرجع نوع‌دار در گراف خدمت', code=step.get('api_code'))

    incomplete = bool(truncated or payments.get('truncated') or bill_journey.get('truncated') or
                      (card.get('service_journey') or {}).get('truncated') or len(related) > RELATED_LIMIT)
    start, end = card.get('started_ns'), card.get('ended_ns')
    duration = f'{(end - start) / 1_000_000_000:.3f}' if start is not None and end is not None and end >= start else None
    from .viewer_execution_flow import observed_flow
    flow=observed_flow(card,steps)
    return dict(service=api, transport=api_path(transport), result_basis=result_basis,
                result_status=result_status, result_label=result_label, result_codes=result_codes,
                invoices=invoices, highlights=highlights, steps=flow['steps'], related=related[:RELATED_LIMIT],
                payment_cards=flow['payment_cards'],linked_request_count=flow['linked_request_count'],
                fee_payment_count=len(fee_keys), bill_payment_count=len(bill_keys),
                has_payments=bool(payments), has_bill_items=bool(bill_journey.get('bill_item_count')),
                incomplete=incomplete or flow['incomplete'], conflicted=conflicted, duration_seconds=duration,
                otp_observed=any(s['kind'].startswith('otp_') for s in steps),
                related_count=len({r['request_key'] for r in related}))
