"""Present existing typed links in one observed flow; never create a join."""
from datetime import datetime
from zoneinfo import ZoneInfo

from .viewer_execution_detail import _step

STEP_LIMIT = 160


def _time(proof):
    if proof.get('at_ns') is not None:
        return proof['at_ns']
    try:
        value = datetime.strptime(proof.get('when_fa', ''), '%Y-%m-%d %H:%M:%S')
        return int(value.replace(tzinfo=ZoneInfo('Asia/Tehran')).timestamp()) * 1_000_000_000
    except (ValueError, TypeError):
        return None


def observed_flow(card, initial_steps):
    steps = list(initial_steps)
    key = card['request_key']
    for step in steps:
        step.update(request_key=key, raw_request_id=card.get('raw_request_id'), related=False)
    seen = set()
    represented = {key}
    payment_cards = []
    payment_seen = set()
    payments = card.get('service_payments') or {}
    partial = bool(payments.get('truncated'))

    def add(kind, title, proof, *, subject='', invoice='', code=None, state='observed',
            description='', fields=(), api=''):
        identity = (kind, invoice, subject, proof.get('origin_key'), proof.get('version_key'), code)
        if identity in seen:
            return
        seen.add(identity)
        request_key = proof.get('request_key') or key
        represented.add(request_key)
        item = _step(kind, title, _time(proof), api=api, code=code, status=state,
                     description=description, proofs=[proof] if proof.get('origin_key') else [], fields=fields)
        item.update(request_key=request_key, raw_request_id=proof.get('raw_request_id'),
                    related=request_key != key)
        steps.append(item)

    outcomes = {
        'success': ('success', 'پرداخت موفق گزارش شده'),
        'failed': ('failure', 'پرداخت ناموفق گزارش شده'),
        'unobserved': ('unknown', 'نتیجهٔ پرداخت مشاهده نشده'),
        'multiple_statuses': ('mixed', 'چند وضعیت متفاوت؛ نتیجه نیازمند بررسی'),
        'partial_evidence': ('unknown', 'شواهد وضعیت پرداخت ناقص است'),
        'unknown': ('unknown', 'معنای وضعیت پرداخت مشخص نیست'),
    }
    for group in payments.get('invoices', []):
        invoice = group['invoice_id']
        for bill in group['bills']:
            for proof in bill['evidence']:
                add('bill_observed', 'قبض مرتبط با استعلام', proof,
                    subject=bill['bill_unique_id'], invoice=invoice,
                    fields=[('Invoice', invoice), ('BillUniqueID', bill['bill_unique_id'])])
        for category, title in (('inquiry_payments', 'پرداخت هزینهٔ استعلام'),
                                 ('bill_payments', 'پرداخت قبض')):
            for payment in group[category]:
                identity = (category, invoice, payment['identity_key'])
                state, label = outcomes.get(payment['outcome'], outcomes['unknown'])
                if partial:
                    state, label = 'unknown', 'نمای ارتباط یا وضعیت پرداخت ناقص است'
                if identity not in payment_seen:
                    payment_seen.add(identity)
                    payment_cards.append(dict(kind=category, title=title, payment_key=payment['payment_key'],
                        invoice=invoice, targets=payment['targets'], status=state, label=label,
                        status_values=payment['status_values']))
                fields = [('Invoice', invoice), ('PaymentKey', payment['payment_key'])]
                if payment['targets']:
                    fields.append(('شناسهٔ قبض‌های مرتبط', ' · '.join(payment['targets'])))
                for proof in payment['evidence']:
                    add(category, title, proof, subject=payment['identity_key'], invoice=invoice,
                        fields=fields, description='رابطهٔ پرداخت در لاگ ثبت شده است؛ نتیجه در گزارش وضعیت همان PaymentKey بررسی می‌شود.')
                for observation in payment['statuses']:
                    reported = observation['value']
                    reported_state = ('success' if reported == 'Success' else
                                      'failure' if reported == 'Failed' else 'unknown')
                    add(category + '_result', 'گزارش نتیجهٔ ' + title, observation['evidence'],
                        subject=payment['identity_key'], invoice=invoice, code=reported,
                        state=reported_state, fields=fields,
                        description='گزارش Backend برای همین PaymentKey؛ تسویهٔ بانکی یا نتیجهٔ مستقل تک‌تک اقلام از آن استنتاج نمی‌شود.')

    bill_journey = card.get('bill_item_journey') or {}
    for payment in payments.get('unresolved_payments', []):
        state, label = outcomes.get(payment['outcome'], outcomes['unknown'])
        if partial:
            state, label = 'unknown', 'نمای وضعیت پرداخت ناقص است'
        payment_cards.append(dict(kind='unresolved_payment', title='پرداخت با مبدأ سرویس نامشخص',
            payment_key=payment['payment_key'], invoice=None, targets=payment['targets'],
            status=state, label=label, status_values=payment['status_values']))
        for observation in payment['statuses']:
            value = observation['value']
            add('unresolved_payment_result', 'گزارش پرداخت با مبدأ نامشخص', observation['evidence'],
                subject=payment['identity_key'], code=value,
                state='success' if value=='Success' else 'failure' if value=='Failed' else 'unknown',
                fields=[('PaymentKey', payment['payment_key'])],
                description='انتساب این پرداخت به هزینهٔ استعلام یا قبض مشخص احراز نشده است.')
    for category, kind, title in (('basket_additions', 'basket', 'افزودن قلم به سبد'),
                                   ('payment_attempts', 'checkout', 'مرحلهٔ Checkout / پرداخت')):
        for item in bill_journey.get(category, []):
            proof = dict(item.get('evidence') or {}, request_key=item['request_key'],
                         raw_request_id=item.get('raw_request_id'), at_ns=item.get('at_ns'))
            if proof['at_ns'] is None:
                proof.pop('at_ns')
                proof['when_fa'] = item.get('when_fa')
            explicit = item.get('relation') == 'explicit_item_selection'
            title_for_item = title if explicit or kind == 'basket' else 'خواندن یا ارجاع قلم در Checkout'
            add(kind, title_for_item, proof, api=item.get('api', ''), fields=[
                ('شاهد ارتباط', 'انتخاب صریح قلم' if explicit else 'شناسهٔ مشترک قلم؛ فهرست نهایی پرداخت احراز نشده'),
                ('پاسخ API', item.get('root_code') or 'نامشخص')])

    for item in (card.get('service_journey') or {}).get('steps', []):
        if item['request_key'] in represented:
            continue
        role = item.get('role')
        payment = role == 'payment_execution'
        if payment:
            payment_cards.append(dict(kind='legacy_payment', title='درخواست پرداخت مرتبط',
                payment_key=None, invoice=None, targets=[], status='unknown',
                label='درخواست پرداخت مشاهده شده؛ نتیجهٔ مالی احراز نشده', status_values=[]))
        proof = dict(request_key=item['request_key'], at_ns=item.get('started_ns'))
        add('related_request', 'درخواست پرداخت مرتبط' if payment else 'درخواست مرتبط با مرجع مشترک',
            proof, api=item.get('api', ''), description='ارتباط از گراف نوع‌دار خدمت است؛ پاسخ API به معنی نتیجهٔ قطعی پرداخت نیست.',
            fields=[('پاسخ API', item.get('api_code') or 'نامشخص')])

    steps.sort(key=lambda s: (s['at_ns'] is None, s['at_ns'] or 0,
                             1 if s['kind'] in ('inquiry_result', 'api_response') else 0))
    incomplete = len(steps) > STEP_LIMIT or partial or bool(bill_journey.get('truncated'))
    return dict(steps=steps[:STEP_LIMIT], payment_cards=payment_cards[:32],
                payment_cards_truncated=len(payment_cards) > 32,
                incomplete=incomplete or len(payment_cards) > 32,
                linked_request_count=len(represented - {key}))
