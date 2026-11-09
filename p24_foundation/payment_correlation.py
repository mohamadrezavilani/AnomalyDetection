"""Owner-confirmed core correlation messages, deployed 2026-10-28.

Only exact headers, trusted emitters and explicit JSON fields establish facts.
The original identifier spelling/value and every array position remain evidence.
"""
from __future__ import annotations
import json
import re

EMITTERS = {
    'InvoiceID-PaymentKey': ('InvoicePaymentHandler.Operation',),
    'InvoiceID-BillUniqueIDs': ('CommandHandlerBase.ReportInvoiceResult',),
    'BillUniqueIDs-PaymentKey': ('BillsPaymentHandler.Execute',),
    'PaymentKey-Status': ('PaymentCallbackHandler.Execute', 'WalletPaymentHandler.Execute',
                          'EwanoPaymentHandler.VerifyRequest'),
}
HEADER = re.compile(r'^correlation: (InvoiceID-PaymentKey|InvoiceID-BillUniqueIDs|BillUniqueIDs-PaymentKey|PaymentKey-Status)\s+(\{.*\})\s*$', re.S)
ID = re.compile(r'^[0-9A-Fa-f]{32}$')
STATUS_AXIS = 'core_payment_correlation_status'


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate_correlation_json_key')
        result[key] = value
    return result


def correlation_facts(raw):
    message = raw.get('message')
    if not isinstance(message, str):
        return None
    match = HEADER.fullmatch(message)
    if not match:
        return None
    label = match[1]
    if str(raw.get('CallPath') or '').split(' Line:', 1)[0] not in EMITTERS[label]:
        return None
    try:
        payload = json.loads(match[2], object_pairs_hook=_unique_object)
    except (ValueError, TypeError, RecursionError):
        return None
    if not isinstance(payload, dict):
        return None
    fields = []
    edges = []
    states = []

    def identifier(name, kind):
        value = payload.get(name)
        if not isinstance(value, str) or not ID.fullmatch(value):
            raise ValueError('invalid_correlation_identifier')
        fields.append(('pishkhan24', kind, '', 'message.correlation.' + name, value))
        return value

    try:
        invoice = payment = None
        if label.startswith('InvoiceID-'):
            aliases = [key for key in ('invoiceID', 'InvoiceID') if key in payload]
            if not aliases or len({str(payload[key]) for key in aliases}) != 1:
                return None
            invoice = identifier(aliases[0], 'invoice')
        if 'PaymentKey' in label:
            payment = identifier('PaymentKey', 'internal_payment')
        if 'BillUniqueIDs' in label:
            bills = payload.get('BillUniqueIDs')
            if not isinstance(bills, list):
                return None
            for index, bill in enumerate(bills):
                if not isinstance(bill, str) or not ID.fullmatch(bill):
                    return None
                path = 'message.correlation.BillUniqueIDs[' + str(index) + ']'
                fields.append(('pishkhan24', 'bill_unique_id', '', path, bill))
                if invoice:
                    edges.append(('invoice_produces_bill', 'invoice', invoice, 'bill_unique_id', bill,
                                  'message.correlation.' + aliases[0] + '+BillUniqueIDs[' + str(index) + ']'))
                else:
                    edges.append(('bill_targets_payment', 'bill_unique_id', bill, 'internal_payment', payment,
                                  path + '+PaymentKey'))
        if label == 'InvoiceID-PaymentKey':
            edges.append(('invoice_targets_fee_payment', 'invoice', invoice, 'internal_payment', payment,
                          'message.correlation.' + aliases[0] + '+PaymentKey'))
        if label == 'PaymentKey-Status':
            value = payload.get('Status')
            if not isinstance(value, str) or not value or len(value) > 160:
                return None
            states.append((STATUS_AXIS, value, 'message.correlation.Status'))
    except (ValueError, TypeError):
        return None
    return dict(label=label, identifiers=fields, edges=edges, states=states)
