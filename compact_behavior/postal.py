"""A typed cache return is output evidence only, never a submitted inquiry target."""
from datetime import datetime
import json
import re

from .json_value import unique_object

SERVICE = 'Services.v1/PostalCodeToAddress'
CACHE = 'CacheCoreApi.HandleRequest'
BASIS = 'postal_cache_return'
CACHE_TYPE = 'v1_InquiryPostalCodeToAddress'
CACHE_HEADER = 'https://cachecore.infra.ayantech.ir/api/Cache/Get (G00000 | successful)'
MAX_CHARS = 65536


def cache_projection(message):
    """Return only the postal field. An ambiguous typed reply can veto another reply."""
    if not message.startswith(CACHE_HEADER) or CACHE_TYPE not in message:
        return None
    invalid = {'PostalCode': None}
    if len(message) > MAX_CHARS:
        return invalid
    lines = message.splitlines()
    if len(lines) != 3 or lines[0] != CACHE_HEADER or not lines[1].startswith('Input:') or not lines[2].startswith('Output:'):
        return invalid
    try:
        envelope = json.loads(lines[2][7:], object_pairs_hook=unique_object)
        if not isinstance(envelope, list) or len(envelope) != 1:
            return invalid
        item = envelope[0]
        params = item['Parameters']
        if params['Type'] != CACHE_TYPE:
            return None
        if item['Status']['Code'] != 'G00000' or not isinstance(params['CacheContent'], str):
            return invalid
        data = json.loads(params['CacheContent'], object_pairs_hook=unique_object)
        code = data['PostalCode']
        if isinstance(code, str) and re.fullmatch('[0-9]{10}', code):
            projection = {'PostalCode': code}
            reported = params.get('ReportDateTime')
            if isinstance(reported, str) and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})?', reported):
                try:
                    datetime.fromisoformat(reported)
                except ValueError:
                    pass
                else:
                    projection['ReportDateTime'] = reported
            return projection
    except (TypeError, KeyError, ValueError, RecursionError):
        pass
    return invalid


PROVIDER = 'ClientAyanCoInquiry.PostalCodeToAddress'
# This exact CallPath and URL come from ClientAyanCoInquiry.PostalCodeToAddress.
CONTACT_HEADER = re.compile(
    r'https?://core2\.inquiry\.ayantech\.ir(?::(?:80|443))?/WebServices/Core\.svc/PostalCodeToAddress'
    r' \(([A-Z]{1,3}[0-9]{4,6}) \| [^()\r\n]{1,128}\)'
)
CONTACT_KINDS = ('success', 'error', 'uncertain')


def contact_kind(message, outputs):
    # Read only the bounded header. The ordinary payload extractor already
    # decoded the response; no extra JSON parse or copy of the address.
    line_end = message.find('\n', 0, 384)
    header = message[:line_end if line_end >= 0 else 384].rstrip('\r')
    match = CONTACT_HEADER.fullmatch(header)
    if not match:
        return None
    value = outputs[0].get('value') if len(outputs) == 1 else None
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    status = value.get('Status') if isinstance(value, dict) else None
    code = status.get('Code') if isinstance(status, dict) else None
    if match[1] != 'G00000':
        return 'uncertain' if code == 'G00000' else 'error'
    if isinstance(code, str) and re.fullmatch('[A-Z]{1,3}[0-9]{4,6}', code):
        if code != 'G00000':
            return 'error'
        params = value.get('Parameters')
        if isinstance(params, dict) and isinstance(params.get('PostalCode'), str) and re.fullmatch('[0-9]{10}', params['PostalCode']):
            return 'success'
    return 'uncertain'


def merge_contacts(left, right):
    """At most two event timestamps per outcome, across duplicates and revisions."""
    result = dict(left)
    for kind, (first, last) in right.items():
        a, b = result.get(kind, (first, last))
        result[kind] = [min(a, first), max(b, last)]
    return result


def observe(window, row, cutoff):
    """Count logical public operations. A request may show a provider retry and a cache hit."""
    f = row['features']

    def add(name, at=None):
        window[name] = window.get(name, 0) + 1
        if at is not None:
            key = 'last_' + name
            window[key] = max(window.get(key, at), at)

    add('requests')
    if f.get('result_eligible') and row.get('result_code'):
        add('public_success' if row['result_code'] == 'G00000' else 'public_error')
    cached = f.get('postal_cache_returned_at_ns')
    cache_seen = type(cached) is int and (cutoff is None or cached < cutoff)
    if cache_seen:
        add('cache', cached)
    contacts = f.get('postal_contacts') or {}
    for kind, (first, last) in contacts.items():
        if cutoff is None or first < cutoff:
            add(kind, last if cutoff is None or last < cutoff else first)
    direct = contacts.get('success')
    direct_seen = direct is not None and (cutoff is None or direct[0] < cutoff)
    if f.get('result_eligible') and row.get('result_code') == 'G00000' and not cache_seen and not direct_seen:
        add('unattributed_success')
