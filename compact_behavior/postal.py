"""A typed cache return is output evidence only, never a submitted inquiry target."""
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
            return {'PostalCode': code}
    except (TypeError, KeyError, ValueError, RecursionError):
        pass
    return invalid
