"""Bounded request-scoped observations, separate from model features and identity."""
from functools import lru_cache
import ipaddress
import re

CONTROL = re.compile(r"[\x00-\x1f]")

VERSION = 'compact-request-context-1'
MAX_VALUES = 4
MAX_SOURCES = 2
SQL_PATHS = {
    'DBPath.pishkhan24.application.ud_prc_userSessionHasAccess',
    'DBPath.pishkhan24.application.ud_prc_userSessionCreate',
    'DBPath.pishkhan24.application.ud_prc_userSessionUpdateInfo',
}
SQL_FIELDS = {'ipaddress': 'ip', 'useragent': 'user_agent', 'application': 'application',
              'platform': 'platform', 'version': 'app_version'}
LOG_FIELDS = {'IP': 'ip', 'UserAgent': 'user_agent', 'userAgent': 'user_agent'}


def empty():
    return {'version': VERSION, 'values': {}, 'limited': []}


@lru_cache(maxsize=8192)
def normalized_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        # IPv4-mapped IPv6 is the same address; do not split one observation.
        return str(ip.ipv4_mapped) if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else str(ip)
    except ValueError:
        return None


def observe(context, field, value, source):
    if not isinstance(value, str):
        return
    value = value.strip()
    if not value or value.upper() in ('N/A', 'NULL', 'NONE', 'UNKNOWN', '-'):
        return
    if field == 'ip':
        if len(value) > 64:
            return
        value = normalized_ip(value)
        if value is None:
            return
    else:
        limit = 1024 if field == 'user_agent' else 128
        if CONTROL.search(value):
            return
        if len(value) > limit:
            # Do not retain a truncated value as if it were the original.
            context['limited'] = sorted(set(context['limited'] + [field + '_length']))
            return
    values = context['values'].setdefault(field, [])
    for entry in values:
        if entry['value'] == value:
            sources = sorted(set(entry['sources'] + [source]))
            entry['sources'] = sources[:MAX_SOURCES]
            return
    values.append({'value': value, 'sources': [source]})
    values.sort(key=lambda e: e['value'])
    if len(values) > MAX_VALUES:
        del values[MAX_VALUES:]
        context['limited'] = sorted(set(context['limited'] + [field + '_variants']))


def from_log(row):
    result = empty()
    source = row.get('_source', row if 'fields' not in row else {})
    for data in (source, row.get('fields', {})):
        if not isinstance(data, dict):
            continue
        for name, target in LOG_FIELDS.items():
            value = data.get(name)
            for item in value if isinstance(value, list) else [value]:
                observe(result, target, item, 'log.' + name)
    return result if result['values'] or result['limited'] else {}


def combine(a, b):
    if not a:
        return b or {}
    if not b or a == b:
        return a
    limited = sorted(set(a['limited'] + b['limited']))
    values = dict(a['values'])
    changed = limited != a['limited']
    for name, incoming in b['values'].items():
        prior = values.get(name, [])
        if prior == incoming:
            continue
        entries = {e['value']: e for e in prior}
        field_changed = False
        for entry in incoming:
            old = entries.get(entry['value'])
            if old is None:
                entries[entry['value']] = entry
                field_changed = True
            elif any(source not in old['sources'] for source in entry['sources']):
                sources = sorted(set(old['sources'] + entry['sources']))[:MAX_SOURCES]
                if sources != old['sources']:
                    entries[entry['value']] = {'value': entry['value'], 'sources': sources}
                    field_changed = True
        if field_changed:
            if len(entries) > MAX_VALUES:
                limited = sorted(set(limited + [name + '_variants']))
            values[name] = [entries[k] for k in sorted(entries)[:MAX_VALUES]]
            changed = True
    return {'version': VERSION, 'values': values, 'limited': limited} if changed else a


def from_payload(value, source):
    """Supplementary body observations, never asserted to be client headers."""
    context = empty()
    names = {'ip': 'ip', 'ipaddress': 'ip', 'clientip': 'ip', 'useragent': 'user_agent',
             'deviceid': 'device_id', 'appversion': 'app_version', 'platform': 'platform',
             'application': 'application'}
    remaining = 256
    def walk(item, depth):
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > 6:
            context['limited'] = sorted(set(context['limited'] + ['payload_scan']))
            return
        if isinstance(item, dict):
            for key, child in item.items():
                target = names.get(str(key).lower().replace('_', '').replace('-', ''))
                if target:
                    observe(context, target, child, source + '.' + str(key)[:64])
                if isinstance(child, (dict, list)):
                    walk(child, depth + 1)
                if remaining < 0:
                    break
        elif isinstance(item, list):
            for child in item:
                walk(child, depth + 1)
                if remaining < 0:
                    break
    walk(value, 0)
    return context if context['values'] or context['limited'] else {}
