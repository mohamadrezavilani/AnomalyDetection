"""Bounded display of existing payload metadata; no collection or identity inference."""

LABELS = {
    'ip': 'IP', 'clientip': 'Client IP', 'useragent': 'User-Agent',
    'deviceid': 'Device ID', 'appversion': 'App Version', 'platform': 'Platform',
}


def observed_context(state, collected=None):
    result = dict(items=[], scan_complete=True, features_only=False)
    if collected:
        from compact_behavior.context import source_label
        labels = {'ip': 'IP', 'user_agent': 'User-Agent', 'device_id': 'Device ID',
            'app_version': 'App Version', 'platform': 'Platform', 'application': 'Application', 'http_method': 'HTTP Method', 'origin': 'Origin'}
        result['collected'] = True
        result['limits'] = collected.get('limited', [])
        for name, values in collected.get('values', {}).items():
            for entry in values:
                result['items'].append(dict(label=labels.get(name, name), value=entry['value'], truncated=False,
                    direction='collected', source=' · '.join(source_label(s) for s in entry['sources']), location='', conflict=len(values)>1, observed_at_ns=entry.get('first_ns'), undated=entry.get('undated', False)))
        return result
    result['collected'] = False
    result['limits'] = []
    visited = 0

    def walk(value, path, direction, surface, depth=0):
        nonlocal visited
        visited += 1
        if visited > 2000 or depth > 20 or len(result['items']) >= 20:
            result['scan_complete'] = False
            return
        if isinstance(value, dict):
            for key, item in value.items():
                label = LABELS.get(str(key).lower().replace('_', '').replace('-', ''))
                location = path + '.' + str(key)
                if label and isinstance(item, (str, int, float)) and not isinstance(item, bool) and str(item).strip():
                    if len(result['items']) >= 20:
                        result['scan_complete'] = False
                        return
                    text = str(item)
                    result['items'].append(dict(label=label, value=text[:2048], truncated=len(text)>2048,
                        direction=direction, source=surface.get('path'), basis=surface.get('basis'), location=location))
                walk(item, location, direction, surface, depth + 1)
                if not result['scan_complete']:
                    return
        elif isinstance(value, list):
            for i, item in enumerate(value):
                walk(item, path + f'[{i}]', direction, surface, depth + 1)
                if not result['scan_complete']:
                    return

    for direction in ('inputs', 'outputs'):
        for surface in state.get(direction, []):
            if surface.get('representation') == 'FEATURES_ONLY_V1':
                result['features_only'] = True
                continue
            walk(surface.get('value'), '$', direction, surface)
            if not result['scan_complete']:
                return result
    return result
