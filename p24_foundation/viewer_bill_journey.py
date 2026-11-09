"""Read-only, bounded bill-item navigation; never a payment-finality model."""
from __future__ import annotations

import json
import re
from collections import defaultdict
from functools import wraps

from .parser import sql_parameters

PAYMENT_ROOTS = frozenset({'UserBasketPayment', 'BillsPayment', 'InvoicePayment', 'WalletPayment'})


def read_scope(method):
    """A reader reused after a late publication must not retain old fingerprints."""
    @wraps(method)
    def scoped(self, *args, **kwargs):
        depth = getattr(self, '_bill_read_depth', 0)
        if not depth:
            self._journey_fingerprint_cache = {}
        self._bill_read_depth = depth + 1
        try:
            return method(self, *args, **kwargs)
        finally:
            self._bill_read_depth = depth
            if not depth:
                self._journey_fingerprint_cache = {}
    return scoped


def cache_items(value, path, depth=0):
    """Retain a field locator even inside JSON encoded in CacheContent."""
    from .viewer_data import HEXISH, clean_scalar
    if depth > 8:
        return
    if isinstance(value, dict):
        val = clean_scalar(value.get('UniqueID'))
        if val and HEXISH.fullmatch(val):
            yield val, path + '.UniqueID'
        for name, child in value.items():
            yield from cache_items(child, path + '.' + str(name), depth + 1)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from cache_items(child, path + '[' + str(index) + ']', depth + 1)
    elif isinstance(value, str) and value.lstrip().startswith(('[', '{')):
        try:
            decoded = json.loads(value)
        except (ValueError, TypeError):
            return
        yield from cache_items(decoded, path + '{json}', depth + 1)


class BillItemJourneyMixin:
    def _bill_item_fingerprints(self, request_key, *, role):
        from .viewer_data import HEXISH, message_json, token
        cache_key = (request_key, role)
        if not hasattr(self, '_journey_fingerprint_cache'):
            self._journey_fingerprint_cache = {}
        if getattr(self, '_bill_read_depth', 0) and cache_key in self._journey_fingerprint_cache:
            return self._journey_fingerprint_cache[cache_key]
        req = self.one('SELECT conflicted FROM viewer_requests WHERE request_key=?', (request_key,))
        if not req or req['conflicted']:
            return {}
        clean = ('''NOT EXISTS(SELECT 1 FROM viewer_events c WHERE c.origin_key=e.origin_key
                    AND c.version_key<>e.version_key)''' if self.sqlite else
                 '''(SELECT COUNT(*) FROM viewer_events c WHERE c.origin_key=e.origin_key)=1''')
        rows = self.all('''SELECT e.origin_key,e.version_key,e.callpath FROM viewer_events e
            WHERE e.request_key=? AND (e.callpath LIKE ? OR e.callpath LIKE ?) AND ''' + clean,
            (request_key, 'CacheCoreApi.%', 'DBPath.%ud_prc_billsBelongs%'))
        results = defaultdict(list)
        for event in rows:
            raw = self.get_raw(event['origin_key'], event['version_key'])
            if not raw:
                continue
            message = raw.get('message', '')
            found = []
            if event['callpath'].startswith('CacheCoreApi.'):
                operation = 'Cache/Add' if role == 'inquiry' else 'Cache/Get'
                marker = 'Input:' if role == 'inquiry' else 'Output:'
                if operation in message:
                    data = message_json(message, marker)
                    if isinstance(data, list):
                        for index, envelope in enumerate(data):
                            params = envelope.get('Parameters') if isinstance(envelope, dict) else None
                            if isinstance(params, dict):
                                found.extend(cache_items(params.get('CacheContent'),
                                    'message.' + marker[:-1] + '[' + str(index) + '].Parameters.CacheContent'))
            elif role in ('basket_add', 'payment') and 'ud_prc_billsBelongs' in event['callpath']:
                try:
                    params, _ = sql_parameters(message)
                    for index, part in enumerate(re.split(r'[,;]', str(params.get('bills') or ''))):
                        part = part.strip().strip('[]"\'')
                        if HEXISH.fullmatch(part):
                            found.append((part, 'message.SQL Parameters.@bills[' + str(index) + ']'))
                except (ValueError, TypeError):
                    pass
            for value, path in found:
                evidence = dict(event, field_path=path, raw_item_id=value)
                key = token(self.keys, 'bill_unique_id', value.lower())
                if evidence not in results[key]:
                    results[key].append(evidence)
        out = dict(results)
        if getattr(self, '_bill_read_depth', 0):
            self._journey_fingerprint_cache[cache_key] = out
        return out

    def _bill_neighbors(self, request):
        """Two indexed pages around this request, with explicit incompleteness."""
        limit = getattr(self, '_bill_journey_page_limit', 128)
        anchor = request['ended_ns']
        if anchor is None:
            return [], True
        rows = []
        truncated = False
        for relation, order in (('<=', 'DESC'), ('>', 'ASC')):
            batch = self.all('''SELECT r.request_key,r.session_key,r.started_ns,r.ended_ns,
                    r.root_call,r.root_ns,r.root_code,r.conflicted,a.current_outcome
                FROM viewer_requests r LEFT JOIN viewer_actions a ON a.action_key=r.request_key
                WHERE r.session_key=? AND r.ended_ns ''' + relation + ''' ?
                ORDER BY r.ended_ns ''' + order + ',r.request_key ' + order + ' LIMIT ?',
                (request['session_key'], anchor, limit + 1))
            truncated = truncated or len(batch) > limit
            rows.extend(batch[:limit])
        return rows, truncated

    def _bill_step(self, candidate, inquiry_items, fingerprints, role):
        from .viewer_data import core_name, service_path, tehran
        common = sorted(inquiry_items.keys() & fingerprints.keys())
        if not common:
            return None
        witnesses = [(key, proof) for key in common for proof in fingerprints[key]]
        explicit = [(key, proof) for key, proof in witnesses if 'ud_prc_billsBelongs' in proof['callpath']]
        key, proof = (explicit or witnesses)[0]
        relation = ('explicit_item_selection' if explicit else
                    'basket_readset_observed_during_checkout' if role == 'payment' else 'referenced_snapshot_item')
        item_evidence=[dict(item_id=inquiry_items[k][0]['raw_item_id'],
            relation=('explicit_item_selection' if any('ud_prc_billsBelongs' in p['callpath'] for p in fingerprints[k])
                      else 'basket_readset_observed_during_checkout' if role=='payment' else 'referenced_snapshot_item'),
            inquiry_evidence=list(inquiry_items[k]),step_evidence=list(fingerprints[k])) for k in common]
        return dict(request_key=candidate['request_key'],raw_request_id=self.raw_request_id(candidate['request_key']),
            service=core_name(candidate['root_call']),api=service_path(candidate['root_call']),
            when_fa=tehran(candidate['root_ns']),at_ns=candidate['root_ns'],root_code=candidate['root_code'],linked_items=len(common),
            relation=relation,evidence=proof,inquiry_evidence=inquiry_items[key][0],item_evidence=item_evidence,
            explicit_selection_item_count=sum(x['relation']=='explicit_item_selection' for x in item_evidence),
            frozen_manifest_proven=False,financial_outcome=candidate.get('current_outcome'),
            method='unknown',provider_rail='unknown',financial_confirmed=False,financial_reported=False)

    @read_scope
    def inquiry_payment_journey(self, request_key):
        from .viewer_data import INQUIRIES, core_name
        inquiry = self.one('SELECT * FROM viewer_requests WHERE request_key=?', (request_key,))
        base = dict(status='unresolved',basket_additions=[],payment_attempts=[],bill_item_count=0,
                    confidence='not_established',truncated=False)
        if (not inquiry or inquiry['conflicted'] or not inquiry['session_key'] or
                core_name(inquiry['root_call'] or '') not in INQUIRIES):
            return base
        items = self._bill_item_fingerprints(request_key, role='inquiry')
        base['bill_item_count'] = len(items)
        if not items:
            return base
        base['confidence'] = 'exact_bill_item_id'
        candidates, base['truncated'] = self._bill_neighbors(inquiry)
        for candidate in candidates:
            if candidate['request_key'] == request_key or candidate['conflicted']:
                continue
            if candidate['root_ns'] is not None and candidate['root_ns'] < (inquiry['root_ns'] or 0):
                continue
            name = core_name(candidate['root_call'] or '')
            role = 'basket_add' if name == 'UserBasketAddBills' else 'payment' if name in PAYMENT_ROOTS else None
            if not role:
                continue
            step = self._bill_step(candidate, items,
                self._bill_item_fingerprints(candidate['request_key'], role=role), role)
            if step:
                base['basket_additions' if role == 'basket_add' else 'payment_attempts'].append(step)
        for name in ('basket_additions', 'payment_attempts'):
            base[name].sort(key=lambda r:(r['when_fa'],r['request_key']))
        base['status'] = ('payment_stage_reference_observed' if base['payment_attempts'] else
                          'basket_added' if base['basket_additions'] else 'no_downstream_step_observed')
        return base

    @read_scope
    def bill_item_journey(self, request_key, *, request=None, inquiry_journey=None):
        from .viewer_data import INQUIRIES, core_name, service_path, tehran
        request = request or self.one('SELECT * FROM viewer_requests WHERE request_key=?', (request_key,))
        if not request:
            return None
        name = core_name(request['root_call'] or '')
        role = 'inquiry' if name in INQUIRIES else 'basket_add' if name == 'UserBasketAddBills' else 'payment' if name in PAYMENT_ROOTS else None
        if not role:
            return None
        result = dict(status='unresolved',current_request_key=request_key,inquiries=[],basket_additions=[],
                      payment_attempts=[],truncated=False,bill_item_count=0,financial_confirmation='unverified',
                      scope='bounded_session_request_neighborhood_not_full_history')
        if request['conflicted'] or not request['session_key']:
            return result
        items = self._bill_item_fingerprints(request_key, role=role)
        result['bill_item_count'] = len(items)
        if not items:
            return result
        if role == 'inquiry':
            candidates = [request]
        else:
            candidates, result['truncated'] = self._bill_neighbors(request)
        for candidate in candidates:
            if (candidate['conflicted'] or core_name(candidate['root_call'] or '') not in INQUIRIES or
                    (candidate['root_ns'] is not None and request['root_ns'] is not None and candidate['root_ns'] > request['root_ns'])):
                continue
            previous = self._bill_item_fingerprints(candidate['request_key'], role='inquiry')
            common = sorted(items.keys() & previous.keys())
            if not common:
                continue
            if len(result['inquiries']) >= 8:
                result['truncated'] = True
                break
            inquiry = dict(request_key=candidate['request_key'],raw_request_id=self.raw_request_id(candidate['request_key']),
                api=service_path(candidate['root_call']),when_fa=tehran(candidate['root_ns']),linked_items=len(common),
                evidence=previous[common[0]][0])
            result['inquiries'].append(inquiry)
            journey = inquiry_journey if candidate['request_key'] == request_key and inquiry_journey is not None else self.inquiry_payment_journey(candidate['request_key'])
            result['truncated'] = result['truncated'] or journey['truncated']
            for kind in ('basket_additions', 'payment_attempts'):
                for step in journey[kind]:
                    # A multi-item inquiry must not bridge disjoint bill items.
                    step_items = self._bill_item_fingerprints(step['request_key'],role='basket_add' if kind=='basket_additions' else 'payment')
                    if not (items.keys() & previous.keys() & step_items.keys()):
                        continue
                    narrowed = self._bill_step(dict(request_key=step['request_key'],root_call=step['api'],
                        root_ns=step['at_ns'],root_code=step['root_code'],current_outcome=step['financial_outcome']),
                        {k:previous[k] for k in items.keys() & previous.keys()}, step_items,
                        'basket_add' if kind=='basket_additions' else 'payment')
                    existing = next((x for x in result[kind] if x['request_key']==step['request_key']),None)
                    if existing is None:
                        result[kind].append(narrowed)
                    else:
                        for entry in narrowed['item_evidence']:
                            known=next((x for x in existing['item_evidence'] if x['item_id'].lower()==entry['item_id'].lower()),None)
                            if known is None:
                                existing['item_evidence'].append(entry)
                            else:
                                for proof_kind in ('inquiry_evidence','step_evidence'):
                                    known[proof_kind].extend(p for p in entry[proof_kind] if p not in known[proof_kind])
                        existing['linked_items']=len(existing['item_evidence'])
                        existing['explicit_selection_item_count']=sum(x['relation']=='explicit_item_selection' for x in existing['item_evidence'])
                        if narrowed['relation']=='explicit_item_selection' and existing['relation']!='explicit_item_selection':
                            for field in ('relation','evidence','inquiry_evidence'):
                                existing[field]=narrowed[field]
        result['status'] = 'exact_item_relationship_observed' if result['inquiries'] else 'no_inquiry_in_bounded_scope'
        return result
