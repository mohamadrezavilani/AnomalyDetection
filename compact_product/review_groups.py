"""Display overlapping rolls together while retaining every revision and verdict."""
from collections import defaultdict
from compact_behavior.inquiry import token
from .case_evidence import clock_input, evidence

WITNESS_PAGE = 24


def groups(findings):
    rolling = defaultdict(list)
    result = []
    for finding in findings:
        r = finding['result']
        if (finding['method'] == 'target_diversity' and finding['session_id']
                and r.get('inquiry_breadth_policy') and r.get('numeric_path')
                and r.get('period_start_ns') is not None and r.get('period_end_ns') is not None):
            key = (finding['session_id'], finding['service'], r['numeric_path'], r['inquiry_breadth_policy'], r.get('subject_policy'))
            rolling[key].append(finding)
        else:
            result.append([finding])
    for sequence in rolling.values():
        current = []
        end = None
        for f in sorted(sequence, key=lambda f: (f['result']['period_start_ns'], f['finding_id'])):
            r = f['result']
            if not current or r['period_start_ns'] >= end:
                current = []
                result.append(current)
                end = r['period_end_ns']
            current.append(f)
            end = max(end, r['period_end_ns'])
    for group in result:
        group.sort(key=lambda f: (f['start_ns'], f['finding_id']), reverse=True)
    return sorted(result, key=lambda group: (group[0]['start_ns'],group[0]['finding_id']), reverse=True)


def page_evidence(db, schema, stream, groups, focused, witness_page):
    plans = []
    selected = {}
    for members in groups:
        all_ids = list(dict.fromkeys(bid for f in members for bid in f['result'].get('evidence') or ()))
        page = witness_page if members[0]['finding_id'] == focused else 1
        # Reanalysis can shrink the episode between requests.
        page = min(page, max(1, (len(all_ids)+WITNESS_PAGE-1)//WITNESS_PAGE))
        visible = set(all_ids[(page-1)*WITNESS_PAGE:page*WITNESS_PAGE])
        for f in members:
            selected[f['finding_id']] = [bid for bid in dict.fromkeys(f['result'].get('evidence') or ()) if bid in visible]
        plans.append((members, len(all_ids), page, len(visible)))
    proof = evidence(db, schema, stream, [f for members in groups for f in members],
                     per_finding=WITNESS_PAGE, selected_ids=selected)
    for members, total, page, expected in plans:
        key = members[0]['finding_id']
        rows = {}
        ips = []
        for f in members:
            item = proof.get(f['finding_id'], {})
            ips.extend(item.get('ips', ()))
            for row in item.get('rows', ()):
                if row['bid'] not in rows or row['target'] is not None:
                    rows[row['bid']] = row
        item = proof.setdefault(key, {})
        item.update(rows=sorted(rows.values(), key=lambda w: (w['at'] is None,w['at'] or 0,w['bid'])),
                    ips=list(dict.fromkeys(ips)), missing=expected-len(rows), total=total,
                    witness_page=page, more=page*WITNESS_PAGE<total)
        if len(members) > 1:
            start = min(f['result']['period_start_ns'] for f in members)
            end = max(f['result']['period_end_ns'] for f in members)
            lower_bound = max(f['result']['distinct_targets'] for f in members)
            if expected == total:
                verified = {token(row['target']) for row in rows.values() if row['target'] is not None}
                lower_bound = max(lower_bound, len(verified))
            item.update(members=members, start=start, end=end, distinct_floor=lower_bound,
                        window=dict(to=clock_input(((end+10**9-1)//10**9)*10**9),
                                    **{'from':clock_input(start)}))
    return proof
