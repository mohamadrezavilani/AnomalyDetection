"""Reference inputs are measurements; diagnostics and evaluation metadata are not."""
from compact_behavior.extract import digest

POLICY = 'stable-summary-references-1'


def base(summary):
    return {k: v for k, v in summary.items()
            if k not in ('security', 'feature_bytes', 'analysis_policy') and not k.startswith('inquiry_')}


def rates(summary):
    return dict(rates={k: [v['count'], v.get('actor_p95', 0), not bool(v['invalid_rate'])]
                       for k, v in summary['services'].items() if k != '<unresolved>'},
                complete=not (summary['invalid_contract'] or summary['unresolved']))


def hashes(summary):
    return (digest(base(summary)), digest(rates(summary)),
            summary.get('security', {}).get('summary_hash'),
            summary.get('inquiry_window_signature'))
