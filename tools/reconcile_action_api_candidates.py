"""Reconcile saved action candidates to Postman path examples, without authority claims."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from p24_foundation.taxonomy import ACTION_API_RECONCILIATION_VERSION,reconcile_action_candidates_with_postman


def build(action_catalog,postman_catalog,conflict_catalog=None):
    return reconcile_action_candidates_with_postman(action_catalog,postman_catalog,conflict_catalog)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--actions',type=Path,default=Path('catalogs/action_crosswalk_candidates.json'))
    parser.add_argument('--postman',type=Path,default=Path('catalogs/postman_route_candidates.json'))
    parser.add_argument('--conflicts',type=Path,default=Path('catalogs/postman_route_conflicts.json'))
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=build(json.loads(args.actions.read_text(encoding='utf-8')),
        json.loads(args.postman.read_text(encoding='utf-8')),
        json.loads(args.conflicts.read_text(encoding='utf-8')))
    if result['version']!=ACTION_API_RECONCILIATION_VERSION:
        raise RuntimeError('unexpected candidate schema version')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    states={}
    for source in result['sources']:
        for pair in source['pairs']:
            state=pair['postman_candidate_state'];states[state]=states.get(state,0)+1
    print(json.dumps({'source_files':len(result['sources']),'candidate_pairs':sum(s['pair_count'] for s in result['sources']),
        'candidate_states':states,'taxonomy_published':False,'execution_claims':False},sort_keys=True))
    return 0


if __name__=='__main__':raise SystemExit(main())
