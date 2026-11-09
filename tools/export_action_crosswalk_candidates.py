"""Export same-RequestID HTTP endpoint / Access-check action candidates only."""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from p24_foundation.privacy import Keys
from p24_foundation.taxonomy import ACTION_CROSSWALK_VERSION,observed_request_action_candidates


def build(paths):
    keys=Keys(os.urandom(32),os.urandom(32),"crosswalk_export_ephemeral_v1")
    sources=[]
    for path in sorted(map(Path,paths),key=lambda p:p.name.casefold()):
        sources.append(observed_request_action_candidates(path.read_bytes(),locator=path.name,keys=keys,namespace="action_crosswalk_export"))
    return dict(version=ACTION_CROSSWALK_VERSION,status="unpublished_same_request_co_observation_candidates",
        counting_unit="distinct logical RequestID projection within each listed source file",
        source_counts_must_not_be_summed="source fixtures can overlap; no cross-source union is asserted",
        interpretation="same RequestID evidence links an observed Client HTTP CallPath and an Access-check @action value; does not prove target execution or authoritative service mapping",
        identity_values_exported=False,sensitive_parameters_or_payloads_exported=False,sources=sources)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--inputs",nargs="+",required=True,type=Path)
    p.add_argument("--output",required=True,type=Path)
    a=p.parse_args();value=build(a.inputs);a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(value,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(dict(source_files=len(value["sources"]),pairs=sum(s["pair_count"] for s in value["sources"]),
        no_identity_or_payload_values=True,authoritative_mapping_created=False)))
    return 0


if __name__=="__main__":raise SystemExit(main())
