"""Export sanitized observed error-code/operation candidates from fixture sources."""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from p24_foundation.error_reconciliation import OBSERVED_CODE_RECONCILIATION_VERSION,observed_code_operation_candidates
from p24_foundation.privacy import Keys


def build(paths,code_catalog):
    keys=Keys(os.urandom(32),os.urandom(32),"err_op_export_v1")
    sources=[]
    for path in sorted(map(Path,paths),key=lambda p:p.name.casefold()):
        sources.append(observed_code_operation_candidates(path.read_bytes(),locator=path.name,keys=keys,
            namespace="error_operation_export",code_catalog=code_catalog))
    return {"version":OBSERVED_CODE_RECONCILIATION_VERSION,
        "status":"unpublished_observed_code_operation_candidates",
        "interpretation":"code meaning and operation/version binding are separate; same-RequestID context is co-observation only",
        "code_systems_globally_assumed":False,
        "source_counts_must_not_be_summed":"fixture sources overlap; no cross-source traffic union is asserted",
        "raw_request_ids_ips_sessions_parameters_or_payloads_exported":False,
        "sources":sources}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--inputs",nargs="+",required=True,type=Path)
    p.add_argument("--code-catalog",type=Path,default=Path("catalogs/error_code_catalog.json"))
    p.add_argument("--output",required=True,type=Path)
    a=p.parse_args();catalog=json.loads(a.code_catalog.read_text(encoding="utf-8"));result=build(a.inputs,catalog)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"sources":len(result["sources"]),
        "groups":sum(s["group_count"] for s in result["sources"]),
        "raw_identity_or_payload_values_exported":False,"operation_binding_proven":False},sort_keys=True))
    return 0


if __name__=="__main__":raise SystemExit(main())
