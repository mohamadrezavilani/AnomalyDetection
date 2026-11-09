"""Export aggregate CallPath role candidates from sanitized log samples."""
import argparse
import json
import os
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from p24_foundation.privacy import Keys
from p24_foundation.taxonomy import TAXONOMY_IMPORT_VERSION,observed_callpath_candidates


def build(paths):
    keys=Keys(os.urandom(32),os.urandom(32),"export_ephemeral_v1");sources=[]
    for path in sorted(map(Path,paths),key=lambda p:p.name.casefold()):
        c=observed_callpath_candidates(path.read_bytes(),locator=path.name,keys=keys,namespace="taxonomy_export")
        sources.append(dict(file_name=c.locator,sha256=c.content_sha256,unresolved_records=c.unresolved_record_count,
            callpath_groups=[dict(source_role=m["source_role"],callpath=m["exact_endpoint"],method=m["method"],
                observed_event_count=m["observed_event_count"],distinct_request_count=m["distinct_request_count"],
                event_kinds=m["event_kinds"],service_key=None,business_phase="unknown",initiation="unknown",
                security_class="unknown",mapping_state="candidate") for m in c.mappings]))
    return dict(version=TAXONOMY_IMPORT_VERSION,status="unpublished_observed_candidates",sources=sources,
        semantic_classifications_inferred=False,session_ip_account_or_payload_values_exported=False)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--inputs",nargs="+",required=True,type=Path);p.add_argument("--output",required=True,type=Path)
    a=p.parse_args();value=build(a.inputs);a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(value,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(dict(source_files=len(value["sources"]),callpath_groups=sum(len(s["callpath_groups"]) for s in value["sources"]),private_values_exported=False)))
    return 0


if __name__=="__main__":raise SystemExit(main())
