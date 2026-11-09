"""Export safe unpublished Postman metadata with duplicate-route provenance."""
import argparse
import collections
import json
import re
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from p24_foundation.taxonomy import TAXONOMY_IMPORT_VERSION,postman_candidates


def build(paths):
    sources,items = [],[]
    hint = re.compile(r"device|login|credential|password|otp|session|register|terminate|card",re.I)
    for path in sorted(map(Path,paths),key=lambda p:p.name.casefold()):
        c=postman_candidates(path.read_bytes(),locator=path.name)
        sources.append(dict(file_name=c.locator,sha256=c.content_sha256,request_items=len(c.mappings)))
        for m in c.mappings:
            items.append(dict(collection=c.title,item_path=m["item_path"],request_name=m["request_name"],
                folder_path=m["folder_path"],method=m["method"],endpoint=m["exact_endpoint"],
                endpoint_state=m["endpoint_state"],origin_kind=m["origin_kind"],source_role="client_http",
                service_key=None,business_phase="unknown",initiation="unknown",security_class="unknown",
                mapping_state="candidate",manual_review_hints=["manual_semantic_review_suggested"] if m["request_name"] and hint.search(m["request_name"]) else []))
    pairs=collections.defaultdict(list)
    for item in items:
        if item["method"] and item["endpoint"]:pairs[(item["method"],item["endpoint"])].append(item)
    conflicts=[dict(method=method,endpoint=endpoint,references=[dict(collection=r["collection"],request_name=r["request_name"],item_path=r["item_path"]) for r in rows])
               for (method,endpoint),rows in sorted(pairs.items()) if len(rows)>1]
    manifest=dict(version=TAXONOMY_IMPORT_VERSION,status="unpublished_review_candidates",collections=sources,request_items=len(items),
        items_with_resolved_routes=sum(bool(x["endpoint"]) and x["endpoint_state"]=="resolved" for x in items),
        items_missing_or_redacted_route=sum(x["endpoint_state"]!="resolved" for x in items),
        unique_method_route_pairs=len(pairs),duplicate_method_route_groups=len(conflicts),semantic_fields_inferred=False,
        request_bodies_headers_auth_values_or_responses_exported=False)
    return manifest,items,conflicts


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--collections",nargs="+",required=True,type=Path);p.add_argument("--output-dir",required=True,type=Path)
    a=p.parse_args();manifest,items,conflicts=build(a.collections);a.output_dir.mkdir(parents=True,exist_ok=True)
    for name,value in {"postman_candidate_manifest.json":manifest,"postman_route_candidates.json":dict(version=TAXONOMY_IMPORT_VERSION,items=items),"postman_route_conflicts.json":dict(version=TAXONOMY_IMPORT_VERSION,conflicts=conflicts)}.items():
        (a.output_dir/name).write_text(json.dumps(value,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(dict(request_items=len(items),duplicate_method_route_groups=len(conflicts),semantic_fields_inferred=False)))
    return 0


if __name__=="__main__":raise SystemExit(main())
