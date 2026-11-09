"""Compile exact dispatcher branches and endpoint mappings from supplied Core."""
import argparse,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]


def build(core):
    core=Path(core)
    helper=core/'Main/Helper/HelperHttpContext.cs'
    handler=core/'Intermediate/Modules/Sales/Commands/Register/InvoiceRegisterHandler.cs'
    facade=core/'WebServices/Services.svc.cs'
    text=helper.read_text(encoding='utf-8-sig').split('public static string GetEndpointByService',1)[1].split('\n        }',1)[0]
    endpoints=dict(re.findall(r'ServiceEnum\.(\w+)\s*=>\s*"([^"\r\n]+)"',text))
    text=handler.read_text(encoding='utf-8-sig').split('private IMethodResult CallService()',1)[1].split('\n        }',1)[0]
    branches=dict(re.findall(r'ServiceEnum\.(\w+)\s*=>\s*(\w+)\(\)',text))
    roles=json.loads((ROOT/'catalogs/viewer_service_roles.json').read_text())['routes'];routes={}
    for name,method in branches.items():
        if name not in endpoints:continue
        path='Services.'+endpoints[name]
        row=routes.setdefault(path,dict(service_names=[],handler_methods=[],catalog_role=roles.get(path,{}).get('role','unknown')))
        row['service_names'].append(name);row['handler_methods'].append(method)
    return dict(version='p24-source-dispatch-1',transport='Services.v1/InvoiceRegister',
        source_files_sha256={p.relative_to(core.parent).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in (helper,handler,facade)},
        meaning='requested service is explicitly authorized by dispatcher endpoint selection; HTTP transport remains InvoiceRegister',
        unmapped_service_names=sorted(set(branches)-set(endpoints)),routes=dict(sorted(routes.items())))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--core-root',type=Path,required=True)
    parser.add_argument('--out',type=Path,default=ROOT/'catalogs/viewer_dispatch_routes.json');args=parser.parse_args()
    data=build(args.core_root);args.out.write_text(json.dumps(data,indent=2)+'\n')
    print(json.dumps(dict(routes=len(data['routes']),unmapped=data['unmapped_service_names'])))


if __name__=='__main__':main()
