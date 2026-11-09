"""Source-backed service dispatch and MyGov OTP facts, without identity inference.

InvoiceRegister is the observed HTTP transport. A successful SQL procedure
execution alone does not prove access authorization, an OTP, or an inquiry.
Service intent comes from its exact logged access action and audited switch.
Every fact retains its event/version in the existing contract projection.
"""
from functools import lru_cache
from pathlib import Path
import json
import re

from .parser import sql_parameters

PREFIX='service_dispatch.'
TRANSPORT='Services.v1/InvoiceRegister'
_CODE=re.compile(r'^G[A-Z0-9]{1,24}$')


@lru_cache(maxsize=1)
def dispatch_catalog():
    return json.loads((Path(__file__).resolve().parents[1]/'catalogs/viewer_dispatch_routes.json').read_text())


def api_path(call):
    return str(call or '').split(' Line:',1)[0].strip()


def _block(message,label):
    try:
        value=json.JSONDecoder(object_pairs_hook=_unique).raw_decode(message.split(label,1)[1].lstrip())[0]
        if isinstance(value,list):value=value[0] if len(value)==1 else None
        return value if isinstance(value,dict) else {}
    except (ValueError,IndexError,TypeError):return {}


def _unique(pairs):
    value={}
    for key,item in pairs:
        if key in value:raise ValueError('duplicate_json_key')
        value[key]=item
    return value


def dispatch_facts(raw):
    """Named facts only: never persist OTP values, identities or medical data."""
    call=api_path(raw.get('CallPath'));message=raw.get('message')
    if not isinstance(message,str):return []
    facts=[]
    if call.startswith('DBPath.') and '(SQL Parameters:' in message:
        try:params,state=sql_parameters(message)
        except (ValueError,TypeError):return []
        if state!='complete':return []
        if call.endswith('.ud_prc_userSessionHasAccess'):
            action=params.get('action')
            if isinstance(action,str) and 'Services.'+action in dispatch_catalog()['routes']:
                facts.append((PREFIX+'access','Services.'+action,'sql.action'))
        elif call.endswith('.ud_prc_invoiceRequest'):
            value=params.get('serviceid')
            if isinstance(value,str) and re.fullmatch(r'[0-9]{1,12}',value):
                facts.append((PREFIX+'invoice_request',value,'sql.serviceID'))
        elif call.endswith('.ud_prc_inquiryInvoiceResult2'):
            value=params.get('statuscode')
            if isinstance(value,str) and _CODE.fullmatch(value):
                facts.append((PREFIX+'inquiry_result',value,'sql.statusCode'))
        return facts
    known={'ClientAyanCoInquiry.MyGovRequestOtp':'otp_request',
           'ClientAyanCoInquiry.MyGovLogin':'otp_validation',
           'ClientAyanCoInquiry.TaminUnderCoveredInquiry':'under_covered'}
    stage=known.get(call)
    if stage is None:return []
    output=_block(message,'Output:');status=output.get('Status')
    code=status.get('Code') if isinstance(status,dict) else None
    if isinstance(code,str) and _CODE.fullmatch(code):
        facts.append((PREFIX+stage,code,'provider.Output.Status.Code'))
    parameters=output.get('Parameters')
    if stage=='otp_request' and isinstance(parameters,dict) and type(parameters.get('OtpRequired')) is bool:
        facts.append((PREFIX+'otp_required','true' if parameters['OtpRequired'] else 'false',
                      'provider.Output.Parameters.OtpRequired'))
    return facts
