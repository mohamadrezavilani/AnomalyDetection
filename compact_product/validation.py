"""Recognize terminal dispatcher failures in retained evidence, including old rows."""

DISPATCH = 'Services.v1/InvoiceRegister'
REJECTIONS = {
    'G00002': ('SessionIsNotValid', 'رد درخواست به دلیل نشست نامعتبر'),
    'G00003': ('NullCheckError', 'رد درخواست به دلیل ورودی نامعتبر'),
    'G00010': ('UserAccessObjectsDoesNotContainAccessObject', 'درخواست ردشده در کنترل دسترسی'),
}


def candidate_sql():
    return """b.api='Services.v1/InvoiceRegister' AND b.result_code IN ('G00002','G00003','G00010')
        AND b.features->>'service_binding'='UNRESOLVED_DISPATCH'"""


def evidence_sql():
    # Require the public completion's own symbol. These codes have other meanings in providers.
    pairs = ','.join(f"('{code}','{symbol}')" for code,(symbol,_) in REJECTIONS.items())
    root = "(p.state->'roots'->0)"
    return f"""p.state->'apis'=jsonb_build_array(b.api)
        AND p.state->'issues'='[]'::jsonb
        AND (p.state->'dispatch'='[]'::jsonb OR (b.result_code='G00010'
            AND jsonb_array_length(p.state->'dispatch')=1
            AND p.state->'dispatch'->0->>'kind'='action'))
        AND jsonb_array_length(p.state->'sessions')<=1
        AND jsonb_array_length(p.state->'roots')=1
        AND {root}->>'api'=b.api AND {root}->>'code'=b.result_code
        AND jsonb_typeof({root}->'at_ns')='number'
        AND (b.result_code,{root}->>'symbol') IN ({pairs})"""


def verified_sql(schema):
    # The ordinary behavior lookup and sparse unknown index stay unchanged.
    # Fetch a legacy payload by primary key only for one of the candidate codes.
    return f"""CASE WHEN {candidate_sql()} THEN EXISTS (
        SELECT 1 FROM {schema}.behavior_payloads p
        WHERE p.behavior_id=b.behavior_id AND {evidence_sql()}) ELSE false END"""
