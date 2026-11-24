"""Refusals are review evidence, not executions or verified token attacks."""
from copy import deepcopy
import unittest
from compact_behavior import FIVE
from compact_behavior import context, security
from compact_behavior.extract import materialize, iso
from compact_ad.engine import summarize, evaluate
from compact_ad.security import Aggregates
from compact_product.cases import select_cases, service_groups
from tests.test_compact_extract import row, extract, T


def attempts(kind='access_denied', count=20, ip='192.0.2.1', tokens=5, endpoint=None, session='allowed-session'):
    code, symbol = ('G00010', 'UserAccessObjectsDoesNotContainAccessObject') if kind=='access_denied' else ('G00002', 'SessionIsNotValid')
    rows=[]
    for i in range(count):
        key=f'{kind}-{ip}-{i}'
        token = session if kind=='access_denied' else f'expired-{i % tokens}'
        r=dict(row(key, token, path=endpoint or 'Services.v1/InvoiceRegister',
                   message=f'POST https://example.test/api HTTP/1.1 ({code} | {symbol})',
                   at=iso(T+i*2*10**9)), IP=ip)
        rows.append(r)
        if kind=='access_denied':
            rows.append(dict(r,CallPath='DBPath.pishkhan24.application.ud_prc_userSessionHasAccess',
                             message='(SQL Parameters: @action=v1/LandLinePhoneBills)'))
    return rows


def bodies(records):
    return [materialize('test',s) for s in extract(records).values()]


def results(records, refs=()):
    summary,services,actors=summarize(bodies(records),cutoff_ns=T+FIVE)
    return summary,evaluate(T,summary,services,actors,refs)


def case_rows(values):
    return [dict(finding_id=str(i),start_ns=T,method=r['method'],service=r['service'],
                 session_id=r['session_id'],result=r) for i,r in enumerate(values) if r['status']=='ANOMALY']


class SecurityContractTests(unittest.TestCase):
    def test_denials_qualify_independently_without_executions(self):
        summary, values=results(attempts())
        r=next(r for r in values if r['method']=='access_denied_attempts')
        self.assertEqual(r['status'],'ANOMALY')
        self.assertEqual(r['observed'],20)
        self.assertEqual(r['service'],'Services.v1/LandLinePhoneBills')
        self.assertEqual(r['reference_windows'],0)
        self.assertEqual(summary['services'],{})
        self.assertEqual(summary['unresolved'],0)
        self.assertEqual(len(select_cases(case_rows(values))),1)

    def test_invalid_tokens_are_network_cohort_never_a_valid_session(self):
        summary, values=results(attempts('invalid_session',30))
        r=next(r for r in values if r['method']=='invalid_session_attempts')
        self.assertEqual(r['status'],'ANOMALY')
        self.assertIsNone(r['session_id'])
        self.assertEqual(r['distinct_presented_tokens'],5)
        c=select_cases(case_rows(values))[0]
        self.assertEqual(c['domain'],'network_attempts')
        self.assertIsNone(c['session_id'])
        groups=service_groups([c])
        self.assertEqual(groups[0]['service'],'Services.v1/InvoiceRegister')
        self.assertIn('invalid_session_attempts',groups[0]['methods'])
        self.assertTrue(groups[0]['network'])
        self.assertFalse(groups[0]['health'])
        self.assertNotIn('192.0.2.1',str(summary))
        self.assertNotIn('expired-',str(summary))

    def test_ordinary_expiry_and_single_denial_do_not_make_cases(self):
        for records in (attempts(count=1),attempts('invalid_session',30,tokens=1),attempts('invalid_session',29)):
            with self.subTest(size=len(records)):
                _,values=results(records)
                self.assertFalse(select_cases(case_rows(values)))
        _,values=results(attempts('invalid_session',100,tokens=1))
        self.assertTrue(select_cases(case_rows(values)))

    def test_ips_do_not_merge_and_endpoints_can_share_only_network_cohort(self):
        a=attempts('invalid_session',30,ip='192.0.2.1')
        b=attempts('invalid_session',30,ip='192.0.2.2',endpoint='Core.v1/InvoicePayment')
        summary, values=results(a+b)
        cases=select_cases(case_rows(values))
        self.assertEqual(len(cases),2)
        self.assertEqual(len({c['case_id'] for c in cases}),2)
        self.assertEqual(summary['services'],{})
        self.assertTrue(all(c['domain']=='network_attempts' for c in cases))

    def test_code_alone_competing_completions_and_dispatch_cannot_prove_refusal(self):
        original=attempts(count=1)
        bad=[
            [dict(original[0],message=original[0]['message'].replace('UserAccessObjectsDoesNotContainAccessObject','ServiceDisabled')),original[1]],
            original+[row(original[0]['RequestID'],path='Services.v1/InvoiceRegister')],
            original+[row(original[0]['RequestID'],path='DBPath.pishkhan24.application.ud_prc_invoiceRequest',message='(SQL Parameters: @serviceID=12)')],
        ]
        for records in bad:
            self.assertNotIn(security.FIELD,bodies(records)[0]['features'])

    def test_ip_provenance_time_conflict_and_mapping(self):
        for ip in ('::ffff:192.0.2.1','192.0.2.1'):
            b=bodies(attempts('invalid_session',1,ip=ip))[0]
            self.assertEqual(b['features'][security.FIELD]['cohort_key'],security.fingerprint('ip','192.0.2.1'))
        c=context.empty()
        context.observe(c,'ip','192.0.2.1','payload.parameters',T)
        self.assertIsNone(security.network(c,T))
        context.observe(c,'ip','192.0.2.1','log.IP',T)
        self.assertEqual(security.network(c,T),security.fingerprint('ip','192.0.2.1'))
        self.assertIsNone(security.network(c,T-1))
        context.observe(c,'ip','192.0.2.2','log.IP',T)
        self.assertIsNone(security.network(c,T))
        c['limited']=['ip_variants']
        self.assertIsNone(security.network(c,T))

    def test_missing_or_undated_ip_is_invalid_input(self):
        records=attempts('invalid_session',30,ip='N/A')
        _,values=results(records)
        r=next(r for r in values if r['method']=='invalid_session_attempts')
        self.assertEqual(r['status'],'INVALID_INPUT')
        self.assertFalse(select_cases(case_rows(values)))

    def test_past_baseline_and_future_cutoff(self):
        summary,_=results(attempts(count=25))
        refs=[dict(start_ns=T-i*FIVE,summary=summary) for i in range(12,0,-1)]
        _,values=results(attempts(count=25),refs)
        r=next(r for r in values if r['method']=='access_denied_attempts')
        self.assertEqual(r['status'],'NORMAL')
        self.assertEqual(r['threshold'],75)
        _,future=results(attempts(),[dict(start_ns=T+FIVE,summary=summary)])
        r=next(r for r in future if r['method']=='access_denied_attempts')
        self.assertEqual(r['reference_windows'],0)
        self.assertEqual(r['status'],'ANOMALY')

    def test_cohort_budget_disables_only_security_qualification(self):
        aggregate=Aggregates(T+FIVE,max_cohorts=1)
        for b in bodies(attempts('invalid_session',30)+attempts('invalid_session',30,ip='192.0.2.2')):
            aggregate.observe(b)
        self.assertFalse(aggregate.complete)
        from compact_ad.security import evaluate as security_evaluate
        values=[]
        def add(*args,**kw):
            v=dict(status=args[3]);values.append(v);return v
        security_evaluate(aggregate.summary(),[],add)
        self.assertTrue(all(r['status']=='INVALID_INPUT' for r in values))

    def test_known_payment_and_background_rows_do_not_invent_financial_relationship(self):
        records=[row(path='Core.v1/InvoicePayment'),row(session='N/A',path='HelperQueue.CleanupOldItems',message='Remove[5] Current[2] successfully completed.')]
        body=bodies(records)[0]
        self.assertEqual(body['operation_role'],'business')
        self.assertEqual(body['api'],'Core.v1/InvoicePayment')
        self.assertEqual(body['features']['financial_chain'],'OUT_OF_SCOPE')
        self.assertNotIn(security.FIELD,body['features'])
        # An actual second HTTP completion or unreviewed operation still conflicts.
        for other in [row(path='HelperQueue.CleanupOldItems'),row(path='Core.v1/WalletPayment')]:
            conflict=bodies([row(path='Core.v1/InvoicePayment'),other])[0]
            self.assertIsNone(conflict['api'])

    def test_nonsecurity_reference_signatures_ignore_security_only_changes(self):
        s,services,actors=summarize(bodies([row()]),cutoff_ns=T+FIVE)
        original=deepcopy(s);original.pop('security')
        old=[dict(start_ns=T-i*FIVE,summary=original) for i in range(12,0,-1)]
        new=[dict(start_ns=r['start_ns'],summary=s) for r in old]
        a=evaluate(T,s,services,actors,old);b=evaluate(T,s,services,actors,new)
        self.assertEqual([r for r in a if r['method'] not in ('access_denied_attempts','invalid_session_attempts')],
                         [r for r in b if r['method'] not in ('access_denied_attempts','invalid_session_attempts')])


if __name__=='__main__':unittest.main()
