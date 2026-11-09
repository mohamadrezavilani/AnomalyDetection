"""Pure tests for source-bound Persian incident briefs."""
import unittest

from p24_foundation.incident_briefs import VERSION, build_incident_brief


class IncidentBriefTests(unittest.TestCase):
    def test_behavior_partitions_count_as_one_evaluation_and_keep_scoped_explanation(self):
        saved=self.saved();saved['result']['behavior_evaluation_selection']={'window':'evaluation-one'}
        observation=dict(target_requests=20,reference_median=2,reference_active_windows=19,
                         explanation_fa='افزایش مشاهده‌شده؛ اولویت تعیین نشده است.')
        saved['result']['active_findings']=[dict(behavior_evaluation_id='evaluation-one',behavior_observation=observation)]*2
        brief=build_incident_brief(saved,is_latest_revision=True)
        self.assertEqual(brief['behavior']['evaluation_count'],1)
        self.assertEqual(len(brief['behavior']['sample']),1)
        self.assertEqual(brief['behavior']['sample'][0]['target_requests'],20)
    def saved(self):
        return dict(incident_id='incident-token',revision_id='revision-token',result=dict(
            publication_id='publication-token',pattern_key='machine.pattern',scope_kind='session',
            failure_family=None,distinct_supported_requests=4,distinct_client_http_requests=3,
            occurrence_count=2,first_event_ns='100',last_event_ns='900',
            active_findings=[{},{}],excluded_findings=[dict(reason='superseded'),dict(reason='source_time_unavailable')],coverage='Pinned memberships only; not whole traffic.',
            root_cause='not_established',requests=[
                dict(request_key='request-a',first_event_ns='100',last_event_ns='110'),
                dict(request_key='request-b',first_event_ns='400',last_event_ns='500'),
                dict(request_key='request-c',first_event_ns='700',last_event_ns='900'),
                dict(request_key='request-d',first_event_ns='300',last_event_ns='350')]))

    def test_brief_uses_exact_pinned_counts_and_selected_internal_request_links(self):
        brief=build_incident_brief(self.saved(),is_latest_revision=True)
        self.assertEqual(brief['version'],VERSION)
        self.assertEqual((brief['supported_requests'],brief['client_http_requests'],brief['occurrences']),(4,3,2))
        self.assertEqual(brief['publication_id'],'publication-token')
        self.assertEqual([x['request_key'] for x in brief['sample_requests']],['request-a','request-d','request-c'])
        self.assertEqual(brief['revision_state'],'latest')
        self.assertEqual(brief['root_cause_state'],'not_established')
        self.assertEqual(brief['elapsed_span_ns'],800)
        self.assertEqual(brief['excluded_finding_reasons'],{'source_time_unavailable':1,'superseded':1})
        self.assertEqual((brief['sample_request_count'],brief['sample_request_limit']),(3,3))

    def test_historical_pins_keep_source_coverage_and_do_not_claim_cause(self):
        brief=build_incident_brief(self.saved(),is_latest_revision=False)
        self.assertEqual(brief['revision_state'],'historical')
        self.assertEqual(brief['coverage'],'Pinned memberships only; not whole traffic.')
        self.assertEqual(brief['root_cause_state'],'not_established')
        self.assertIn('نمایندهٔ آماری کل نیستند',brief['sample_selection_note'])

    def test_missing_coverage_abstains_instead_of_claiming_complete_capture(self):
        sample=self.saved();sample['result']['coverage']=None
        brief=build_incident_brief(sample,is_latest_revision=True)
        self.assertIn('مشخص نشده',brief['coverage'])

    def test_invalid_or_reversed_times_do_not_create_a_negative_or_false_span(self):
        sample=self.saved();sample['result']['first_event_ns']='not-a-time'
        brief=build_incident_brief(sample,is_latest_revision=True)
        self.assertIsNone(brief['elapsed_span_ns'])
        sample['result']['first_event_ns']=True;sample['result']['last_event_ns']=False
        brief=build_incident_brief(sample,is_latest_revision=True)
        self.assertIsNone(brief['elapsed_span_ns'])
        sample['result']['first_event_ns']='1000';sample['result']['last_event_ns']='900'
        brief=build_incident_brief(sample,is_latest_revision=True)
        self.assertIsNone(brief['elapsed_span_ns'])

    def test_sample_selection_is_bounded_stable_and_tolerates_bad_or_duplicate_rows(self):
        sample=self.saved()
        sample['result']['distinct_supported_requests']=8
        sample['result']['requests']=[
            dict(request_key='z',first_event_ns='bad'),
            dict(request_key='float-time',first_event_ns=1.5),
            dict(request_key='b',first_event_ns='20'),
            dict(request_key='a',first_event_ns='10'),
            dict(request_key='b',first_event_ns='30'),
            dict(first_event_ns='0'),None,
            *[dict(request_key=f'k{i}',first_event_ns=str(40+i)) for i in range(8)],
        ]
        first=build_incident_brief(sample,is_latest_revision=True)
        second=build_incident_brief(sample,is_latest_revision=True)
        self.assertEqual(first['sample_requests'],second['sample_requests'])
        self.assertLessEqual(len(first['sample_requests']),3)
        self.assertEqual(first['sample_request_count'],3)
        self.assertEqual(len({row['request_key'] for row in first['sample_requests']}),3)
        self.assertEqual(first['supported_requests'],8)
        sample['result']['requests']=[dict(request_key='opaque',first_event_ns='invalid')]
        brief=build_incident_brief(sample,is_latest_revision=True)
        self.assertEqual(brief['sample_requests'][0]['request_key'],'opaque')


if __name__=='__main__':unittest.main()
