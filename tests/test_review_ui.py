"""Changed-path review checks; no server, database, collector or paid AI calls."""
import re
import unittest
from pathlib import Path
from contextlib import contextmanager
from html import unescape
from html.parser import HTMLParser
from unittest.mock import patch

from p24_foundation.review_demo import DemoReviewProvider
from p24_foundation.review_ui import create_app,tehran_time
from p24_foundation.time import parse_time


class ReviewUITests(unittest.TestCase):
    def setUp(self):
        self.demo=DemoReviewProvider()
        from contextlib import nullcontext
        self.app=create_app(lambda:nullcontext(self.demo),initial_publication=self.demo.publication_id)
        self.client=self.app.test_client()

    def test_keyboard_focus_ring_covers_form_controls_and_skip_navigation(self):
        root=Path(__file__).resolve().parents[1]
        css=(root/'review_ui'/'static'/'review.css').read_text(encoding='utf-8')
        base=(root/'review_ui'/'templates'/'base.html').read_text(encoding='utf-8')
        for selector in ('button:focus-visible','input:focus-visible','select:focus-visible',
                         'textarea:focus-visible','a:focus-visible','summary:focus-visible',
                         '[tabindex]:focus-visible'):
            self.assertIn(selector,css)
        self.assertIn('outline:3px solid #2455c5',css)
        self.assertIn('href="#main"',base)
        self.assertIn('<main id="main"',base)

    def test_primary_navigation_marks_one_current_section_on_each_review_area(self):
        paths=['/','/registration-candidates','/services','/incidents','/investigations','/workflows']
        request_key=next(iter(self.demo.summaries))
        paths.append('/request/'+request_key)
        incident_key=self.demo._incident_fixture()['incident_id']
        paths.append('/incident/'+incident_key)
        for path in paths:
            with self.subTest(path=path):
                response=self.client.get(path)
                self.assertEqual(response.status_code,200)
                html=response.get_data(as_text=True)
                nav=re.search(r'<nav\b.*?</nav>',html,re.S).group(0)
                self.assertEqual(nav.count('aria-current="page"'),1)

    def test_scrollable_evidence_regions_are_keyboard_reachable_and_named(self):
        root=Path(__file__).resolve().parents[1]
        pattern=re.compile(r'<(?:div|section)\b[^>]*\bclass=["\'][^"\']*(?:table-scroll|evidence-list|workflow-evidence-list)[^"\']*["\'][^>]*>')
        checked=0
        for template in (root/'review_ui'/'templates').glob('*.html'):
            source=template.read_text(encoding='utf-8')
            for tag in pattern.findall(source):
                checked+=1
                self.assertRegex(tag,r'\btabindex=["\']0["\']',template.name)
                self.assertRegex(tag,r'\baria-label=["\'][^"\']+["\']',template.name)
        self.assertGreaterEqual(checked,10)

    def test_table_headers_declare_row_or_column_scope(self):
        root=Path(__file__).resolve().parents[1]
        checked=0
        for template in (root/'review_ui'/'templates').glob('*.html'):
            source=template.read_text(encoding='utf-8')
            for tag in re.findall(r'<th\b[^>]*>',source):
                checked+=1
                self.assertRegex(tag,r'\bscope=["\'](?:col|row|colgroup|rowgroup)["\']',template.name)
        self.assertGreaterEqual(checked,20)

    def test_every_post_form_has_a_hidden_csrf_field(self):
        class FormContract(HTMLParser):
            def __init__(self):
                super().__init__();self.forms=[];self.post_form=False;self.has_csrf=False;self.label_depth=0;self.named_controls=[]
            def handle_starttag(self,tag,attrs):
                values=dict(attrs)
                if tag=='form':
                    self.post_form=values.get('method','get').lower()=='post';self.has_csrf=False
                elif tag=='label':self.label_depth+=1
                elif tag=='input' and self.post_form and values.get('type','text').lower()=='hidden' and values.get('name')=='csrf':
                    self.has_csrf=True
                if tag in {'input','select','textarea'} and not (tag=='input' and values.get('type','text').lower()=='hidden'):
                    self.named_controls.append(self.label_depth>0 or bool(values.get('aria-label') or values.get('aria-labelledby')))
            def handle_endtag(self,tag):
                if tag=='form':
                    if self.post_form:self.forms.append(self.has_csrf)
                    self.post_form=False
                elif tag=='label':self.label_depth=max(0,self.label_depth-1)
        root=Path(__file__).resolve().parents[1]
        contract=FormContract()
        for template in (root/'review_ui'/'templates').glob('*.html'):
            contract.feed(template.read_text(encoding='utf-8'))
        self.assertGreaterEqual(len(contract.forms),3)
        self.assertTrue(all(contract.forms),contract.forms)
        self.assertGreaterEqual(len(contract.named_controls),8)
        self.assertTrue(all(contract.named_controls),contract.named_controls)

    def test_pinned_workflow_pages_paginate_and_link_source_fact_evidence(self):
        response=self.client.get('/workflows?limit=1');html=response.get_data(as_text=True)
        self.assertEqual(response.status_code,200)
        self.assertIn('شواهد فرایند و تحویل',html)
        links=[unescape(v) for v in re.findall(r'href="([^"]+)"',html)]
        detail=next(v for v in links if v.startswith('/workflow-state/'))
        self.assertIn('publication='+self.demo.publication_id,detail)
        page=self.client.get(detail)
        self.assertEqual(page.status_code,200)
        self.assertIn('synthetic.state',page.get_data(as_text=True))
        self.assertEqual(self.client.get(next(v for v in links if v.startswith('/workflows?') and 'cursor=' in v)).status_code,200)
        self.assertNotIn('SQL Parameters:',html+page.get_data(as_text=True))

    def test_incident_page_displays_stale_priority_and_revision_pinned_links(self):
        saved=self.demo._incident_fixture()
        self.demo.incident_priority=lambda key:dict(priority='unrated',recorded_priority='high',stale=True,
            decision_id='decision-demo',evidence_revision_id='old-revision',evidence_generation=2)
        self.demo.incident_links=lambda key:dict(total=1,claim='shared RequestID evidence only; no common identity or root cause inferred',
            items=[dict(investigation_id='group-1',basis='shared_request',revision_state='current',shared_request_count=1,incident_revision_id=saved['revision_id'],
                linked_incident_id='linked-incident',linked_revision_id='linked-revision',publication_id=self.demo.publication_id)])
        response=self.client.get('/incident/'+saved['incident_id'])
        html=response.get_data(as_text=True)
        self.assertEqual(response.status_code,200)
        self.assertIn('ارزیابی قبلی منقضی شده است',html)
        self.assertIn('مقدار ثبت‌شدهٔ قبلی: high',html)
        self.assertIn('نسخهٔ مبنا',html)
        self.assertIn('linked-incident',html)
        self.assertIn('/investigation/group-1?publication='+self.demo.publication_id,html)
        self.assertIn('shared RequestID evidence only',html)
        self.assertNotIn('کاهش امتیاز آشکارساز',html)

    def test_priority_requires_preview_csrf_and_confirmed_current_pin(self):
        from contextlib import nullcontext
        from unittest.mock import Mock
        pinned=dict(incident_id='incident-demo',priority='high',impact='multiple_requests',urgency='active',
            confidence='medium',reason_key='service_impact',decision_generation=2,evidence_revision_id='revision-demo',
            incident_generation=4,evidence_sha256='a'*64,publication_id=self.demo.publication_id)
        self.demo.priority_preview=Mock(return_value=pinned.copy())
        self.demo.priority_decide=Mock()
        app=create_app(lambda:nullcontext(self.demo),initial_publication=self.demo.publication_id,mode='live')
        client=app.test_client();key=self.demo._incident_fixture()['incident_id']
        context='?publication='+self.demo.publication_id+'&origin=investigation&from_investigation=group-key'
        form=client.get('/incident/'+key+'/priority'+context)
        self.assertEqual(form.status_code,200);self.assertIn('ساخت پیش‌نمایش',form.get_data(as_text=True));self.assertIn('عامل‌ها وزن یا فرمول خودکار ندارند',form.get_data(as_text=True))
        self.assertIn('origin=investigation',form.get_data(as_text=True))
        with client.session_transaction() as state:csrf=state['review_csrf']
        fields=dict(csrf=csrf,priority='high',impact='multiple_requests',urgency='active',confidence='medium',reason_key='service_impact')
        preview=client.post('/incident/'+key+'/priority/preview'+context,data=fields)
        html=preview.get_data(as_text=True)
        self.assertEqual(preview.status_code,200);self.assertIn('نسخهٔ شواهد',html)
        self.assertIn('origin=investigation',html)
        import re
        command=re.search(r'name="command_id" value="([^"]+)"',html).group(1)
        digest=re.search(r'name="preview_sha256" value="([^"]+)"',html).group(1)
        self.assertFalse(self.demo.priority_decide.called)
        confirmed=client.post('/incident/'+key+'/priority/confirm'+context,data=dict(csrf=csrf,command_id=command,preview_sha256=digest))
        self.assertEqual(confirmed.status_code,303);self.assertIn('origin=investigation',confirmed.headers['Location'])
        self.assertIn('from_investigation=group-key',confirmed.headers['Location']);self.demo.priority_decide.assert_called_once()
        args=self.demo.priority_decide.call_args.kwargs
        self.assertEqual(args['expected_generation'],2);self.assertEqual(args['expected_revision_id'],'revision-demo')
        replay=client.post('/incident/'+key+'/priority/confirm'+context,data=dict(csrf=csrf,command_id=command,preview_sha256=digest))
        self.assertEqual(replay.status_code,404)

    def test_priority_confirmation_rejects_changed_evidence_revision(self):
        from contextlib import nullcontext
        from unittest.mock import Mock
        pinned=dict(incident_id='incident-demo',priority='high',impact='multiple_requests',urgency='active',
            confidence='medium',reason_key='service_impact',decision_generation=0,evidence_revision_id='revision-old',
            incident_generation=2,evidence_sha256='b'*64,publication_id=self.demo.publication_id)
        changed=pinned|dict(evidence_revision_id='revision-new',incident_generation=3,evidence_sha256='c'*64)
        self.demo.priority_preview=Mock(side_effect=[pinned.copy(),changed.copy()]);self.demo.priority_decide=Mock()
        client=create_app(lambda:nullcontext(self.demo),initial_publication=self.demo.publication_id,mode='live').test_client()
        key=self.demo._incident_fixture()['incident_id'];client.get('/incident/'+key+'/priority')
        with client.session_transaction() as state:csrf=state['review_csrf']
        fields=dict(csrf=csrf,priority='high',impact='multiple_requests',urgency='active',confidence='medium',reason_key='service_impact')
        html=client.post('/incident/'+key+'/priority/preview',data=fields).get_data(as_text=True)
        import re
        command=re.search(r'name="command_id" value="([^"]+)"',html).group(1)
        digest=re.search(r'name="preview_sha256" value="([^"]+)"',html).group(1)
        response=client.post('/incident/'+key+'/priority/confirm',data=dict(csrf=csrf,command_id=command,preview_sha256=digest))
        self.assertEqual(response.status_code,400);self.demo.priority_decide.assert_not_called()

    def test_incident_brief_labels_historical_revision_and_keeps_pinned_counts(self):
        saved=self.demo._incident_fixture()
        self.demo.incident_revision_status=lambda key,revision_id:dict(incident_id=key,revision_id=revision_id,
            latest_revision_id='newer-revision',latest_generation=2,is_latest=False)
        response=self.client.get('/incident/'+saved['incident_id']);html=response.get_data(as_text=True)
        self.assertEqual(response.status_code,200)
        self.assertIn('نسخهٔ تاریخی؛ شاهدهای تازه‌تری ثبت شده است',html)
        self.assertIn('نمونه‌ها فقط برای ناوبری',html)
        self.assertIn('علت ریشه‌ای',html)
        self.assertIn('فاصلهٔ زمانی دقیق',html)
        self.assertIn('پیوستگی فعالیت را ثابت نمی‌کند',html)

    def test_incident_page_shows_priority_decision_trail_and_pin_states(self):
        saved=self.demo._incident_fixture()
        self.demo.incident_priority_history=lambda key,**kwargs:dict(total=2,next_cursor=None,items=[
            dict(priority='high',state='stale',decided_at='2026-10-20T10:00:00+00:00',actor_key='operator-key',
                reason_key='service_impact',policy_version='policy-v1',impact_factors=dict(impact='multiple_requests',
                    urgency='active',confidence='medium',incident_revision_id='revision-old')),
            dict(priority='medium',state='superseded',decided_at='2026-10-19T10:00:00+00:00',actor_key='operator-key',
                reason_key='operator_assessment',policy_version='policy-v1',impact_factors=dict(impact='single_request',
                    urgency='routine',confidence='high',incident_revision_id='revision-prior'))])
        html=self.client.get('/incident/'+saved['incident_id']).get_data(as_text=True)
        self.assertIn('سابقهٔ ارزیابی اولویت',html)
        self.assertIn('منقضی نسبت به شواهد',html);self.assertIn('جایگزین‌شده',html)
        self.assertIn('operator-key',html);self.assertIn('نسخهٔ شاهد',html)

    def test_priority_preview_rejects_csrf_and_investigation_queue_is_available(self):
        from contextlib import nullcontext
        app=create_app(lambda:nullcontext(self.demo),initial_publication=self.demo.publication_id,mode='live')
        client=app.test_client();key=self.demo._incident_fixture()['incident_id']
        denied=client.post('/incident/'+key+'/priority/preview',data=dict(priority='high'))
        self.assertEqual(denied.status_code,403)
        self.demo.investigations=lambda publication:dict(publication_id=publication,total=1,
            claim='Only validated shared RequestID evidence is shown; no common identity or root cause inferred',
            items=[dict(investigation_id='group-key',title_fa='گروه ساختگی آزمون',status='open',links=[dict(incident_id='incident-a',
                incident_revision_id='rev-a',linked_incident_id='incident-b',linked_revision_id='rev-b',
                publication_id=self.demo.publication_id,revision_state='historical',shared_request_count=2)])])
        queue=client.get('/investigations');html=queue.get_data(as_text=True)
        self.assertEqual(queue.status_code,200);self.assertIn('گروه‌های بررسی مبتنی بر شواهد',html)
        self.assertIn('incident-a',html);self.assertIn('incident-b',html);self.assertIn('2',html)
        self.assertIn('<bdi dir="ltr">incident-a</bdi>',html)
        self.assertIn('<bdi dir="ltr">rev-a</bdi>',html)
        self.assertIn('شواهد نسخهٔ تاریخی',html)
        group=dict(investigation_id='group-key',title_fa='گروه ساختگی آزمون',status='open',claim='proof only',
            links=[dict(incident_id='incident-a',incident_revision_id='rev-a',linked_incident_id='incident-b',
                linked_revision_id='rev-b',publication_id=self.demo.publication_id,basis='shared_request',
                revision_state='current',shared_request_count=52,shared_request_keys=['opaque-request-'+str(i) for i in range(52)],proof_sha256='digest-1'),
                dict(incident_id='incident-b',incident_revision_id='rev-b',linked_incident_id='incident-a',
                linked_revision_id='rev-a',publication_id=self.demo.publication_id,basis='shared_request',
                revision_state='current',shared_request_count=52,shared_request_keys=['opaque-request-'+str(i) for i in range(52)],proof_sha256='digest-1')])
        self.demo.investigation=lambda key:group
        detail=client.get('/investigation/group-key');detail_html=detail.get_data(as_text=True)
        self.assertEqual(detail.status_code,200)
        for value in ('incident-a','incident-b','opaque-request-1','opaque-request-49','هویت مشترک','۵۰ مورد از ۵۲'):
            self.assertIn(value,detail_html)
        self.assertNotIn('opaque-request-50',detail_html)
        self.assertIn('۱ پیوند دوطرفهٔ ثبت‌شده',detail_html)
        self.assertIn('/request/opaque-request-0?publication='+self.demo.publication_id,detail_html)
        self.assertIn('نسخهٔ جاری',detail_html)
        self.assertIn('<bdi dir="ltr">incident-a</bdi>',detail_html)
        self.assertIn('<bdi dir="ltr">rev-a</bdi>',detail_html)

        real_key=next(iter(self.demo.summaries))
        card=self.demo.request(self.demo.publication_id,real_key)
        card['item']['request_key']='opaque-request-0'
        evidence=self.demo.evidence(self.demo.publication_id,real_key,limit=25)
        evidence['request_key']='opaque-request-0'
        evidence['next_cursor']='cursor-token'
        with patch.object(self.demo,'request',return_value=card), patch.object(self.demo,'evidence',return_value=evidence):
            request_page=client.get('/request/opaque-request-0?publication='+self.demo.publication_id+
                '&origin=investigation&from_investigation=group-key')
        request_html=request_page.get_data(as_text=True)
        self.assertEqual(request_page.status_code,200)
        self.assertIn('گروه بررسی',request_html)
        self.assertIn('/investigation/group-key?publication='+self.demo.publication_id,request_html)
        next_page=next(unescape(value) for value in re.findall(r'href="([^"]+)"',request_html)
            if value.startswith('/request/opaque-request-0?') and 'cursor=cursor-token' in value)
        self.assertIn('origin=investigation',next_page)
        self.assertIn('from_investigation=group-key',next_page)
        self.assertEqual(client.get('/request/opaque-request-0?origin=investigation').status_code,400)

    def test_workflow_without_a_pin_explicitly_abstains(self):
        with patch.object(self.demo,'workflows',return_value=dict(status='not_provided',result=None,next_cursor=None)):
            response=self.client.get('/workflows')
        self.assertEqual(response.status_code,200)
        self.assertIn('بررسی فرایند به این نسخه متصل نشده است',response.get_data(as_text=True))

    def test_lifecycle_ledger_and_scoped_code_interpretation_are_rendered(self):
        registration=next(k for k,row in self.demo.summaries.items() if row['endpoint']=='Core.v2/DeviceRegister')
        html=self.client.get('/request/'+registration).get_data(as_text=True)
        self.assertIn('شواهد مراحل Session و ورود',html)
        self.assertIn('نسخهٔ شاهد',html)
        provider=self.demo.examples[0]['key']
        html=self.client.get('/request/'+provider).get_data(as_text=True)
        self.assertIn('اتصال بررسی‌شده در نمونهٔ مرجع',html)
        self.assertIn('تعریف نامزد در منابع',html)

    def test_workflow_examples_are_explicitly_synthetic_and_blocked_in_live_mode(self):
        response=self.client.get('/workflow-examples')
        self.assertEqual(response.status_code,200)
        html=response.get_data(as_text=True)
        self.assertIn('یک رویداد منطقی، دو تحویل',html)
        self.assertIn('سناریوهای زیر ساختگی‌اند',html)
        self.assertIn('نسخهٔ محتوای متعارض',html)
        from contextlib import nullcontext
        live=create_app(lambda:nullcontext(self.demo),initial_publication=self.demo.publication_id,mode='live').test_client()
        self.assertEqual(live.get('/workflow-examples').status_code,400)

    def test_navigation_uses_opaque_keys_and_pinned_publication(self):
        response=self.client.get('/?limit=1');html=response.get_data(as_text=True)
        self.assertEqual(response.status_code,200)
        links=[unescape(v) for v in re.findall(r'href="([^"]+)"',html)]
        request_link=next(v for v in links if v.startswith('/request/'))
        self.assertIn('publication='+self.demo.publication_id,request_link)
        self.assertNotIn(self.demo.raw_session,html)
        self.assertEqual(self.client.get(request_link).status_code,200)
        next_link=next(v for v in links if 'cursor=' in v)
        self.assertEqual(self.client.get(next_link).status_code,200)
        conflict=self.client.get('/?scope=conflicting').get_data(as_text=True)
        self.assertIn('تعارض هویت',conflict)
        self.assertIn('به این Session نسبت داده نشده',conflict)

    def test_provider_log_and_body_results_expand_separately_without_raw_payloads(self):
        key=self.demo.examples[0]['key'];html=self.client.get('/request/'+key).get_data(as_text=True)
        self.assertIn('<details class="operation">',html)
        self.assertIn('G00000',html);self.assertIn('GD2016',html)
        self.assertIn('منبع و شناسه‌های شواهد',html)
        self.assertNotIn('@otpCode=',html);self.assertNotIn('SQL Parameters:',html)

    def test_access_check_action_is_separate_from_http_endpoint(self):
        key=next(k for k,v in self.demo.summaries.items() if v['endpoint']=='Core.v2/DeviceRegister')
        response=self.client.get('/request/'+key);html=response.get_data(as_text=True)
        self.assertEqual(response.status_code,200)
        self.assertIn('مقصد ثبت‌شده در بررسی دسترسی',html)
        self.assertIn('v2/DeviceRegister',html)
        self.assertIn('Core.v2/DeviceRegister',html)
        self.assertIn('اثبات اجرای مقصد',html)

    def test_local_access_headers_and_invalid_parameters(self):
        response=self.client.get('/')
        self.assertEqual(response.headers['Cache-Control'],'no-store')
        self.assertIn("default-src 'none'",response.headers['Content-Security-Policy'])
        self.assertEqual(self.client.get('/',environ_overrides={'REMOTE_ADDR':'198.51.100.1'}).status_code,403)
        self.assertEqual(self.client.get('/',headers={'Host':'untrusted.invalid'}).status_code,400)
        for query in ('limit=0','scope=all','publication=bad','cursor='+('x'*4097)):
            self.assertEqual(self.client.get('/?'+query).status_code,400)
        request_key=next(iter(self.demo.summaries))
        for query in ('origin=service','from_service=service-key',
                      'origin=investigation&from_investigation=group-key&from_service=service-key',
                      'origin=investigation'):
            self.assertEqual(self.client.get('/request/'+request_key+'?'+query).status_code,400)

    def test_database_exception_is_not_exposed(self):
        @contextmanager
        def unavailable():raise RuntimeError('SYNTHETIC_DATABASE_PASSWORD');yield
        client=create_app(unavailable,initial_publication=self.demo.publication_id,mode='live').test_client()
        with self.assertLogs('p24_foundation.review_ui',level='WARNING') as logs:response=client.get('/')
        self.assertEqual(response.status_code,500)
        self.assertNotIn('SYNTHETIC_DATABASE_PASSWORD',response.get_data(as_text=True)+str(logs.output))

    def test_source_strings_are_html_escaped_and_demo_never_connects(self):
        key=next(iter(self.demo.summaries));self.demo.summaries[key]['endpoint']='<script>SYNTHETIC_XSS</script>'
        response=self.client.get('/request/'+key)
        self.assertIn('&lt;script&gt;',response.get_data(as_text=True))
        self.assertNotIn('<script>',response.get_data(as_text=True))
        with patch('p24_foundation.config.connect',side_effect=AssertionError('demo must stay offline')):
            self.assertEqual(create_app().test_client().get('/').status_code,200)

    def test_tehran_time_preserves_fraction_and_zero(self):
        value=parse_time('2026-10-20T07:28:22.4406337Z').epoch_ns
        self.assertEqual(tehran_time(value),'2026-10-20  10:58:22.4406337')
        self.assertIn('1970-01-01',tehran_time(0))
        self.assertEqual(tehran_time(None),'ثبت نشده')

    def test_registration_review_keeps_inference_explicit_and_links_both_requests(self):
        before=self.demo.session(self.demo.publication_id,identity_scope='assigned',limit=100)['totals']
        response=self.client.get('/registration-candidates');html=response.get_data(as_text=True)
        self.assertEqual(response.status_code,200);self.assertIn('این ثبت‌ها به آمار Session اضافه نشده',html)
        links=[unescape(v) for v in re.findall(r'href="([^"]+)"',html)]
        requests=[v for v in links if v.startswith('/request/')]
        self.assertEqual(len(requests),2)
        for link in requests:
            detail=self.client.get(link)
            self.assertEqual(detail.status_code,200);self.assertIn('/registration-candidates?',detail.get_data(as_text=True))
        self.assertEqual(self.demo.session(self.demo.publication_id,identity_scope='assigned',limit=100)['totals'],before)
        self.assertNotIn(self.demo.raw_session,html)

    def test_endpoint_exploration_pages_keep_exact_route_and_return_context(self):
        response=self.client.get('/services?limit=1');html=response.get_data(as_text=True)
        self.assertEqual(response.status_code,200)
        links=[unescape(v) for v in re.findall(r'href="([^"]+)"',html)]
        detail=next(v for v in links if v.startswith('/service/'))
        self.assertIn('publication='+self.demo.publication_id,detail)
        page=self.client.get(detail);self.assertEqual(page.status_code,200)
        request_link=next(unescape(v) for v in re.findall(r'href="([^"]+)"',page.get_data(as_text=True)) if v.startswith('/request/'))
        self.assertIn('from_service=',request_link)
        self.assertEqual(self.client.get(request_link).status_code,200)
        self.assertEqual(self.client.get(next(v for v in links if 'cursor=' in v)).status_code,200)
        self.assertEqual(self.client.get('/service/unknown').status_code,404)

    def test_incident_pages_keep_revision_and_request_evidence_pinned(self):
        response=self.client.get('/incidents');self.assertEqual(response.status_code,200)
        links=[unescape(v) for v in re.findall(r'href="([^"]+)"',response.get_data(as_text=True))]
        detail=next(v for v in links if v.startswith('/incident/'))
        self.assertIn('revision=',detail);self.assertIn('publication='+self.demo.publication_id,detail)
        page=self.client.get(detail);self.assertEqual(page.status_code,200)
        self.assertIn('نوبت‌های مشاهده',page.get_data(as_text=True))
        self.assertIn('workflow-evidence-list',page.get_data(as_text=True))

    def test_investigation_context_survives_incident_and_request_drilldown(self):
        saved=self.demo._incident_fixture()
        request_key=next(iter(self.demo.summaries))
        self.demo.investigation=lambda key:dict(investigation_id=key,title_fa='گروه آزمون',status='open',claim='proof only',
            links=[dict(incident_id=saved['incident_id'],incident_revision_id=saved['revision_id'],
                linked_incident_id='incident-z',linked_revision_id='revision-z',publication_id=self.demo.publication_id,
                basis='shared_request',revision_state='current',shared_request_count=1,shared_request_keys=[request_key],proof_sha256='digest-1'),
                dict(incident_id='incident-z',incident_revision_id='revision-z',linked_incident_id=saved['incident_id'],
                linked_revision_id=saved['revision_id'],publication_id=self.demo.publication_id,basis='shared_request',
                revision_state='current',shared_request_count=1,shared_request_keys=[request_key],proof_sha256='digest-1')])
        investigation=self.client.get('/investigation/group-key?publication='+self.demo.publication_id)
        self.assertEqual(investigation.status_code,200)
        incident_link=next(unescape(value) for value in re.findall(r'href="([^"]+)"',investigation.get_data(as_text=True))
            if value.startswith('/incident/'+saved['incident_id']))
        self.assertIn('origin=investigation',incident_link)
        self.assertIn('from_investigation=group-key',incident_link)
        incident=self.client.get(incident_link);incident_html=incident.get_data(as_text=True)
        self.assertEqual(incident.status_code,200)
        self.assertIn('/investigation/group-key?publication='+self.demo.publication_id,incident_html)
        self.assertRegex(incident_html,r'<a href="/investigations\?publication=[^"]+" aria-current="page">')
        request_link=next(unescape(value) for value in re.findall(r'href="([^"]+)"',incident_html)
            if value.startswith('/request/'+request_key))
        self.assertIn('origin=investigation',request_link)
        self.assertIn('from_investigation=group-key',request_link)
        request=self.client.get(request_link)
        self.assertEqual(request.status_code,200)
        request_html=request.get_data(as_text=True)
        self.assertIn('/investigation/group-key?publication='+self.demo.publication_id,request_html)
        self.assertRegex(request_html,r'<a href="/investigations\?publication=[^"]+" aria-current="page">')

    def test_feedback_requires_csrf_correct_origin_and_explicit_preview(self):
        from contextlib import nullcontext
        demo=self.demo;demo.review_preview=lambda key,**kw:dict(scope='pattern',affected_records=1,affected=[],preview_sha256='a'*64)
        seen=[];demo.review_decide=lambda key,**kw:seen.append((key,kw))
        client=create_app(lambda:nullcontext(demo),initial_publication=demo.publication_id,mode='live').test_client()
        key=demo._incident_fixture()['incident_id'];route='/incident/'+key+'/review'
        context='?publication='+demo.publication_id+'&origin=investigation&from_investigation=group-key'
        self.assertEqual(client.post(route,data={}).status_code,403)
        response=client.get(route+context);self.assertEqual(response.status_code,200)
        html=response.get_data(as_text=True)
        self.assertIn('/investigation/group-key?publication='+demo.publication_id,html)
        self.assertIn('origin=investigation',html)
        fields=dict(re.findall(r'name="([^"]+)" value="([^"]*)"',html))
        fields.update(verdict='benign',reason_key='operator_review')
        self.assertEqual(client.post(route+context,data=fields,headers={'Origin':'https://untrusted.invalid'}).status_code,403)
        self.assertEqual(seen,[])
        submitted=client.post(route+context,data=fields,headers={'Origin':'http://localhost'})
        self.assertEqual(submitted.status_code,303);self.assertIn('from_investigation=group-key',submitted.headers['Location'])
        self.assertEqual(seen[0][1]['preview_sha256'],'a'*64)
        self.assertEqual(self.client.get(route).status_code,403) # synthetic demo does not save decisions
