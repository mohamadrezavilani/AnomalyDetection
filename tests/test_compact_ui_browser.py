"""Synthetic evidence only; screenshots contain no server or user data."""
import os
from pathlib import Path
import unittest
from flask import render_template
from compact_product.web import create_app
from compact_product.config import Config
from compact_product.error_catalog import catalog_records
from compact_product.request_context import observed_context


@unittest.skipUnless(os.environ.get('P24_COMPACT_BROWSER'), 'native browser required')
class CompactUiBrowserTests(unittest.TestCase):
    def test_desktop_and_mobile_evidence_explanations(self):
        from playwright.sync_api import sync_playwright
        app = create_app(Config(), {}, 'preview', secret='test')
        entry = next(r for r in catalog_records() if r['code'] == 'GR0010')
        codes = {'GR0010': [dict(message_fa=entry['user_message_fa'], log_symbol=entry['log_symbol'],
            source=dict(file=entry['source_file'], sheet=entry['source_sheet'], row=entry['source_row']))]}
        row = dict(api='Services.v1/InvoiceRegister', request_id='demo-request-001', session_id='demo-session-001',
            service_key=None, behavior_id='demo', observed_at_ns=0, result_code='GR0010', revision=1,
            quality=['output_binding_unconfirmed', 'unresolved_dispatch'],
            state=dict(inputs=[dict(path='Services.v1/InvoiceRegister', basis='public_api', value={'Count': 1, 'UserAgent': 'Synthetic browser', 'IP': '192.0.2.1'})],
                outputs=[dict(path='ExampleProvider', basis='supporting', value={'Code': 'GR0010', 'Result': None})]))
        with app.test_request_context('/behaviors/demo'):
            detail = render_template('behavior.html', title='جزئیات رفتار', row=row,
                body=dict(operation_role='unknown', service_key=None, features={}), code_definitions=codes, request_context=observed_context(row['state']))
        with app.test_request_context('/?scope=unknown'):
            home = render_template('home.html', title='رفتارهای مشاهده‌شده', rows=[row]*3, scope='unknown', code_definitions=codes)
        from compact_product.cases import select_cases,REASONS
        signals=[dict(finding_id=m,method=m,session_id='demo',service='Services.v1/WaterBills',start_ns=0,
            result=dict(reference_windows=24,evidence=['a','b','c'],observed=30,baseline=2,threshold=10,subject_policy="inquiry_subjects_v1",numeric_path="WaterBillID"))
            for m in ('actor_rate','target_diversity')]
        from tests.test_compact_security import attempts, results, case_rows
        _,security_results=results(attempts()+attempts('invalid_session',30))
        signals.extend(case_rows(security_results))
        from tests.test_compact_audit35 import inquiry_rows
        from tests.test_compact_extract import extract, T
        from compact_behavior import FIVE
        from compact_behavior.extract import materialize
        from compact_ad.engine import summarize, evaluate
        summary,services,actors=summarize([materialize('preview',s) for s in extract(inquiry_rows(12,unknown_last=True,outcome='mixed')).values()],cutoff_ns=T+FIVE)
        breadth_results=evaluate(T,summary,services,actors,[])
        extra=case_rows([r for r in breadth_results if r.get('inquiry_breadth_policy')])
        for r in extra:r['finding_id']='breadth-'+r['finding_id']
        signals.extend(extra)
        selected=select_cases(signals)
        with app.test_request_context('/incidents?date=2026-11-22'):
            cases=render_template('cases.html',title='آنومالی‌های دارای شواهد تقویتی',rows=selected,
                date='2026-11-22',page=1,has_next=False,case_count=4,signal_count=5,truncated=False,reasons=REASONS)
        with app.test_request_context('/cases/synthetic?date=2026-11-22'):
            network=render_template('case.html',title='بررسی تلاش‌ها',case=next(c for c in selected if c['domain']=='network_attempts'),
                date='2026-11-22',days=1,truncated=False,reasons=REASONS,ips=['192.0.2.1'],ip_range={})
        with sync_playwright() as p:
            browser = p.chromium.launch(executable_path=os.environ['P24_COMPACT_BROWSER'], headless=True,
                args=['--no-sandbox', '--disable-dev-shm-usage'])
            try:
                page = browser.new_page()
                for width, size in ((1440, 'desktop'), (390, 'mobile')):
                    page.set_viewport_size(dict(width=width, height=1000))
                    for name, html in (('behavior', detail), ('home', home), ('cases',cases),('network',network)):
                        page.set_content(html)
                        self.assertLessEqual(page.evaluate('document.documentElement.scrollWidth'), width)
                        self.assertTrue(page.get_by_role('heading', level=1).is_visible())
                        if name in ('behavior','home'):self.assertIn('امکان برقراری ارتباط', page.locator('body').inner_text())
                        self.assertNotIn('نکتهٔ کیفیت', page.locator('body').inner_text())
                        if name == 'behavior':
                            self.assertIn('مشخصات ثبت‌شدهٔ درخواست', page.locator('body').inner_text())
                            self.assertIn('$.UserAgent', page.locator('body').inner_text())
                        if name == 'home':
                            self.assertEqual(page.locator('nav[aria-label="نوع رفتار"] a').count(),3)
                            self.assertEqual(page.locator('nav[aria-label="نوع رفتار"] a[href*="attempts"]').count(),0)
                            self.assertTrue(page.get_by_label('RequestID',exact=True).is_visible())
                            page.get_by_label('RequestID',exact=True).fill('demo-request-001')
                            self.assertTrue(page.get_by_label('IP',exact=True).is_visible())
                            self.assertEqual(page.locator('tbody tr').first.locator('a[href="/behaviors/demo"]').count(), 1)
                            self.assertEqual(page.locator('details[open]').count(), 0)
                            page.locator('.notes summary').first.click()
                            self.assertIn('خدمت مقصد', page.locator('.notes').first.inner_text())
                        if name=='cases':
                            self.assertEqual(page.locator('nav[aria-label="نمای آنومالی‌ها"] a').count(),3)
                            self.assertTrue(page.get_by_label('تا روز (میلادی، تهران)').is_visible())
                            self.assertEqual(page.locator('a[href^="/cases/"]').count(),4)
                            self.assertIn('حداقل 12 هدف',page.locator('body').inner_text())
                            self.assertTrue(page.get_by_role('link',name='سیگنال‌های ضعیف و بررسی تخصصی ←').is_visible())
                            self.assertIn('تلاش‌های یک IP',page.locator('body').inner_text())
                        if name=='network':
                            self.assertTrue(page.get_by_role('heading',name='تلاش‌های یک IP',exact=True).is_visible())
                            self.assertIn('5 توکن',page.locator('body').inner_text())
                            self.assertIn('IP مشترک',page.locator('body').inner_text())
                            self.assertEqual(page.locator('a[href^="/sessions"]').count(),0)
                        folder = os.environ.get('P24_COMPACT_UI_SCREENSHOTS')
                        if folder:
                            Path(folder).mkdir(parents=True, exist_ok=True)
                            page.screenshot(path=str(Path(folder) / f'{name}-{size}.png'), full_page=True)
            finally:
                browser.close()
