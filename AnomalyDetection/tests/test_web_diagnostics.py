import io,json,tempfile,unittest
from pathlib import Path
from anomaly_detection import BUILD_ID
from anomaly_detection.web_diagnostics import record,probe


class WebDiagnosticsTests(unittest.TestCase):
    def test_bounded_trace_never_exports_exception_sql_payload_or_session_query(self):
        with tempfile.TemporaryDirectory() as temp:
            for _ in range(25):
                try:raise RuntimeError('private-payload secret-token SQL SELECT 1')
                except RuntimeError as exc:record(temp,'/case/private-session','render_owned_page',exc,[])
            value=json.loads((Path(temp)/'reports/web_diagnostics.json').read_text())
            self.assertEqual(len(value['events']),20)
            for word in ('private-payload','secret-token','SELECT 1','private-session'):self.assertNotIn(word,json.dumps(value))
            self.assertEqual(value['events'][-1]['route'],'/detail')

    def test_probe_checks_actual_build_without_saving_html_or_cookies(self):
        class Response(io.BytesIO):status=200
        calls=[]
        def open_page(request,timeout):
            calls.append((request.get_method(),request.full_url,timeout))
            text=json.dumps({'build_id':BUILD_ID}) if request.full_url.endswith('/api/status') else '<html dir="rtl"><table>private-data</table>'+BUILD_ID
            return Response(text.encode())
        value=probe(opener=open_page)
        self.assertEqual(value['status'],'PASS_LOCAL_GETS');self.assertEqual(len(calls),4)
        self.assertTrue(all(m=='GET' and url.startswith('http://127.0.0.1:5022/') and n<=5 for m,url,n in calls))
        self.assertNotIn('private-data',json.dumps(value));self.assertFalse(value['proves_detection_accuracy'])

    def test_wrong_build_or_unreachable_page_is_not_success(self):
        class Response(io.BytesIO):status=200
        self.assertEqual(probe(opener=lambda *a,**k:Response(b'{}'))['status'],'PARTIAL_OR_FAILED_LOCAL_GETS')
        def broken(*args,**kwargs):raise OSError('do-not-export-this')
        value=probe(opener=broken)
        self.assertEqual(value['status'],'PARTIAL_OR_FAILED_LOCAL_GETS')
        self.assertNotIn('do-not-export-this',json.dumps(value))

    def test_extended_probe_follows_only_a_local_case_key_and_records_dossier_budget(self):
        class Response(io.BytesIO):status=200
        key='ac1:'+'a'*64;calls=[]
        def open_page(request,timeout):
            calls.append(request.full_url)
            if request.full_url.endswith('/api/status'):body=json.dumps({'build_id':BUILD_ID})
            else:
                body='<html dir="rtl">'+BUILD_ID+'<table></table><a href="https://outside.invalid">outside</a>'
                if '/case/' in request.full_url:body+='چرا فعال شده و چقدر قابل اتکاست؟ جزئیات در زمان این خواندن آماده نشد'
                else:body+='<a href="/case/'+key+'">case</a>'
            return Response(body.encode())
        value=probe(opener=open_page,include_details=True)
        self.assertEqual(len(calls),8);self.assertEqual(value['detail_probe'],'CASE_LINK_FOUND')
        detail=next(p for p in value['pages'] if p['path'].startswith('/case/'))
        self.assertEqual(detail['evidence_read_status'],'PENDING_BUDGET');self.assertTrue(detail['method_reason_present'])
        self.assertTrue(all(url.startswith('http://127.0.0.1:5022/') for url in calls))


if __name__=='__main__':unittest.main()
