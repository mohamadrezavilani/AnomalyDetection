"""One read-only evidence bundle; collecting a report never grants acceptance."""
from contextlib import redirect_stdout
from datetime import datetime,timezone
from io import StringIO
import json
from pathlib import Path
import uuid,zipfile
from . import BUILD_ID


def collect(root,sha,*,seconds=60):
    from .product_control import export_report
    from .case_export import main as review
    root=Path(root).resolve()
    observed,worker_path=export_report(root,sha,observe_seconds=seconds)
    from .web_diagnostics import probe
    from .process_control import read_observed_json
    web=probe(include_details=True)
    failures,web_error=read_observed_json(root/'reports/web_diagnostics.json')
    installed,manifest_error=read_observed_json(root/'RELEASE_MANIFEST.json')
    diagnostics=list(observed.get('diagnostic_failures',[]))
    if web_error: diagnostics.append({'stage':'web_diagnostics','failure':web_error})
    if manifest_error: diagnostics.append({'stage':'installed_manifest','failure':manifest_error})
    captured=StringIO()
    with redirect_stdout(captured):exit_code=review(project=root.parent)
    try:value=json.loads(captured.getvalue())
    except (ValueError,TypeError):value={'status':'REVIEW_RESULT_UNAVAILABLE'}
    review_path=Path(value['output']).resolve() if value.get('output') else None
    if review_path and (review_path.parent!=root/'reports' or not review_path.is_file()):review_path=None
    output=root/'reports'/('Anomaly_Final_Acceptance_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')+'_'+uuid.uuid4().hex[:8]+'.zip')
    output.parent.mkdir(parents=True,exist_ok=True)
    meta={'build_id':BUILD_ID,'source_sha256':sha,'worker_health':observed.get('health'),
        'identity_scope':'REPORT_COLLECTOR_NOT_RUNNING_WORKER',
        'installed_build_id':installed.get('build_id'),'installed_source_sha256':installed.get('source_sha256'),
        'worker_identity_verified':observed.get('observation_matches_process',False),
        'diagnostic_failures':diagnostics,
        'observation_seconds':seconds,'review_status':value.get('status'),'review_exit_code':exit_code,
        'review_included':review_path is not None,'models_executed_by_collector':False,
        'web_read_status':web['status'],
        'source_modified':False,'database_modified':False,'project_acceptance':'NOT_ASSIGNED_BY_COLLECTOR'}
    with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as z:
        z.write(worker_path,'worker_report.zip')
        if review_path:z.write(review_path,'case_review.zip')
        z.writestr('web_read_probe.json',json.dumps(web,ensure_ascii=False,indent=2))
        z.writestr('web_diagnostics.json',json.dumps(failures,ensure_ascii=False,indent=2))
        z.writestr('acceptance_manifest.json',json.dumps(meta,ensure_ascii=False,indent=2))
    complete=bool(review_path and exit_code==0 and value.get('status')=='COMPLETE_READ_ONLY_CASE_REVIEW' and not diagnostics)
    return {'status':'EVIDENCE_BUNDLE_EXPORTED' if complete else 'PARTIAL_EVIDENCE_BUNDLE_EXPORTED',
        'output':str(output),'worker_health':observed.get('health'),'review_status':value.get('status'),
        'diagnostic_failures':diagnostics,
        'web_read_status':web['status'],
        'project_acceptance':'NOT_ASSIGNED_BY_COLLECTOR'}
