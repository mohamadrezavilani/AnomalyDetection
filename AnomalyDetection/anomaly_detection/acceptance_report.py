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
    from .process_control import read_json
    web=probe(include_details=True)
    failures=read_json(root/'reports/web_diagnostics.json',{})
    captured=StringIO()
    with redirect_stdout(captured):exit_code=review(project=root.parent)
    try:value=json.loads(captured.getvalue())
    except (ValueError,TypeError):value={'status':'REVIEW_RESULT_UNAVAILABLE'}
    review_path=Path(value['output']).resolve() if value.get('output') else None
    if review_path and (review_path.parent!=root/'reports' or not review_path.is_file()):review_path=None
    output=root/'reports'/('Anomaly_Final_Acceptance_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')+'_'+uuid.uuid4().hex[:8]+'.zip')
    output.parent.mkdir(parents=True,exist_ok=True)
    meta={'build_id':BUILD_ID,'source_sha256':sha,'worker_health':observed.get('health'),
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
    return {'status':'EVIDENCE_BUNDLE_EXPORTED' if review_path else 'PARTIAL_EVIDENCE_BUNDLE_EXPORTED',
        'output':str(output),'worker_health':observed.get('health'),'review_status':value.get('status'),
        'web_read_status':web['status'],
        'project_acceptance':'NOT_ASSIGNED_BY_COLLECTOR'}
