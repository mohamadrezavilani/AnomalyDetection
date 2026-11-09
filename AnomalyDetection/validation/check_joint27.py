"""Safety and sequencing regression for the coordinator, without a native host."""
from contextlib import nullcontext
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

import Joint_Update
import Install_Update
from anomaly_detection import BUILD_ID
from anomaly_detection import windows_viewer_control as windows
from anomaly_detection import native_pg,viewer_raw_retention as retention
from anomaly_detection.snapshot import ContractError


def process_selection():
    project=r'C:\Users\Administrator\PycharmProjects\TestProject\pishkhan24'
    python=r'C:\Users\Administrator\PycharmProjects\TestProject\.venv\Scripts\python.exe'
    args=[python,r'.\viewer_performance\Run_Viewer_Memory.py','--project-root',project,'--worker']
    allowed={windows.windows_path(python)}
    assert windows.role(args,python,project,allowed)=='worker'
    assert windows.role(args[:-1],python,project,allowed) is None
    assert windows.role(args,python,project+'-other',allowed) is None
    config=project+r'\viewer_config.local.py'
    args=[python,r'.\tools\run_behavior_viewer.py','serve','--config',config]
    assert windows.role(args,python,project,allowed)=='web'
    assert windows.role(args,python+'-other',project,allowed) is None
    assert windows.role(args[:-1]+['viewer_config.local.py'],python,project,allowed) is None
    ps=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    args=[ps,'-NoExit','-File',project+r'\viewer_performance\viewer.ps1','-Action','Web','-Config',config]
    assert windows.role(args,ps,project,allowed)=='launcher'
    assert windows.role(args[:-1]+[config+'-other'],ps,project,allowed) is None


def coordinated_flow(root, blocked):
    order=[]
    project=root/'project'
    ad=project/'AnomalyDetection'
    ad.mkdir(parents=True,exist_ok=True)
    (ad/'run_anomaly.py').touch()
    args=SimpleNamespace(project=project,from_tehran_date='2026-11-07',apply=True,
                         pg_data_dir=None,observe_seconds=0)
    result={}
    def stage(name,value):
        order.append(name)
        return value
    def mock_invoke(project,runner,*args,**kw):
        if args[0]=='--config':
            return stage('check',(0,{'status':'READY_TO_START'}))
        assert args[0]=='worker-start'
        return stage('start-ad',(0,{'status':'STARTED'}))
    startup={'viewer_web':True,'ad_web':True,'viewer_worker_lease':True,
             'ad_worker_verified':True,'viewer_process_exit_codes':[None,None]}
    with patch.object(Joint_Update,'os',SimpleNamespace(name='nt')), \
         patch.object(retention,'verify_viewer',return_value=({},('%Payment%',))), \
         patch.object(retention,'viewer_database',return_value=nullcontext(None)), \
         patch.object(native_pg,'database',return_value=nullcontext(None)), \
         patch.object(retention,'db_identity',return_value={}), \
         patch.object(retention,'scope_status',return_value={}), \
         patch.object(retention,'raw_tables',return_value={}), \
         patch.object(windows,'stop',side_effect=lambda *a:stage('stop-viewer',{})), \
         patch.object(Joint_Update,'wait_for_viewer_release',side_effect=lambda *a:stage('wait-viewer-db',None)), \
         patch.object(Joint_Update,'ad_stop',side_effect=lambda *a:stage('stop-ad',None)), \
         patch.object(windows,'port_is_open',return_value=False), \
         patch.object(Install_Update,'install',side_effect=lambda *a,**kw:stage('install',{})), \
         patch.object(Joint_Update,'compact_with_locks',side_effect=lambda *a:stage('compact',{'status':
                      'VIEWER_RAW_BLOCKED_DISK_HEADROOM' if blocked else 'VIEWER_RAW_APPLIED'})), \
         patch.object(windows,'launch',side_effect=lambda *a:stage('start-viewer',())), \
         patch.object(Joint_Update,'invoke',side_effect=mock_invoke), \
         patch.object(Joint_Update,'observe_started',side_effect=lambda *a:stage('observe',startup)):
        Joint_Update.run(args,'fixture',result,lambda stage:None)
    assert order==['check','stop-viewer','wait-viewer-db','stop-ad','install','compact','start-viewer','start-ad','observe'],order
    assert result['status']==('SERVICES_STARTED_MAINTENANCE_INCOMPLETE' if blocked else 'JOINT_APPLIED_AND_STARTED')


def main():
    process_selection()
    with patch.object(Joint_Update,'invoke',side_effect=[(2,{'status':'STOP_REQUESTED'}),(0,{'status':'STOPPED'})]) as cli:
        Joint_Update.ad_stop(Path('.'),Path('run_anomaly.py'))
        assert cli.call_count==2
    with patch.object(Joint_Update,'invoke',return_value=(1,{'status':'ERROR'})):
        try:
            Joint_Update.ad_stop(Path('.'),Path('run_anomaly.py'))
        except ContractError as exc:
            assert str(exc)=='AD_STOP_FAILED'
        else:
            raise AssertionError('unverified stop accepted')
    with tempfile.TemporaryDirectory(prefix='ad27_joint_',dir=Path(__file__).parent) as folder:
        coordinated_flow(Path(folder),False)
        coordinated_flow(Path(folder),True)
    print(json.dumps({'status':'PASS_COORDINATED_UPGRADE_SEQUENCING','build_id':BUILD_ID,
         'environment':'LINUX_SELECTOR_AND_MOCKED_LIFECYCLE','windows_console_signal':'NOT_RUN',
         'checks':{'owned_project_worker_and_web_matching':'PASS',
                   'stop_requested_retries_but_unknown_failures_stop':'PASS',
                   'verify_stop_both_install_compact_start_both_observe':'PASS',
                   'restore_both_services_if_disk_preflight_blocks_deletion':'PASS'}},indent=2))


if __name__=='__main__':
    main()
