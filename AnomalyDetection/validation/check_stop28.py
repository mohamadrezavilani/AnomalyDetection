"""Regression for delayed Windows Viewer shutdown and scoped process handles."""
from contextlib import nullcontext
import ctypes
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock, patch

import Joint_Update
from anomaly_detection import BUILD_ID
from anomaly_detection import viewer_raw_retention as retention
from anomaly_detection import windows_viewer_control as windows
from anomaly_detection.snapshot import ContractError


PROJECT=Path('fixture_project')
IMAGE=r'c:\testproject\.venv\scripts\python.exe'
WORKER=windows.ViewerProcess('worker',IMAGE,'verified worker','creation-a')
WEB=windows.ViewerProcess('web',IMAGE,'verified web','creation-b')


def delayed_stop():
    active={12:WORKER,18:WEB}
    signal=SimpleNamespace(returncode=0,stdout=json.dumps({'signaled':[12,18]}))
    events=[]
    with patch.object(windows,'active_viewer_processes',side_effect=[active,active,{}]), \
         patch.object(windows,'time',SimpleNamespace(monotonic=Mock(side_effect=[0,1,1,1,21]),
                                                    sleep=Mock())), \
         patch.object(subprocess,'CREATE_NO_WINDOW',1,create=True), \
         patch.object(subprocess,'run',return_value=signal) as graceful, \
         patch.object(windows,'terminate_verified',return_value=2) as fallback, \
         patch.object(windows,'port_is_open',return_value=False):
        result=windows.stop(PROJECT,Path('Joint_Update.py'),events.append)
    assert graceful.call_count==1
    fallback.assert_called_once_with(PROJECT,active)
    assert events==['stop_verified_viewer_processes']
    assert result=={'console_signaled':2,'terminated_verified_processes':2}


def released_port_required():
    with patch.object(windows,'active_viewer_processes',return_value={}), \
         patch.object(windows,'port_is_open',return_value=True), \
         patch.object(windows,'terminate_verified') as fallback:
        try:
            windows.stop(PROJECT,Path('Joint_Update.py'),lambda stage:None)
        except ContractError as exc:
            assert str(exc)=='UNRECOGNIZED_PROCESS_ON_VIEWER_PORT'
        else:
            raise AssertionError('unrecognized listener accepted')
        fallback.assert_not_called()


def kernel_for_fixture(image=IMAGE):
    exited=set()
    def query_image(handle,flags,buffer,length):
        buffer.value=image
        return True
    def end_process(handle,code):
        exited.add(handle)
        return True
    return SimpleNamespace(
        OpenProcess=Mock(side_effect=lambda access,inherit,pid:pid+1000),
        QueryFullProcessImageNameW=Mock(side_effect=query_image),
        TerminateProcess=Mock(side_effect=end_process),
        WaitForSingleObject=Mock(side_effect=lambda handle,ms:0 if handle in exited else 258),
        CloseHandle=Mock(return_value=True))


def handle_verification():
    kernel=kernel_for_fixture()
    recycled=windows.ViewerProcess('web',IMAGE,'verified web','creation-reused')
    with patch.object(ctypes,'WinDLL',return_value=kernel,create=True), \
         patch.object(windows,'os',SimpleNamespace(getpid=lambda:99)), \
         patch.object(windows,'active_viewer_processes',return_value={12:WORKER,18:recycled}):
        assert windows.terminate_verified(PROJECT,{12:WORKER,18:WEB})==1
    kernel.TerminateProcess.assert_called_once_with(1012,1)
    assert {call.args[0] for call in kernel.CloseHandle.call_args_list}=={1012,1018}
    assert any(call.args[1]>0 for call in kernel.WaitForSingleObject.call_args_list)

    kernel=kernel_for_fixture(image=r'C:\other\python.exe')
    with patch.object(ctypes,'WinDLL',return_value=kernel,create=True), \
         patch.object(windows,'os',SimpleNamespace(getpid=lambda:99)), \
         patch.object(windows,'active_viewer_processes',return_value={12:WORKER}):
        try:
            windows.terminate_verified(PROJECT,{12:WORKER})
        except ContractError as exc:
            assert str(exc)=='VIEWER_PROCESS_IMAGE_MISMATCH'
        else:
            raise AssertionError('different executable accepted')
    kernel.TerminateProcess.assert_not_called()
    kernel.CloseHandle.assert_called_once_with(1012)


def database_release():
    execute=Mock(side_effect=[
        SimpleNamespace(fetchone=lambda:{'worker_idle':False,'writer_idle':True}),
        SimpleNamespace(fetchone=lambda:{'worker_idle':True,'writer_idle':True}),
    ])
    with patch.object(retention,'viewer_database',return_value=nullcontext(SimpleNamespace(execute=execute))), \
         patch.object(Joint_Update,'time',SimpleNamespace(monotonic=Mock(side_effect=[0,1,2]),sleep=Mock())):
        Joint_Update.wait_for_viewer_release(PROJECT)
    assert execute.call_count==2


if __name__=='__main__':
    delayed_stop()
    released_port_required()
    handle_verification()
    database_release()
    print(json.dumps({'status':'PASS_VIEWER_STOP_REGRESSION','build_id':BUILD_ID,
        'environment':'LINUX_WIN32_API_AND_DATABASE_BOUNDARY_FIXTURES','native_windows':'NOT_RUN',
        'checks':{'delayed_console_stop_uses_targeted_fallback':'PASS',
                  'recycled_identity_and_mismatched_image_not_terminated':'PASS',
                  'termination_waits_for_handle_signal_and_closes_handles':'PASS',
                  'unknown_port_listener_blocks_upgrade':'PASS',
                  'viewer_advisory_locks_are_rechecked_before_upgrade':'PASS'}},indent=2))
