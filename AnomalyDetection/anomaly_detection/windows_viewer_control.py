"""Stop only verified Viewer consoles and start the installed pinned runtime."""
import ctypes
from dataclasses import dataclass
import json
import ntpath
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

from .snapshot import require


@dataclass(frozen=True)
class ViewerProcess:
    role: str
    image: str
    command: str
    created: str | None


def windows_path(path):
    return ntpath.normcase(ntpath.normpath(str(path)))


def option(args, name):
    indices = [i for i,arg in enumerate(args) if arg.casefold()==name.casefold()]
    return args[indices[0]+1] if len(indices)==1 and indices[0]+1<len(args) else None


def role(args, executable, project, python_paths):
    """Require a full project/config binding even for relative launcher paths."""
    if len(args)<2:
        return None
    project=windows_path(project)
    expected_config=windows_path(ntpath.join(project,'viewer_config.local.py'))
    exe=windows_path(executable or '')
    if exe in python_paths:
        start=next((i for i,value in enumerate(args[1:],1) if value not in ('-u','-B')),None)
        if start is None:
            return None
        script,*tail=args[start:]
        path=windows_path(script)
        if path in ('viewer_performance\\run_viewer_memory.py',
                    windows_path(ntpath.join(project,'viewer_performance/Run_Viewer_Memory.py'))):
            bound=option(tail,'--project-root')
            return 'worker' if bound and windows_path(bound)==project and '--worker' in tail else None
        if path in ('tools\\run_behavior_viewer.py',
                    windows_path(ntpath.join(project,'tools/run_behavior_viewer.py'))) and tail:
            config=option(tail,'--config')
            if config and windows_path(config)==expected_config:
                return {'serve':'web','live':'worker'}.get(tail[0])
        return None
    if ntpath.basename(exe) not in ('powershell.exe','pwsh.exe'):
        return None
    launcher=option(args,'-File')
    config=option(args,'-Config')
    mode=option(args,'-Action')
    if launcher and config and mode and windows_path(config)==expected_config:
        known={windows_path(ntpath.join(project,path)) for path in
               ('tools/viewer.ps1','viewer_performance/viewer.ps1')}
        if windows_path(launcher) in known and mode.casefold() in ('worker','web'):
            return 'launcher'
    return None


def split_command_line(command):
    from ctypes import wintypes

    shell=ctypes.WinDLL('shell32',use_last_error=True)
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    shell.CommandLineToArgvW.argtypes=(wintypes.LPCWSTR,ctypes.POINTER(ctypes.c_int))
    shell.CommandLineToArgvW.restype=ctypes.POINTER(wintypes.LPWSTR)
    kernel.LocalFree.argtypes=(ctypes.c_void_p,)
    kernel.LocalFree.restype=ctypes.c_void_p
    count=ctypes.c_int()
    values=shell.CommandLineToArgvW(command,ctypes.byref(count))
    if not values:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return [values[i] for i in range(count.value)]
    finally:
        kernel.LocalFree(ctypes.cast(values,ctypes.c_void_p))


def viewer_processes(project):
    powershell=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
    script=(
        "$ErrorActionPreference='Stop'; "
        "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); "
        "Get-CimInstance Win32_Process -Filter \"Name='python.exe' OR Name='pythonw.exe' OR "
        "Name='powershell.exe' OR Name='pwsh.exe'\" | "
        "Select-Object ProcessId,ExecutablePath,CommandLine,CreationDate | ConvertTo-Json -Compress"
    )
    result=subprocess.run([str(powershell),'-NoProfile','-NonInteractive','-Command',script],
                          capture_output=True,encoding='utf-8-sig',errors='strict',timeout=15,
                          creationflags=subprocess.CREATE_NO_WINDOW)
    require(result.returncode==0, 'WINDOWS_PROCESS_INVENTORY_FAILED')
    entries=json.loads(result.stdout or '[]')
    if isinstance(entries,dict):
        entries=[entries]
    python_paths={windows_path(sys.executable),windows_path(sys._base_executable)}
    matched={}
    for entry in entries:
        command=entry.get('CommandLine')
        if command:
            identity=role(split_command_line(command),entry.get('ExecutablePath'),project,python_paths)
            if identity:
                matched[entry['ProcessId']]=ViewerProcess(identity,windows_path(entry['ExecutablePath']),
                                                         command,entry.get('CreationDate'))
    return matched


def console_stop(project, pid):
    """Run in a separate process. Signal only an exclusively owned console."""
    from ctypes import wintypes

    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.AttachConsole.argtypes=(wintypes.DWORD,)
    kernel.AttachConsole.restype=wintypes.BOOL
    kernel.GetConsoleProcessList.argtypes=(ctypes.POINTER(wintypes.DWORD),wintypes.DWORD)
    kernel.GetConsoleProcessList.restype=wintypes.DWORD
    kernel.SetConsoleCtrlHandler.argtypes=(ctypes.c_void_p,wintypes.BOOL)
    kernel.SetConsoleCtrlHandler.restype=wintypes.BOOL
    kernel.GenerateConsoleCtrlEvent.argtypes=(wintypes.DWORD,wintypes.DWORD)
    kernel.GenerateConsoleCtrlEvent.restype=wintypes.BOOL
    kernel.FreeConsole()
    expected=viewer_processes(project).get(pid)
    if expected is None or expected.role=='launcher':
        return []
    require(kernel.AttachConsole(pid), 'VIEWER_CONSOLE_ATTACH_FAILED')
    try:
        pids=(wintypes.DWORD*128)()
        count=kernel.GetConsoleProcessList(pids,len(pids))
        require(0<count<=len(pids), 'VIEWER_CONSOLE_MEMBERS_UNKNOWN')
        members=set(pids[:count])-{os.getpid()}
        matches=viewer_processes(project)
        require(pid in members and matches.get(pid)==expected and members<=matches.keys(),
                'VIEWER_CONSOLE_SHARED_STOP_WITH_CTRL_C')
        require(kernel.SetConsoleCtrlHandler(None,True), 'VIEWER_CONSOLE_HANDLER_FAILED')
        require(kernel.GenerateConsoleCtrlEvent(0,0), 'VIEWER_CONSOLE_STOP_SIGNAL_FAILED')
        time.sleep(.25)
        return sorted(members)
    finally:
        kernel.FreeConsole()


def port_is_open(port):
    with socket.socket() as conn:
        conn.settimeout(.5)
        return conn.connect_ex(('127.0.0.1',port))==0


def active_viewer_processes(project):
    return {pid:proc for pid,proc in viewer_processes(project).items() if proc.role in ('worker','web')}


def terminate_verified(project, expected):
    """Hold native handles while rechecking identity, so a recycled PID is safe."""
    from ctypes import wintypes

    if not expected:
        return 0
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.OpenProcess.argtypes=(wintypes.DWORD,wintypes.BOOL,wintypes.DWORD)
    kernel.OpenProcess.restype=wintypes.HANDLE
    kernel.QueryFullProcessImageNameW.argtypes=(wintypes.HANDLE,wintypes.DWORD,wintypes.LPWSTR,
                                              ctypes.POINTER(wintypes.DWORD))
    kernel.QueryFullProcessImageNameW.restype=wintypes.BOOL
    kernel.TerminateProcess.argtypes=(wintypes.HANDLE,wintypes.UINT)
    kernel.TerminateProcess.restype=wintypes.BOOL
    kernel.WaitForSingleObject.argtypes=(wintypes.HANDLE,wintypes.DWORD)
    kernel.WaitForSingleObject.restype=wintypes.DWORD
    kernel.CloseHandle.argtypes=(wintypes.HANDLE,)
    kernel.CloseHandle.restype=wintypes.BOOL
    terminate_query_sync=0x0001|0x1000|0x100000
    wait_signaled,wait_timeout=0,258
    handles={}
    try:
        for pid,proc in expected.items():
            require(proc.role in ('worker','web') and proc.created and pid>0 and pid!=os.getpid(),
                    'UNVERIFIED_VIEWER_STOP_TARGET')
            handle=kernel.OpenProcess(terminate_query_sync,False,pid)
            if not handle:
                if ctypes.get_last_error()==87:  # Process exited before OpenProcess.
                    continue
                require(False,'VIEWER_PROCESS_HANDLE_UNAVAILABLE')
            handles[pid]=handle

        current=active_viewer_processes(project)
        confirmed=[]
        for pid,handle in handles.items():
            if current.get(pid)!=expected[pid]:
                continue
            state=kernel.WaitForSingleObject(handle,0)
            if state==wait_signaled:
                continue
            require(state==wait_timeout,'VIEWER_PROCESS_STATE_UNAVAILABLE')
            image=ctypes.create_unicode_buffer(32768)
            length=wintypes.DWORD(len(image))
            if not kernel.QueryFullProcessImageNameW(handle,0,image,ctypes.byref(length)):
                if kernel.WaitForSingleObject(handle,0)==wait_signaled:
                    continue
                require(False,'VIEWER_PROCESS_IMAGE_UNAVAILABLE')
            require(windows_path(image.value)==expected[pid].image,'VIEWER_PROCESS_IMAGE_MISMATCH')
            confirmed.append(handle)

        terminated=0
        for handle in confirmed:
            if kernel.TerminateProcess(handle,1):
                terminated+=1
            else:
                require(kernel.WaitForSingleObject(handle,0)==wait_signaled,'VIEWER_PROCESS_TERMINATE_FAILED')
        deadline=time.monotonic()+15
        for handle in confirmed:
            milliseconds=max(0,int((deadline-time.monotonic())*1000))
            require(kernel.WaitForSingleObject(handle,milliseconds)==wait_signaled,'VIEWER_PROCESS_EXIT_TIMEOUT')
        return terminated
    finally:
        for handle in handles.values():
            kernel.CloseHandle(handle)


def stop(project, staged_script, progress):
    attempted=set()
    signaled=set()
    terminated=0
    deadline=time.monotonic()+20
    while active:=active_viewer_processes(project):
        if time.monotonic()>=deadline:
            progress('stop_verified_viewer_processes')
            terminated=terminate_verified(project,active)
            require(not active_viewer_processes(project),'VIEWER_PROCESS_STILL_RUNNING')
            break
        for pid in active:
            if pid in attempted:
                continue
            if time.monotonic()>=deadline:
                break
            attempted.add(pid)
            try:
                result=subprocess.run([sys.executable,str(staged_script),'--project',str(project),
                                       '--signal-viewer-console',str(pid)],
                                      capture_output=True,encoding='utf-8',errors='replace',
                                      timeout=max(1,deadline-time.monotonic()),
                                      creationflags=subprocess.CREATE_NO_WINDOW)
            except subprocess.TimeoutExpired:
                break
            value=json.loads(result.stdout)
            if result.returncode==0:
                signaled.update(value['signaled'])
                attempted.update(signaled)
            else:
                # A shared or unavailable console cannot receive a broadcast.
                # The verified-handle path after the grace period is targeted.
                code=value.get('failure',{}).get('code')
                require(code in ('VIEWER_CONSOLE_ATTACH_FAILED','VIEWER_CONSOLE_MEMBERS_UNKNOWN',
                                 'VIEWER_CONSOLE_SHARED_STOP_WITH_CTRL_C','VIEWER_CONSOLE_HANDLER_FAILED',
                                 'VIEWER_CONSOLE_STOP_SIGNAL_FAILED'),code or 'VIEWER_STOP_FAILED')
        time.sleep(.5)
    require(not port_is_open(5021),'UNRECOGNIZED_PROCESS_ON_VIEWER_PORT')
    return {'console_signaled':len(signaled),'terminated_verified_processes':terminated}


def launch(project):
    worker=subprocess.Popen([sys.executable,str(project/'viewer_performance/Run_Viewer_Memory.py'),
                             '--project-root',str(project),'--worker','--resume-checkpoint'],
                            cwd=project,creationflags=subprocess.CREATE_NEW_CONSOLE)
    web=subprocess.Popen([sys.executable,str(project/'tools/run_behavior_viewer.py'),'serve',
                          '--config',str(project/'viewer_config.local.py'),'--progress',
                          '--host','127.0.0.1','--port','5021'],
                         cwd=project,creationflags=subprocess.CREATE_NEW_CONSOLE)
    return worker,web
