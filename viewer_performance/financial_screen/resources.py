"""Bounded observations of only the client and the identified PG backend.

RSS includes shared mappings: it is not summed into physical RAM consumption.
Process I/O includes kernel cache; it is never labelled physical disk traffic.
"""
from collections import Counter
import os
from pathlib import Path
import threading
import time


def process_usage(pid):
    try:
        if os.name=='nt':
            import ctypes
            from ctypes import wintypes as w
            api=ctypes.WinDLL('kernel32',use_last_error=True)
            api.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];api.OpenProcess.restype=w.HANDLE
            api.CloseHandle.argtypes=[w.HANDLE];api.CloseHandle.restype=w.BOOL
            api.GetProcessTimes.argtypes=[w.HANDLE,*([ctypes.POINTER(w.FILETIME)]*4)]
            api.QueryFullProcessImageNameW.argtypes=[w.HANDLE,w.DWORD,w.LPWSTR,ctypes.POINTER(w.DWORD)]
            handle=api.OpenProcess(0x1000|0x10,False,pid)
            if not handle:raise OSError('process handle unavailable')
            class Memory(ctypes.Structure):
                _fields_=[('cb',w.DWORD),('PageFaultCount',w.DWORD)]+[(n,ctypes.c_size_t) for n in (
                    'PeakWorkingSetSize','WorkingSetSize','QuotaPeakPagedPoolUsage','QuotaPagedPoolUsage',
                    'QuotaPeakNonPagedPoolUsage','QuotaNonPagedPoolUsage','PagefileUsage','PeakPagefileUsage')]
            try:
                times=[w.FILETIME() for _ in range(4)]
                if not api.GetProcessTimes(handle,*[ctypes.byref(t) for t in times]):raise OSError('process times unavailable')
                memory=Memory();memory.cb=ctypes.sizeof(memory)
                psapi=ctypes.WinDLL('psapi');psapi.GetProcessMemoryInfo.argtypes=[w.HANDLE,ctypes.c_void_p,w.DWORD]
                if not psapi.GetProcessMemoryInfo(handle,ctypes.byref(memory),memory.cb):raise OSError('memory unavailable')
                length=w.DWORD(32768);image=ctypes.create_unicode_buffer(length.value)
                if not api.QueryFullProcessImageNameW(handle,0,image,ctypes.byref(length)):raise OSError('image unavailable')
                stamp=lambda t:(t.dwHighDateTime<<32)|t.dwLowDateTime
                return dict(status='READ',identity=stamp(times[0]),cpu_seconds=(stamp(times[2])+stamp(times[3]))/1e7,
                    rss_bytes=memory.WorkingSetSize,created_epoch_seconds=stamp(times[0])/1e7-11644473600,
                    image_name=image.value.replace('\\','/').rsplit('/',1)[-1].lower())
            finally:api.CloseHandle(handle)
        stat=Path('/proc/'+str(pid)+'/stat').read_text();fields=stat.rsplit(')',1)[1].split()
        boot=next(int(line.split()[1]) for line in Path('/proc/stat').read_text().splitlines() if line.startswith('btime '))
        status=dict(line.split(':',1) for line in Path('/proc/'+str(pid)+'/status').read_text().splitlines() if ':' in line)
        return dict(status='READ',identity=fields[19],cpu_seconds=(int(fields[11])+int(fields[12]))/os.sysconf('SC_CLK_TCK'),
            rss_bytes=int(status['VmRSS'].split()[0])*1024,created_epoch_seconds=boot+int(fields[19])/os.sysconf('SC_CLK_TCK'),
            image_name=stat.split('(',1)[1].rsplit(')',1)[0])
    except (OSError,KeyError,ValueError):return dict(status='UNAVAILABLE')


def available_memory():
    try:
        if os.name=='nt':
            import ctypes
            class Status(ctypes.Structure):
                _fields_=[('length',ctypes.c_ulong),('load',ctypes.c_ulong)]+[(n,ctypes.c_ulonglong) for n in (
                    'total','available','total_page','available_page','total_virtual','available_virtual','extended')]
            value=Status();value.length=ctypes.sizeof(value)
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(value)):return None
            return value.available
        rows=Path('/proc/meminfo').read_text().splitlines()
        return next(int(row.split()[1])*1024 for row in rows if row.startswith('MemAvailable:'))
    except (OSError,StopIteration):return None


class Sampler:
    def __init__(self,admin,db,guard,deadline,*,interval=2):
        self.admin,self.db,self.guard,self.deadline=admin,db,guard,deadline
        self.interval=interval;self.done=threading.Event();self.waits=Counter();self.samples=0;self.failure=None
        self.peaks={};self.first={};self.last={};self.max_database_bytes=0;self.unavailable={}
        self.thread=threading.Thread(target=self.observe,daemon=True)

    def tick(self):
        self.guard()
        memory=available_memory()
        if memory is not None and memory<4*1024**3:raise ValueError('SCREEN_OS_MEMORY_RESERVE_REACHED')
        if time.monotonic()>self.deadline:raise TimeoutError('SCOPE_SCREEN_BUDGET_EXHAUSTED')
        row=self.admin.execute('SELECT backend_start,wait_event_type,wait_event FROM pg_stat_activity WHERE pid=%s',
            (self.db.conn.info.backend_pid,)).fetchone()
        if not row:raise ValueError('SCREEN_BACKEND_REPLACED')
        self.waits[(row['wait_event_type'] or 'CPU_OR_RUNNABLE')+':'+(row['wait_event'] or '-')]+=1
        size=self.admin.execute('SELECT pg_database_size(%s) AS n',(self.db.conn.info.dbname,)).fetchone()['n']
        self.max_database_bytes=max(self.max_database_bytes,size)
        if size>16*1024**3:raise ValueError('SCREEN_DATABASE_SPACE_BUDGET_EXCEEDED')
        for name,pid in (('client',os.getpid()),('postgres_backend',self.db.conn.info.backend_pid)):
            item=process_usage(pid)
            if name=='postgres_backend' and item['status']=='READ' and (item['image_name'] not in ('postgres','postgres.exe') or
                    abs(item['created_epoch_seconds']-row['backend_start'].timestamp())>5):
                item=dict(status='UNVERIFIED_OS_PID_NAMESPACE')
            if item['status']=='READ':
                if name=='client' and item['rss_bytes']>2*1024**3:raise ValueError('SCREEN_CLIENT_MEMORY_BUDGET_EXCEEDED')
                if name in self.first and self.first[name]['identity']!=item['identity']:raise ValueError('SCREEN_OS_PROCESS_REPLACED')
                self.first.setdefault(name,item);self.last[name]=item
                self.peaks[name]=max(self.peaks.get(name,0),item['rss_bytes'])
            else:self.unavailable[name]=item['status']
        self.samples+=1

    def observe(self):
        while not self.done.wait(self.interval):
            try:self.tick()
            except Exception as exc:
                self.failure=exc
                try:self.db.conn.cancel()
                except Exception:pass
                return

    def __enter__(self):self.tick();self.thread.start();return self
    def __exit__(self,*args):
        self.done.set();self.thread.join(10)
        if self.thread.is_alive():raise ValueError('SCREEN_MONITOR_DID_NOT_STOP')
        if self.failure:raise self.failure
        if not any(args):self.tick()

    def report(self):
        return dict(samples=self.samples,interval_seconds=self.interval,wait_samples=dict(self.waits),
            max_database_bytes=self.max_database_bytes,processes={name:dict(
                cpu_seconds=self.last[name]['cpu_seconds']-item['cpu_seconds'],peak_sampled_rss_bytes=self.peaks[name])
                for name,item in self.first.items()},unavailable_processes=self.unavailable,cpu_scope='verified_image_and_start_time_only',
            rss_shared_pages_are_not_additive=True,physical_disk_io='NOT_ATTRIBUTED',
            queue_depth='NOT_RUN_NO_DOWNSTREAM_AD',raw_sample_storage_bounded=True)
