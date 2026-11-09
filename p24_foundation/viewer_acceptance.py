"""Explicit, non-vacuous acceptance gates for the finite native Viewer pilot."""
from __future__ import annotations
import math


def nonnegative_number(value):
    return type(value) in (int,float) and math.isfinite(value) and value>=0


def evaluate_pilot(report):
    windows=report.get('windows',[]);rechecks=report.get('rechecks',[])
    requested=report.get('requested_windows',6);required=report.get('required_rechecks',2)
    def published(rows,mode):
        modes=mode if isinstance(mode,tuple) else (mode,)
        return all(row.get('status')=='PUBLISHED' and row.get('mode') in modes and
            nonnegative_number(row.get('total_cycle_seconds')) for row in rows)
    cycles=windows+rechecks
    before=report.get('before',{}).get('backlog_windows');after=report.get('after',{}).get('backlog_windows')
    latency=report.get('http_latency',{})
    def ui(kind,budget):
        row=latency.get(kind,{})
        return type(row.get('samples')) is int and row['samples']>0 and \
            nonnegative_number(row.get('p95_seconds')) and row['p95_seconds']<=budget
    return dict(
        six_forward_windows_complete=(type(requested) is int and requested>=6 and len(windows)==requested and published(windows,'forward')),
        rechecks_complete=(type(required) is int and required>=2 and len(rechecks)>=required and published(rechecks,('recheck','manual_recheck'))),
        restart_performed=report.get('restart_performed') is True,
        restart_checkpoint_preserved=report.get('restart_checkpoint_preserved') is True,
        all_cycles_under_budget=bool(cycles) and all(nonnegative_number(r.get('total_cycle_seconds')) and r['total_cycle_seconds']<=300 for r in cycles),
        http_without_errors=type(report.get('http_errors')) is int and report['http_errors']==0,
        ui_budget_met=ui('home',2) and ui('session',3) and ui('request',3),
        backlog_not_growing=type(before) is int and type(after) is int and 0<=after<=before,
    )


def evaluate_development_smoke(report):
    """Explicit non-acceptance gates for bounded live developer feedback.

    A smoke result cannot satisfy evaluate_pilot nor read-only install acceptance.
    A reconnect checks checkpoint persistence but is not a process restart test.
    """
    windows=report.get('windows',[]);rechecks=report.get('rechecks',[])
    requested=report.get('requested_windows');required=report.get('required_rechecks')
    def valid(rows,mode):
        return all(isinstance(row,dict) and row.get('status')=='PUBLISHED' and
                   row.get('mode') in mode and
                   nonnegative_number(row.get('total_cycle_seconds')) and
                   row['total_cycle_seconds']<=300 for row in rows)
    ui=report.get('http_latency',{})
    def sampled(kind,limit):
        row=ui.get(kind,{})
        return isinstance(row,dict) and type(row.get('samples')) is int and row['samples']>0 and \
            nonnegative_number(row.get('p95_seconds')) and row['p95_seconds']<=limit
    return dict(
        bounded_forward_windows=(type(requested) is int and 1<=requested<=5 and
                                 len(windows)==requested and valid(windows,('forward',))),
        bounded_rechecks=(type(required) is int and 0<=required<=2 and
                          len(rechecks)>=required and valid(rechecks,('recheck','manual_recheck'))),
        reconnect_checkpoint_preserved=(report.get('restart_performed') is True and
                                        report.get('restart_checkpoint_preserved') is True),
        http_without_errors=type(report.get('http_errors')) is int and report['http_errors']==0,
        ui_budget_met=sampled('home',2) and sampled('session',3) and sampled('request',3),
    )
