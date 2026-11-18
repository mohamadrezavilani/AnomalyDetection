"""Explain installation Git gates without resetting code or runtime evidence.

This file also runs through stdin before checkout, using only the standard
library. The one generated startup report may remain locally modified only
when its HEAD, index and target blobs are identical. Its bytes are preserved
privately; staged edits, deletion, symlinks and all other dirty paths block.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


REPORT = 'validation/viewer_startup.json'


def inspect(project, target, executable, output):
    project = Path(project).resolve()
    output = Path(output).resolve()
    if not re.fullmatch('[0-9a-fA-F]{40}', target):
        raise ValueError('FULL_TARGET_SHA_REQUIRED')
    private = (project / 'AnomalyDetection/reports').resolve()
    if not output.is_relative_to(private) or output == private:
        raise ValueError('PRIVATE_INSTALL_REPORT_PATH_REQUIRED')
    output.parent.mkdir(parents=True, exist_ok=True)
    result = dict(status='INSTALL_GIT_BLOCKED', target=target, changed_paths=[],
                  allowed_generated_reports=[], blocking_changes=[],
                  tracked_files_modified=False, index_modified=False,
                  database_modified=False, workers_stopped=False)

    def git(*args):
        process = subprocess.run([str(executable), '--no-optional-locks', *args], cwd=project,
                                 capture_output=True, timeout=30)
        if process.returncode:
            result['git_failure'] = dict(operation=args[0], exit_code=process.returncode,
                                        stderr=process.stderr[-4096:].decode('utf-8', 'replace'))
            raise ValueError('INSTALL_GIT_COMMAND_FAILED')
        return process.stdout

    try:
        if Path(os.fsdecode(git('rev-parse', '--show-toplevel').strip())).resolve() != project:
            raise ValueError('INSTALL_GIT_ROOT_MISMATCH')
        result['head'] = git('rev-parse', 'HEAD').decode('ascii').strip()
        records = git('status', '--porcelain=v1', '-z', '--untracked-files=no').split(b'\0')
        index = 0
        while index < len(records):
            record = records[index]
            index += 1
            if not record:
                continue
            code, name = record[:2].decode('ascii'), os.fsdecode(record[3:])
            item = dict(path=name, status=code)
            result['changed_paths'].append(item)
            if 'R' in code or 'C' in code:
                if index < len(records):
                    item['original_path'] = os.fsdecode(records[index])
                    index += 1
            if name != REPORT or code != ' M':
                result['blocking_changes'].append(item)
                continue
            path = project / name
            if path.is_symlink() or not path.resolve().is_relative_to(project) or not path.is_file():
                raise ValueError('STARTUP_REPORT_MUST_BE_A_LOCAL_REGULAR_FILE')
            if path.stat().st_size > 1024 * 1024:
                raise ValueError('STARTUP_REPORT_BYTE_BUDGET')
            head = git('ls-tree', '-z', 'HEAD', '--', name)
            selected = git('ls-tree', '-z', target, '--', name)
            staged = git('ls-files', '--stage', '-z', '--', name)
            fields = head.split(b'\t', 1)[0].split()
            expected_index = fields[0] + b' ' + fields[2] + b' 0\t' + os.fsencode(name) + b'\0' if len(fields) == 3 else b''
            if not head or head != selected or fields[0] != b'100644' or staged != expected_index:
                raise ValueError('STARTUP_REPORT_HEAD_INDEX_TARGET_MUST_MATCH')
            body = path.read_bytes()
            value = json.loads(body.decode('utf-8-sig'))
            if (not isinstance(value, dict) or value.get('mode') not in ('RESUME_CHECKPOINT', 'DEBUG_RECENT_START')
                    or not isinstance(value.get('live'), dict)
                    or not isinstance(value.get('runtime_source_sha256'), str)
                    or not re.fullmatch('[a-f0-9]{64}', value['runtime_source_sha256'])):
                raise ValueError('GENERATED_STARTUP_REPORT_CONTRACT_REQUIRED')
            digest = hashlib.sha256(body).hexdigest()
            saved = output.parent / ('preserved-startup-' + digest + '.json')
            if saved.exists():
                if saved.read_bytes() != body:
                    raise ValueError('PRESERVED_STARTUP_REPORT_CHANGED')
            else:
                with saved.open('xb') as stream:
                    stream.write(body)
                    stream.flush()
                    os.fsync(stream.fileno())
            if saved.read_bytes() != body:
                raise ValueError('PRESERVED_STARTUP_REPORT_VERIFICATION_FAILED')
            result['allowed_generated_reports'].append(dict(path=name, preserved=str(saved), sha256=digest,
                target_blob_unchanged=True, left_in_place=True))
        if git('rev-parse', 'HEAD').decode('ascii').strip() != result['head']:
            raise ValueError('INSTALL_GIT_HEAD_CHANGED')
        if not result['blocking_changes']:
            result['status'] = 'INSTALL_GIT_READY'
    except Exception as exc:
        result['failure'] = dict(error_type=type(exc).__name__,
                                code=str(exc) if isinstance(exc, ValueError) else None)
    with output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, ensure_ascii=True, indent=2)
        stream.write('\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', required=True, type=Path)
    parser.add_argument('--target', required=True)
    parser.add_argument('--git', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = inspect(args.project, args.target, args.git, args.output)
    print(json.dumps(dict(status=result['status'], output=str(args.output),
        changed_paths=result['changed_paths'], blocking_changes=result['blocking_changes'],
        preserved_reports=result['allowed_generated_reports'], failure=result.get('failure'),
        git_failure=result.get('git_failure')), ensure_ascii=True), flush=True)
    return 0 if result['status'] == 'INSTALL_GIT_READY' else 2


if __name__ == '__main__':
    raise SystemExit(main())
