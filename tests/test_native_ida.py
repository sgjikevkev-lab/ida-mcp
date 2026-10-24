"""Optional integration checks in a NEW IDA process on a disposable fixture.

Uses a private IDAUSR and never installs into, attaches to, or closes the user's
existing IDA sessions. Run with --ida pointing to IDA Pro 9.2 ida.exe.
"""
import argparse
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ida', required=True, type=Path)
    args = parser.parse_args()
    directory = ROOT / 'bin' / f'native-qa-{os.getpid()}'
    plugins = directory / 'user' / 'plugins'
    plugins.mkdir(parents=True)
    shutil.copy2(ROOT / 'bin/Release/ida_mcp64.dll', plugins / 'ida_mcp64.dll')
    fixture = directory / 'fixture.exe'
    shutil.copy2(ROOT / 'bin/Release/fixture.exe', fixture)
    env = dict(os.environ, IDAUSR=str(directory / 'user'), IDA_MCP_QA_DIR=str(directory))
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0
    process = subprocess.Popen([str(args.ida), '-A', f'-L{directory / "ida.log"}',
                                f'-S{ROOT / "tests/native_bootstrap.py"}', str(fixture)],
                               env=env, startupinfo=startup)
    pipe = rf'\\.\pipe\ida_mcp_{process.pid}'
    counter = 0
    covered = set()

    def call(name=None, arguments=None, method='tools/call', wait=15):
        nonlocal counter
        counter += 1
        request_id = counter
        request = {'jsonrpc': '2.0', 'id': request_id, 'method': method, '_cancel_token': f'qa-{request_id}'}
        if name is not None:
            covered.add(name)
            request['params'] = {'name': name, 'arguments': arguments or {}}
        responses = queue.Queue()
        def run():
            try:
                with open(pipe, 'r+b', buffering=0) as stream:
                    stream.write(json.dumps(request).encode() + b'\n')
                    line = bytearray()
                    while not line.endswith(b'\n'):
                        chunk = stream.read(1)
                        if not chunk:
                            raise RuntimeError('IDA pipe closed')
                        line += chunk
                    responses.put(json.loads(line))
            except BaseException as error:
                responses.put(error)
        threading.Thread(target=run, daemon=True).start()
        if wait is None:
            return request_id, responses
        response = responses.get(timeout=wait)
        if isinstance(response, BaseException):
            raise response
        assert response['id'] == request_id, response
        return response

    def text(response):
        return response['result']['content'][0]['text']

    def successful(name, arguments=None):
        response = call(name, arguments)
        assert not response.get('result', {}).get('isError', False), (name, response)
        return text(response)

    try:
        deadline = time.monotonic() + 45
        while not (directory / 'ready').exists():
            if process.poll() is not None:
                raise RuntimeError(f'IDA exited before startup: {process.returncode}; see {directory / "ida.log"}')
            if time.monotonic() >= deadline:
                raise TimeoutError(f'IDA startup timeout; see {directory / "ida.log"}')
            time.sleep(0.1)
        catalog = call(method='tools/list')['result']['tools']
        decompiler = next(tool for tool in catalog if tool['name'] == 'decompile')
        assert 'include_lvars' in decompiler['inputSchema']['properties'], 'Loaded plugin is not the new build'
        successful('survey_binary')
        successful('get_segments')
        successful('get_exports')
        successful('get_bytes', {'addr': 'mcp_fixture_add', 'size': 8})
        decompiled = successful('decompile', {'addr': 'mcp_fixture_add'})
        assert 'return' in decompiled and 'lvars' not in decompiled, decompiled
        assert json.loads(successful('py', {'code': '6 * 7'})) == {'result': 42}
        failed = call('py', {'code': "print('before-error')\nraise ValueError('native-test')"})
        assert failed['result']['isError'] and 'before-error' in text(failed), failed
        assert json.loads(successful('py', {'code': '1 + 1'})) == {'result': 2}
        failed = call('get_bytes', {'addr': '__missing_fixture_symbol__'})
        assert failed['result']['isError'], failed
        request_id, responses = call('py', {'code': 'while True:\n    pass'}, wait=None)
        time.sleep(0.3)
        assert 'true' in successful('get_status')
        with open(pipe, 'r+b', buffering=0) as stream:
            stream.write(json.dumps({'jsonrpc': '2.0', 'method': 'ida/cancel',
                                     'params': {'requestId': request_id, 'token': f'qa-{request_id}'}}).encode() + b'\n')
        cancelled = responses.get(timeout=5)
        assert not isinstance(cancelled, BaseException), cancelled
        assert cancelled['result']['isError'] and 'cancelled' in text(cancelled), cancelled
        assert json.loads(successful('py', {'code': '40 + 2'})) == {'result': 42}
        for name, arguments in [
            ('list_funcs', {'count': 3}),
            ('list_globals', {'count': 3}),
            ('imports_query', {'count': 3}),
            ('strings', {'count': 3}),
            ('find_bytes', {'pattern': 'DE AD BE EF', 'count': 1}),
            ('insn_query', {'func': 'mcp_fixture_add', 'count': 3}),
            ('disasm', {'addr': 'mcp_fixture_add', 'count': 3}),
            ('basic_blocks', {'addr': 'mcp_fixture_add'}),
            ('xref_query', {'addr': 'mcp_fixture_add', 'count': 3}),
            ('callgraph', {'addr': 'mcp_fixture_add', 'depth': 1, 'max_nodes': 10}),
            ('analyze_function', {'addr': 'mcp_fixture_add', 'max_callers': 3, 'max_callees': 3}),
            ('types', {'c_code': 'struct MCPFixture { int a; };'}),
            ('types', {'name': 'MCPFixture'}),
            ('rtti', {'pattern': '__no_fixture_class__', 'count': 1}),
            ('get_ast', {'addr': 'mcp_fixture_add', 'max_depth': 16}),
            ('mba_simplify', {'addr': 'mcp_fixture_add'}),
            ('simplify_predicate', {'addr': 'mcp_fixture_add', 'auto_detect': True, 'persist': False}),
            ('find_path', {'from': 'mcp_fixture_add', 'to': 'mcp_fixture_add', 'max_depth': 2}),
            ('trace_data_flow', {'addr': 'mcp_fixture_add', 'depth': 1}),
            ('make_signature', {'addr': 'mcp_fixture_add', 'max_length': 32}),
            ('stack_frame', {'addr': 'mcp_fixture_add'}),
            ('reconstruct_struct', {'addr': 'mcp_fixture_add', 'var': 'arg0', 'scan_depth': 1}),
            ('resolve_vcall', {'addr': 'mcp_fixture_add', 'index': 0}),
            ('idb_save', {}),
        ]:
            response = call(name, arguments)
            output = text(response)
            assert 'native_fault' not in output and 'backend_quarantined' not in output, (name, response)
            # A tiny arithmetic fixture has no frame/structure/vtable to recover.
            if name not in {'stack_frame', 'reconstruct_struct', 'resolve_vcall', 'make_signature'}:
                assert not response['result'].get('isError', False), (name, response)
        for name, arguments in [
            ('trace_data_flow', {'addr': 'mcp_fixture_update', 'var': 'arg0', 'depth': 2}),
            ('trace_data_flow', {'addr': 'mcp_fixture_call', 'var': 'arg0', 'direction': 'backward', 'depth': 2}),
            ('reconstruct_struct', {'addr': 'mcp_fixture_update', 'var': 'arg0', 'scan_depth': 1}),
            ('rtti', {'pattern': '*MCPFixture*', 'count': 10}),
            ('rtti', {'name': 'MCPFixtureDerived'}),
            ('resolve_vcall', {'class': 'MCPFixtureDerived', 'index': 0}),
            ('basic_blocks', {'addr': 'mcp_fixture_update', 'include_instructions': True}),
            ('callgraph', {'addr': 'mcp_fixture_call', 'depth': 2, 'max_nodes': 10}),
            ('get_ast', {'addr': 'mcp_fixture_update', 'pattern': {'op': 'cot_asg'}, 'max_matches': 5}),
        ]:
            successful(name, arguments)
        # Install a fixture-only database hook that attempts two SDK dialogs.
        # An ordinary refactor must suppress them even though host batch is off.
        assert json.loads(successful('py', {'code': 'import idc\nidc.batch(1)'})) == {'result': 0}
        successful('py', {'code': '''import ida_idp, ida_kernwin
qa_warning_seen = False
class QAHooks(ida_idp.IDB_Hooks):
    def renamed(self, ea, new_name, local_name):
        global qa_warning_seen
        qa_warning_seen = True
        ida_kernwin.warning('Fixture warning: must be suppressed by MCP')
        ida_kernwin.ask_yn(0, 'Fixture question: must be suppressed by MCP')
        return 0
qa_hooks = QAHooks()
qa_hooks.hook()
'''})
        receipt = successful('refactor', {'target': 'mcp_fixture_add', 'name': 'mcp_fixture_sum'})
        assert '"code"' not in receipt, receipt
        assert json.loads(successful('py', {'code': 'qa_hooks.unhook()\nqa_warning_seen'})) == {'result': True}
        assert covered == {tool['name'] for tool in catalog}, covered
        print(f'Native IDA 9.2 checks passed; artifacts: {directory}', flush=True)
    finally:
        (directory / 'stop').write_text('stop', encoding='utf-8')
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


if __name__ == '__main__':
    main()
