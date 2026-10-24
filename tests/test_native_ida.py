"""Optional integration checks in a NEW IDA process on a disposable fixture.

Uses a private IDAUSR and never installs into, attaches to, or closes the user's
existing IDA sessions. Run with --ida pointing to IDA Pro 9.2 ida.exe.
"""
import argparse
import json
import os
from pathlib import Path
import queue
import re
import shutil
import subprocess
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def decode_tool_text(text):
    """Decode compact JSON or the model-facing structured text rendering."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    lines = text.splitlines()
    if not lines:
        raise ValueError('empty tool result')

    def scalar(value):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value

    def block(index, indent):
        while index < len(lines) and not lines[index].strip():
            index += 1
        if index >= len(lines):
            return {}, index
        prefix = ' ' * indent
        if not lines[index].startswith(prefix):
            return {}, index
        body = lines[index][indent:]

        if body == '-':
            values = []
            while index < len(lines) and lines[index] == prefix + '-':
                value, index = block(index + 1, indent + 2)
                values.append(value)
                while index < len(lines) and not lines[index].strip():
                    index += 1
            return values, index

        result = {}
        while index < len(lines):
            line = lines[index]
            if not line.strip():
                index += 1
                continue
            current_indent = len(line) - len(line.lstrip(' '))
            if current_indent != indent:
                break
            body = line[indent:]
            match = re.match(r'("(?:[^"\\]|\\.)*")(?:\[(\d+)\])?:(.*)$', body)
            if not match:
                break
            key = json.loads(match.group(1))
            table_count = match.group(2)
            remainder = match.group(3).lstrip()
            index += 1

            if table_count is not None:
                if index >= len(lines):
                    raise ValueError(f'missing table header for {key!r}')
                headers = [json.loads(cell) for cell in lines[index].strip().split('\t')]
                index += 1
                rows = []
                while index < len(lines) and len(lines[index]) - len(lines[index].lstrip(' ')) == indent + 2:
                    cells = lines[index][indent + 2:].split('\t')
                    if len(cells) != len(headers):
                        raise ValueError(f'malformed table row: {lines[index]!r}')
                    rows.append({name: scalar(value) for name, value in zip(headers, cells)})
                    index += 1
                if len(rows) != int(table_count):
                    raise ValueError(f'table row count {len(rows)} != declared {table_count}')
                result[key] = rows
            elif remainder == '|':
                chunks = []
                while index < len(lines) and len(lines[index]) >= indent + 2 and lines[index][:indent + 2] == prefix + '  ':
                    chunks.append(lines[index][indent + 2:])
                    index += 1
                result[key] = '\n'.join(chunks)
            elif remainder:
                result[key] = scalar(remainder)
            elif index < len(lines) and len(lines[index]) - len(lines[index].lstrip(' ')) > indent:
                result[key], index = block(index, indent + 2)
            else:
                result[key] = {}
        return result, index

    parsed, _ = block(0, 0)
    if not parsed:
        raise ValueError(f'unrecognized model output: {text[:200]!r}')
    return parsed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ida', required=True, type=Path)
    args = parser.parse_args()
    directory = ROOT / 'bin' / f'native-qa-{os.getpid()}-{uuid.uuid4().hex[:8]}'
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

    def call(name=None, arguments=None, method='tools/call', wait=15, params=None):
        nonlocal counter
        counter += 1
        request_id = counter
        request = {'jsonrpc': '2.0', 'id': request_id, 'method': method, '_cancel_token': f'qa-{request_id}'}
        if params is not None:
            request['params'] = params
        elif name is not None:
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
        emulate_tool = next(tool for tool in catalog if tool['name'] == 'emulate_function')
        assert 'call_stubs' in emulate_tool['inputSchema']['properties'], 'Loaded plugin is not the new emulation build'
        successful('py', {'code': '''import idc
assert idc.SetType(idc.get_name_ea(idc.BADADDR, 'mcp_fixture_add'), 'int mcp_fixture_add(int a, int b);')
assert idc.SetType(idc.get_name_ea(idc.BADADDR, 'mcp_fixture_double'), 'double mcp_fixture_double(double value);')'''} )
        emulated_add = decode_tool_text(successful('emulate_function', {
            'addr': 'mcp_fixture_add', 'arguments': [19, 23]
        }))
        assert emulated_add['returned'] and int(emulated_add['return_value'], 0) == 42, emulated_add
        emulated_named_add = decode_tool_text(successful('emulate_function', {
            'addr': 'mcp_fixture_add', 'arguments': {'a': 20, 'b': 22}
        }))
        assert emulated_named_add['returned'] and int(emulated_named_add['return_value'], 0) == 42, emulated_named_add
        emulated_double = decode_tool_text(successful('emulate_function', {
            'addr': 'mcp_fixture_double', 'arguments': {'value': 21.5}
        }))
        assert emulated_double['returned'] and emulated_double['floating_return']['value'] == 43.0, emulated_double
        emulated_buffer = decode_tool_text(successful('emulate_function', {
            'addr': 'mcp_fixture_mutate_buffer', 'arguments': [{'bytes': '41'}, 1]
        }))
        assert emulated_buffer['returned'] and int(emulated_buffer['return_value'], 0) == 66, emulated_buffer
        assert emulated_buffer['buffers'][0]['bytes'] == '42', emulated_buffer
        emulated_global = decode_tool_text(successful('emulate_function', {
            'addr': 'mcp_fixture_set_global', 'arguments': [99]
        }))
        assert emulated_global['returned'] and emulated_global['memory_writes'], emulated_global
        unchanged_global = decode_tool_text(successful('get_bytes', {'addr': 'mcp_fixture_global', 'size': 4}))
        assert unchanged_global['hex'].lower().split() == ['07', '00', '00', '00'], unchanged_global
        emulated_stub = decode_tool_text(successful('emulate_function', {
            'addr': 'mcp_fixture_stub_caller', 'arguments': [4],
            'call_stubs': [{'addr': 'mcp_fixture_stub_target', 'return': 40}]
        }))
        assert emulated_stub['returned'] and int(emulated_stub['return_value'], 0) == 41, emulated_stub
        assert emulated_stub['modeled_calls'][0]['calls'] == 1, emulated_stub
        emulated_limited = decode_tool_text(successful('emulate_function', {
            'addr': 'mcp_fixture_loop', 'arguments': [1000, 1], 'max_instructions': 10
        }))
        assert not emulated_limited['returned'] and emulated_limited['outcome'] == 'instruction_limit', emulated_limited
        malformed_initialize = call(method='initialize', params='bad')
        assert malformed_initialize['error']['code'] == -32602, malformed_initialize
        malformed_protocol = call(method='initialize', params={'protocolVersion': []})
        assert malformed_protocol['error']['code'] == -32602, malformed_protocol
        decompiler = next(tool for tool in catalog if tool['name'] == 'decompile')
        assert 'include_lvars' in decompiler['inputSchema']['properties'], 'Loaded plugin is not the new build'
        successful('survey_binary')
        segment_list = decode_tool_text(successful('get_segments'))['segments']
        loaded_ends = decode_tool_text(successful('py', {'code': '''import ida_bytes, ida_segment, idautils
[ida_segment.getseg(ea).end_ea for ea in idautils.Segments()
 if ida_bytes.is_loaded(ida_segment.getseg(ea).end_ea - 1)]'''}))['result']
        assert loaded_ends, segment_list
        tail_addr = loaded_ends[-1] - 1
        tail_bytes = decode_tool_text(successful('get_bytes', {'addr': hex(tail_addr), 'size': 8}))
        assert tail_bytes['size_read'] == 1 and len(tail_bytes['hex'].split()) == 1, tail_bytes
        assert call('get_bytes', {'addr': 'mcp_fixture_add', 'size': 0})['result']['isError']
        successful('get_exports')
        successful('types', {'c_code': 'struct MCPFixture { int a; }; struct MCPPageA { int a; }; struct MCPPageB { int b; }; struct MCPPageC { int c; };'})
        typed_read = decode_tool_text(successful('types', {'addr': 'mcp_fixture_add', 'name': 'MCPFixture'}))
        assert typed_read['struct'] == 'MCPFixture' and typed_read['fields'][0]['name'] == 'a', typed_read
        type_page_1 = decode_tool_text(successful('types', {'pattern': 'MCPPage*', 'count': 1}))
        assert len(type_page_1['types']) == 1 and type_page_1['next_cursor'] == '1', type_page_1
        type_page_2 = decode_tool_text(successful('types', {
            'pattern': 'MCPPage*', 'count': 1, 'cursor': type_page_1['next_cursor']
        }))
        assert len(type_page_2['types']) == 1 and type_page_2['types'][0]['name'] != type_page_1['types'][0]['name'], type_page_2
        limited_ast_matches = decode_tool_text(successful('get_ast', {
            'addr': 'mcp_fixture_update', 'pattern': {'op': 'cot_asg'}, 'max_matches': 1
        }))
        assert len(limited_ast_matches['matches']) <= 1, limited_ast_matches
        if len(limited_ast_matches['matches']) == 1:
            assert limited_ast_matches.get('truncated') is True, limited_ast_matches
        binary_limited_ast = decode_tool_text(successful('get_ast', {
            'func_pattern': 'mcp_fixture_*', 'pattern': {'op': 'cot_asg'}, 'limit': 10, 'max_matches': 1
        }))
        assert len(binary_limited_ast['matches']) <= 1, binary_limited_ast
        if len(binary_limited_ast['matches']) == 1:
            assert binary_limited_ast.get('truncated') is True, binary_limited_ast
        empty_call_args = decode_tool_text(successful('get_ast', {
            'addr': 'mcp_fixture_call', 'pattern': {'op': 'cot_call', 'args': []}
        }))
        assert empty_call_args['matches'] == [], empty_call_args
        for name, arguments in [
            ('list_funcs', {'min_size': -1}),
            ('list_funcs', {'min_size': 16, 'max_size': 8}),
            ('list_funcs', {'cursor': 'not-an-address'}),
            ('list_globals', {'cursor': 'not-an-address'}),
            ('xref_query', {'addr': 'mcp_fixture_add', 'direction': 'sideways'}),
            ('xref_query', {'addr': 'mcp_fixture_add', 'type': 'mystery'}),
            ('xref_query', {'addr': 'mcp_fixture_add', 'cursor': '1junk'}),
            ('callgraph', {'addr': 'mcp_fixture_add', 'direction': 'sideways'}),
            ('trace_data_flow', {'addr': 'mcp_fixture_add', 'direction': 'sideways'}),
            ('emulate_function', {'addr': '__missing_fixture_function__'}),
            ('emulate_function', {'addr': 'mcp_fixture_add', 'timeout_ms': 1800001}),
            ('emulate_function', {'addr': 'mcp_fixture_add', 'arguments': [1, 2, 3]}),
            ('get_ast', {'pattern': {'op': 'cot_call'}, 'addr': '__missing_fixture_function__'}),
            ('get_ast', {'pattern': {'op': 'cot_call'}}),
            ('mba_simplify', {'addr': 'mcp_fixture_add', 'expr_addr': 'not-an-address'}),
            ('imports_query', {'addr': 'not-an-address'}),
            ('get_exports', {'addr': 'not-an-address'}),
            ('get_segments', {'addr': 'not-an-address'}),
            ('strings', {'cursor': 'not-an-address'}),
            ('strings', {'pattern': '*', 'type': 'invalid-encoding'}),
            ('types', {'pattern': '*', 'kind': 'mystery'}),
            ('types', {'pattern': '*', 'cursor': '1junk'}),
            ('types', {'addr': 'mcp_fixture_add'}),
            ('decompile', {'addrs': []}),
            ('decompile', {'addr': 123}),
            ('disasm', {'addr': 'mcp_fixture_add', 'count': -1}),
            ('disasm', {'addr': 'mcp_fixture_add', 'count': 1001}),
            ('disasm', {'targets': ['mcp_fixture_add'], 'count': 101}),
        ]:
            invalid_core = call(name, arguments)
            assert invalid_core['result']['isError'], (name, arguments, invalid_core)
        byte_result = decode_tool_text(successful('get_bytes', {'addr': 'mcp_fixture_add', 'size': 8}))
        skipped_predicate = decode_tool_text(successful('simplify_predicate', {
            'addr': 'mcp_fixture_add',
            'predicate_addr': byte_result['address'],
            'force_branch': 'always_true',
            'persist': False
        }))
        assert skipped_predicate['modifications'][0]['status'] == 'skipped'
        assert skipped_predicate['modifications'][0]['reason'] == 'predicate_not_found_in_function', skipped_predicate
        malformed_address = call('get_bytes', {'addr': byte_result['address'] + 'junk', 'size': 8})
        assert malformed_address['result']['isError'], ('address parser accepted trailing junk', malformed_address)
        invalid_signature_range = call('make_signature', {'start': '0x1', 'end': '0x2'})
        assert invalid_signature_range['result']['isError'], invalid_signature_range
        assert call('make_signature', {'addr': 'mcp_fixture_add', 'start': '0x1', 'end': '0x2'})['result']['isError']
        assert call('make_signature', {'start': 'mcp_fixture_add'})['result']['isError']
        segments = decode_tool_text(successful('get_segments', {}))['segments']
        data_segment = next((segment for segment in segments if 'rdata' in segment['name'].lower()), None)
        if data_segment:
            fallback_flow = decode_tool_text(successful('trace_data_flow', {
                'addr': data_segment['start'], 'depth': 1
            }))
            assert fallback_flow['flow_count'] >= 1 and fallback_flow['flow'][0]['address'] == data_segment['start'], fallback_flow
        backward_data_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': 'mcp_fixture_global', 'direction': 'backward', 'depth': 1
        }))
        assert any(
            item.get('edge', {}).get('via') == 'data_xref'
            and item.get('edge', {}).get('to') == backward_data_flow['root']['address']
            for item in backward_data_flow['flow']
        ), backward_data_flow
        forward_pointer_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': 'mcp_fixture_global_ptr', 'direction': 'forward', 'depth': 1
        }))
        assert any(
            item.get('edge', {}).get('via') == 'data_xref'
            and item.get('edge', {}).get('from') == forward_pointer_flow['root']['address']
            for item in forward_pointer_flow['flow']
        ), forward_pointer_flow
        xrefs_to = decode_tool_text(successful('xref_query', {
            'addr': 'mcp_fixture_global_ptr', 'direction': 'to'
        }))
        xrefs_from = decode_tool_text(successful('xref_query', {
            'addr': 'mcp_fixture_global_ptr', 'direction': 'from'
        }))
        xrefs_both = decode_tool_text(successful('xref_query', {
            'addr': 'mcp_fixture_global_ptr', 'direction': 'both'
        }))
        assert any(item.get('function', '').startswith('mcp_fixture_read_pointer') for item in xrefs_to['xrefs']), xrefs_to
        assert any(item.get('to_name') == 'mcp_fixture_global' for item in xrefs_from['xrefs']), xrefs_from
        assert {item['direction'] for item in xrefs_both['xrefs']} == {'to', 'from'}, xrefs_both
        forward_variable_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': 'mcp_fixture_add', 'var': 'arg0', 'direction': 'forward', 'depth': 1
        }))
        assert any(item.get('type') == 'return' for item in forward_variable_flow['flow']), forward_variable_flow
        overwritten_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': 'mcp_fixture_overwrite_0', 'var': 'arg0', 'direction': 'forward', 'depth': 1
        }))
        assert not any(item.get('type') == 'return' for item in overwritten_flow['flow']), overwritten_flow
        compound_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': 'mcp_fixture_accumulate_0', 'var': 'arg0', 'direction': 'forward', 'depth': 1
        }))
        assert any(item.get('type') == 'return' for item in compound_flow['flow']), compound_flow
        xor_compound_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': 'mcp_fixture_xor_accumulate_0', 'var': 'arg0', 'direction': 'forward', 'depth': 1
        }))
        assert any(item.get('type') == 'return' for item in xor_compound_flow['flow']), xor_compound_flow
        one_byte_signature = call('make_signature', {'addr': 'mcp_fixture_add', 'max_length': 1})
        if not one_byte_signature['result'].get('isError', False):
            signature_data = json.loads(text(one_byte_signature))
            assert signature_data['length'] <= 1, signature_data
        decompiled = successful('decompile', {'addr': 'mcp_fixture_add'})
        assert 'return' in decompiled and 'lvars' not in decompiled, decompiled
        decompiled_with_lvars = decode_tool_text(successful('decompile', {
            'addr': 'mcp_fixture_add', 'include_lvars': True
        }))
        assert decompiled_with_lvars['lvars'] and all('index' in item for item in decompiled_with_lvars['lvars']), decompiled_with_lvars
        semantic_function = decode_tool_text(successful('analyze_function', {
            'addr': 'mcp_fixture_add_0', 'semantic_summary': True
        }))
        semantic_summary = semantic_function['semantic_summary']
        assert semantic_summary['engine'] == 'RAX' and semantic_summary['architecture'] == 'x86-64', semantic_summary
        assert semantic_summary['instructions_analyzed'] > 0, semantic_summary
        assert semantic_summary['instructions_complete'] > 0, semantic_summary
        assert semantic_summary['registers_read'] and semantic_summary['registers_written'], semantic_summary
        assert semantic_summary['control_flow'], semantic_summary
        machine_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': 'mcp_fixture_add_0', 'var': 'rcx', 'direction': 'forward',
            'machine_level': True
        }))
        assert machine_flow['analysis']['engine'] == 'RAX', machine_flow
        assert machine_flow['analysis']['scope'].startswith('intraprocedural CFG'), machine_flow
        assert machine_flow['root']['var'] == 'rcx', machine_flow
        assert any(item.get('type') == 'register_use' for item in machine_flow['flow']), machine_flow
        backward_machine_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': 'mcp_fixture_add_0', 'var': 'rax', 'direction': 'backward',
            'machine_level': True
        }))
        assert any(item.get('type') == 'register_definition' for item in backward_machine_flow['flow']), backward_machine_flow
        assert backward_machine_flow['analysis']['instructions_complete'] > 0, backward_machine_flow
        branch_machine_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': 'mcp_fixture_update_0', 'var': 'rcx', 'direction': 'forward',
            'machine_level': True
        }))
        assert branch_machine_flow['analysis']['basic_blocks'] > 1, branch_machine_flow
        assert branch_machine_flow['analysis']['worklist_steps'] > 1, branch_machine_flow
        assert any(item.get('depth', 0) > 0 for item in branch_machine_flow['flow']), branch_machine_flow
        assert branch_machine_flow['analysis']['scope'].endswith('merged conservatively'), branch_machine_flow
        partial_register_disasm = decode_tool_text(successful('disasm', {
            'addr': 'mcp_fixture_partial_register', 'count': 16, 'detailed': True
        }))
        partial_consumer = next(
            item for item in partial_register_disasm['items']
            if 'mov rbx, rax' in ' '.join(item.get('disasm', '').lower().split())
        )
        partial_write = next(
            item for item in partial_register_disasm['items']
            if 'mov al, 1' in ' '.join(item.get('disasm', '').lower().split())
        )
        partial_register_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': partial_write['address'], 'var': 'rax', 'direction': 'forward',
            'machine_level': True
        }))
        assert any(item.get('address') == partial_consumer['address'] for item in partial_register_flow['flow']), (partial_register_flow, partial_register_disasm)
        zero_extend_disasm = decode_tool_text(successful('disasm', {
            'addr': 'mcp_fixture_zero_extend', 'count': 16, 'detailed': True
        }))
        zero_extend_consumer = next(
            item for item in zero_extend_disasm['items']
            if 'mov rbx, rax' in ' '.join(item.get('disasm', '').lower().split())
        )
        zero_extend_write = next(
            item for item in zero_extend_disasm['items']
            if 'mov eax, 1' in ' '.join(item.get('disasm', '').lower().split())
        )
        zero_extend_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': zero_extend_write['address'], 'var': 'rax', 'direction': 'forward',
            'machine_level': True
        }))
        assert not any(item.get('address') == zero_extend_consumer['address'] for item in zero_extend_flow['flow']), zero_extend_flow
        backward_partial_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': partial_consumer['address'], 'var': 'rbx', 'direction': 'backward',
            'machine_level': True
        }))
        assert any(item.get('address') == partial_write['address'] for item in backward_partial_flow['flow']), backward_partial_flow
        backward_zero_extend_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': zero_extend_consumer['address'], 'var': 'rbx', 'direction': 'backward',
            'machine_level': True
        }))
        assert not any(item.get('address') == zero_extend_disasm['items'][0]['address']
            for item in backward_zero_extend_flow['flow']), backward_zero_extend_flow
        high_byte_disasm = decode_tool_text(successful('disasm', {
            'addr': 'mcp_fixture_high_byte_register', 'count': 16, 'semantic_effects': True
        }))
        high_byte_write = next(item for item in high_byte_disasm['items']
            if 'mov ah, 1' in ' '.join(item.get('disasm', '').lower().split()))
        high_byte_consumer = next(item for item in high_byte_disasm['items']
            if 'mov rbx, rax' in ' '.join(item.get('disasm', '').lower().split()))
        low_byte_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': high_byte_write['address'], 'var': 'al', 'direction': 'forward',
            'machine_level': True
        }))
        high_byte_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': high_byte_write['address'], 'var': 'ah', 'direction': 'forward',
            'machine_level': True
        }))
        assert any(item.get('address') == high_byte_consumer['address'] for item in low_byte_flow['flow']), low_byte_flow
        assert not any(item.get('address') == high_byte_consumer['address'] for item in high_byte_flow['flow']), (high_byte_flow, high_byte_disasm)
        flag_disasm = decode_tool_text(successful('disasm', {
            'addr': 'mcp_fixture_flag_slice', 'count': 16, 'semantic_effects': True
        }))
        flag_branch = next(item for item in flag_disasm['items'] if item.get('semantics', {}).get('control_flow') == 'conditional_branch')
        zero_flag_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': flag_branch['address'], 'var': 'zf', 'direction': 'forward',
            'machine_level': True
        }))
        carry_flag_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': flag_branch['address'], 'var': 'cf', 'direction': 'forward',
            'machine_level': True
        }))
        assert any(item.get('address') == flag_branch['address'] and item.get('type') == 'register_use'
            for item in zero_flag_flow['flow']), zero_flag_flow
        assert zero_flag_flow['root']['var'] == 'zf', zero_flag_flow
        assert not any(item.get('address') == flag_branch['address'] and item.get('type') == 'register_use'
            for item in carry_flag_flow['flow']), carry_flag_flow
        loop_disasm = decode_tool_text(successful('disasm', {
            'addr': 'mcp_fixture_loop', 'count': 128, 'semantic_effects': True
        }))
        if len(loop_disasm['items']) == 1 and loop_disasm['items'][0].get('semantics', {}).get('target'):
            loop_disasm = decode_tool_text(successful('disasm', {
                'addr': loop_disasm['items'][0]['semantics']['target'], 'count': 128,
                'semantic_effects': True
            }))
        loop_items = loop_disasm['items']
        loop_back_edge = next(
            (item for item in loop_items
             if item.get('semantics', {}).get('control_flow') in ('branch', 'conditional_branch')
             and item.get('semantics', {}).get('target')
             and int(item['semantics']['target'], 16) < int(item['address'], 16)),
            None
        )
        assert loop_back_edge is not None, loop_disasm
        loop_target = next(item for item in loop_items if item['address'] == loop_back_edge['semantics']['target'])
        loop_target_index = loop_items.index(loop_target)
        assert loop_target_index + 1 < len(loop_items), loop_disasm
        loop_root = loop_items[loop_target_index + 1]
        loop_target_registers = set()
        for effect in loop_target.get('semantics', {}).get('effects', []):
            if effect.get('kind') == 'register' and 'read' in effect.get('access', []):
                loop_target_registers.add(effect.get('register', '').lower())
            if effect.get('kind') == 'memory' and 'read' in effect.get('access', []):
                address = effect.get('address', {})
                loop_target_registers.update(address.get(key, '').lower() for key in ('base', 'index'))
        loop_target_registers.discard('')
        assert loop_target_registers, loop_target
        loop_register = next(iter(sorted(loop_target_registers)))
        loop_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': loop_root['address'], 'var': loop_register, 'direction': 'forward',
            'machine_level': True
        }))
        assert any(item.get('address') == loop_target['address'] for item in loop_flow['flow']), loop_flow
        stack_disasm = decode_tool_text(successful('disasm', {
            'addr': 'mcp_fixture_stack_alias', 'count': 32, 'detailed': True
        }))
        stack_store = next((item for item in stack_disasm['items']
            if 'rbp' in item.get('disasm', '').lower() and 'rcx' in item.get('disasm', '').lower()
            and item.get('semantics') is None), None)
        stack_load = next((item for item in stack_disasm['items']
            if 'rbp' in item.get('disasm', '').lower() and 'eax' in item.get('disasm', '').lower()
            and 'rcx' not in item.get('disasm', '').lower()), None)
        assert stack_store is not None and stack_load is not None, stack_disasm
        stack_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': stack_store['address'], 'var': 'rcx', 'direction': 'forward',
            'machine_level': True
        }))
        stack_load_node = next((item for item in stack_flow['flow'] if item.get('address') == stack_load['address']), None)
        assert stack_load_node is not None and stack_load_node.get('memory_dependency') is True, (stack_flow, stack_disasm)
        assert stack_flow['analysis']['memory_aliases_tracked'] is True, stack_flow
        assert stack_flow['analysis']['memory_accesses_tracked'] >= 2, stack_flow
        backward_stack_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': stack_load['address'], 'var': 'rax', 'direction': 'backward',
            'machine_level': True
        }))
        backward_store_node = next((item for item in backward_stack_flow['flow'] if item.get('address') == stack_store['address']), None)
        assert backward_store_node is not None and backward_store_node.get('memory_dependency') is True, backward_stack_flow
        rsp_disasm = decode_tool_text(successful('disasm', {
            'addr': 'mcp_fixture_rsp_alias', 'count': 16, 'detailed': True
        }))
        rsp_store = next(item for item in rsp_disasm['items']
            if 'rsp' in item.get('disasm', '').lower() and 'rcx' in item.get('disasm', '').lower())
        rsp_load = next(item for item in rsp_disasm['items']
            if 'rsp' in item.get('disasm', '').lower() and 'eax' in item.get('disasm', '').lower())
        rsp_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': rsp_store['address'], 'var': 'rcx', 'direction': 'forward',
            'machine_level': True
        }))
        rsp_load_node = next((item for item in rsp_flow['flow'] if item.get('address') == rsp_load['address']), None)
        assert rsp_load_node is not None and rsp_load_node.get('memory_dependency') is True, rsp_flow
        assert rsp_flow['analysis']['memory_aliases_tracked'] is True, rsp_flow
        partial_memory_disasm = decode_tool_text(successful('disasm', {
            'addr': 'mcp_fixture_stack_partial_overwrite', 'count': 24, 'semantic_effects': True
        }))
        partial_memory_store = next(item for item in partial_memory_disasm['items']
            if any(effect.get('kind') == 'memory' and effect.get('width_bits') == 64
                and effect.get('access') and 'write' in effect['access']
                and effect.get('source_register') == 'rcx'
                for effect in item.get('semantics', {}).get('effects', [])))
        partial_memory_load = next(item for item in partial_memory_disasm['items']
            if any(effect.get('kind') == 'memory' and effect.get('width_bits') == 64
                and effect.get('access') and 'read' in effect['access']
                for effect in item.get('semantics', {}).get('effects', [])))
        partial_memory_forward = decode_tool_text(successful('trace_data_flow', {
            'addr': partial_memory_store['address'], 'var': 'rcx', 'direction': 'forward',
            'machine_level': True
        }))
        assert any(item.get('address') == partial_memory_load['address'] and item.get('memory_dependency')
            for item in partial_memory_forward['flow']), partial_memory_forward
        partial_memory_backward = decode_tool_text(successful('trace_data_flow', {
            'addr': partial_memory_load['address'], 'var': 'rax', 'direction': 'backward',
            'machine_level': True
        }))
        assert any(item.get('address') == partial_memory_store['address'] and item.get('memory_dependency')
            for item in partial_memory_backward['flow']), partial_memory_backward
        global_disasm = decode_tool_text(successful('disasm', {
            'addr': 'mcp_fixture_global_alias', 'count': 12, 'semantic_effects': True
        }))
        global_store = next((item for item in global_disasm['items']
            if any(effect.get('kind') == 'memory' and 'write' in effect.get('access', [])
                and effect.get('source_register') in ('ecx', 'rcx')
                for effect in item.get('semantics', {}).get('effects', []))), None)
        assert global_store is not None, global_disasm
        global_load = next((item for item in global_disasm['items']
            if any(effect.get('kind') == 'memory' and 'read' in effect.get('access', [])
                for effect in item.get('semantics', {}).get('effects', []))), None)
        assert global_load is not None, global_disasm
        global_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': global_store['address'], 'var': 'rcx', 'direction': 'forward',
            'machine_level': True
        }))
        assert any(item.get('address') == global_load['address'] and item.get('memory_dependency')
            for item in global_flow['flow']), global_flow
        assert global_flow['analysis']['memory_aliases_tracked'] is True, global_flow
        preserved_call_disasm = decode_tool_text(successful('disasm', {
            'addr': 'mcp_fixture_call_preserved', 'count': 16, 'semantic_effects': True
        }))
        preserved_root = preserved_call_disasm['items'][0]
        preserved_consumer = next(item for item in preserved_call_disasm['items']
            if 'rbx' in item.get('disasm', '').lower() and 'rax' in item.get('disasm', '').lower())
        preserved_call_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': preserved_root['address'], 'var': 'rcx', 'direction': 'forward',
            'machine_level': True
        }))
        assert any(item.get('address') == preserved_consumer['address'] for item in preserved_call_flow['flow']), preserved_call_flow
        assert any(item.get('type') == 'call_boundary' for item in preserved_call_flow['flow']), preserved_call_flow
        assert preserved_call_flow['analysis']['dataflow_complete'] is False, preserved_call_flow
        assert any('volatile registers' in reason for reason in preserved_call_flow['analysis']['incomplete_reasons']), preserved_call_flow
        preserved_call_instruction = next(item for item in preserved_call_disasm['items']
            if item.get('semantics', {}).get('control_flow') == 'call')
        preserved_direct_call_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': preserved_call_instruction['address'], 'var': 'rbx', 'direction': 'forward',
            'machine_level': True
        }))
        assert any(item.get('address') == preserved_consumer['address'] for item in preserved_direct_call_flow['flow']), preserved_direct_call_flow
        assert preserved_direct_call_flow['analysis']['dataflow_complete'] is True, preserved_direct_call_flow
        volatile_direct_call_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': preserved_call_instruction['address'], 'var': 'rax', 'direction': 'forward',
            'machine_level': True
        }))
        assert not any(item.get('address') == preserved_consumer['address'] for item in volatile_direct_call_flow['flow']), volatile_direct_call_flow
        assert any('volatile registers' in reason for reason in volatile_direct_call_flow['analysis']['incomplete_reasons']), volatile_direct_call_flow
        volatile_call_disasm = decode_tool_text(successful('disasm', {
            'addr': 'mcp_fixture_call_volatile', 'count': 16, 'detailed': True
        }))
        volatile_root = volatile_call_disasm['items'][0]
        volatile_consumer = next(item for item in volatile_call_disasm['items']
            if 'rbx' in item.get('disasm', '').lower() and 'rax' in item.get('disasm', '').lower())
        volatile_call_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': volatile_root['address'], 'var': 'rcx', 'direction': 'forward',
            'machine_level': True
        }))
        assert not any(item.get('address') == volatile_consumer['address'] for item in volatile_call_flow['flow']), volatile_call_flow
        assert any('volatile registers' in reason for reason in volatile_call_flow['analysis']['incomplete_reasons']), volatile_call_flow
        assert call('trace_data_flow', {
            'addr': 'mcp_fixture_add_0', 'var': 'not_a_register', 'machine_level': True
        })['result']['isError']
        decompile_batch = decode_tool_text(successful('decompile', {
            'addrs': ['mcp_fixture_add', '__missing_fixture_function__']
        }))
        assert len(decompile_batch['functions']) == 2 and 'code' in decompile_batch['functions'][0]
        assert decompile_batch['functions'][1]['error_code'] == 'function_not_found', decompile_batch
        detailed_disasm = decode_tool_text(successful('disasm', {
            'addr': 'mcp_fixture_add', 'count': 2, 'bytes': True, 'detailed': True
        }))
        assert detailed_disasm['items'] and 'bytes' in detailed_disasm['items'][0], detailed_disasm
        rax_disasm = decode_tool_text(successful('disasm', {
            'addr': 'mcp_fixture_add_0', 'semantic_effects': True
        }))
        assert rax_disasm['items'] and all('semantics' in item for item in rax_disasm['items']), rax_disasm
        assert any(item['semantics'].get('status') == 'complete' for item in rax_disasm['items']), rax_disasm
        assert any(
            effect.get('kind') == 'register' and 'write' in effect.get('access', [])
            for item in rax_disasm['items']
            for effect in item['semantics'].get('effects', [])
        ), rax_disasm
        rax_instruction_query = decode_tool_text(successful('insn_query', {
            'func': 'mcp_fixture_add_0', 'count': 10, 'semantic_effects': True
        }))
        assert rax_instruction_query['instructions'] and all(
            'semantics' in item for item in rax_instruction_query['instructions']
        ), rax_instruction_query
        assert call('insn_query', {
            'func': 'mcp_fixture_add_0', 'count': 101, 'semantic_effects': True
        })['result']['isError']
        assert call('disasm', {'targets': ['mcp_fixture_add'], 'semantic_effects': True})['result']['isError']
        batch_disasm = decode_tool_text(successful('disasm', {
            'targets': ['__missing_fixture_function__', 'mcp_fixture_add'], 'count': 1
        }))
        assert batch_disasm['results'][0]['error_code'] == 'invalid_addr'
        assert batch_disasm['results'][1]['instructions'], batch_disasm
        assert decode_tool_text(successful('py', {'code': '6 * 7'})) == {'result': 42}
        script_path = directory / 'qa_script.py'
        script_path.write_text("import sys\nprint(sys.argv[1:])\n40 + 2", encoding='utf-8')
        script_result = decode_tool_text(successful('py', {'file': str(script_path), 'argv': ['qa-arg']}))
        assert script_result['result'] == 42 and 'qa-arg' in script_result['stdout'], script_result
        bounded_result = decode_tool_text(successful('py', {'code': "'x' * 10000000"}))
        assert len(bounded_result['result']) <= 90000 and bounded_result['output_truncated'], bounded_result
        assert call('py', {'code': '1', 'file': str(script_path)})['result']['isError']
        failed = call('py', {'code': "print('before-error')\nraise ValueError('native-test')"})
        assert failed['result']['isError'] and 'before-error' in text(failed), failed
        assert decode_tool_text(successful('py', {'code': '1 + 1'})) == {'result': 2}
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
        assert decode_tool_text(successful('py', {'code': '40 + 2'})) == {'result': 42}
        bounded_ast = decode_tool_text(successful('get_ast', {
            'pattern': {'op': 'cot_call'}, 'func_pattern': '__no_such_fixture_function__', 'limit': 1
        }))
        assert bounded_ast['functions_scanned'] == 1 and bounded_ast.get('truncated') is True, bounded_ast
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
            ('types', {'name': 'MCPFixture'}),
            ('rtti', {'pattern': '__no_fixture_class__', 'count': 1}),
            ('get_ast', {'addr': 'mcp_fixture_add', 'max_depth': 16}),
            ('mba_simplify', {'addr': 'mcp_fixture_add'}),
            ('simplify_predicate', {'addr': 'mcp_fixture_add', 'auto_detect': True, 'persist': False}),
            ('find_path', {'from': 'mcp_fixture_add', 'to': 'mcp_fixture_add', 'max_depth': 2}),
            ('trace_data_flow', {'addr': 'mcp_fixture_add', 'depth': 1}),
            ('make_signature', {'addr': 'mcp_fixture_add', 'max_length': 32}),
            ('stack_frame', {'addr': 'mcp_fixture_call', 'include_lvars': True}),
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
        reconstructed = decode_tool_text(successful('reconstruct_struct', {
            'addr': 'mcp_fixture_update', 'scan_depth': 1
        }))
        assert reconstructed['function'] == 'mcp_fixture_update' and isinstance(reconstructed['fields'], list), reconstructed
        missing_struct_var = call('reconstruct_struct', {
            'addr': 'mcp_fixture_update', 'var': '__missing_fixture_var__'
        })
        assert missing_struct_var['result'].get('isError') is True, missing_struct_var
        invalid_struct_name = call('reconstruct_struct', {
            'addr': 'mcp_fixture_update', 'struct_name': 'Injected; int other'
        })
        assert invalid_struct_name['result'].get('isError') is True, invalid_struct_name
        keyword_struct_name = call('reconstruct_struct', {
            'addr': 'mcp_fixture_update', 'struct_name': 'int'
        })
        assert keyword_struct_name['result'].get('isError') is True, keyword_struct_name
        too_deep_pattern = '$_'
        for _ in range(34):
            too_deep_pattern = {'op': 'cot_add', 'x': too_deep_pattern}
        custom_match = decode_tool_text(successful('mba_simplify', {
            'addr': 'mcp_fixture_update',
            'custom_rules': [{'name': 'qa_add', 'pattern': {'op': '$_'}, 'simplified': 'custom-add'}]
        }))
        assert isinstance(custom_match.get('matches'), list), custom_match
        for malformed_rule in [
            {'name': 'missing-pattern'},
            {'pattern': {'op': 7}},
            {'pattern': {'x': {'unknown_field': True}}},
            {'pattern': too_deep_pattern},
        ]:
            invalid_rule = call('mba_simplify', {'addr': 'mcp_fixture_add', 'custom_rules': [malformed_rule]})
            assert invalid_rule['result'].get('isError') is True, invalid_rule
            assert 'custom_rule' in text(invalid_rule) or 'custom_pattern' in text(invalid_rule), invalid_rule
        for malformed_ast_pattern in [
            {'var_name': False},
            {'member_offset': -1},
            {'args': [1]},
            {'unknown_field': True},
        ]:
            invalid_pattern = call('get_ast', {'addr': 'mcp_fixture_add', 'pattern': malformed_ast_pattern})
            assert invalid_pattern['result'].get('isError') is True, invalid_pattern
        batch_types = decode_tool_text(successful('types', {'names': ['MCPFixture', '__missing_qa_type__']}))
        assert len(batch_types['types']) == 2 and batch_types['types'][0]['name'] == 'MCPFixture', batch_types
        assert batch_types['types'][1]['status'] == 'error', batch_types
        assert 'content' not in batch_types['types'][0], batch_types
        bounded_analysis = decode_tool_text(successful('analyze_function', {
            'addr': 'mcp_fixture_update', 'max_callers': 0, 'max_callees': 0
        }))
        assert bounded_analysis['callers'] == [] and bounded_analysis['callees'] == [], bounded_analysis
        if bounded_analysis['unique_callers'] > 0:
            assert bounded_analysis.get('callers_truncated') is True, bounded_analysis
        if bounded_analysis['callees_count'] > 0:
            assert bounded_analysis.get('callees_truncated') is True, bounded_analysis
        for name, arguments in [
            ('trace_data_flow', {'addr': 'mcp_fixture_update', 'var': 'arg0', 'depth': 2}),
            ('reconstruct_struct', {'addr': 'mcp_fixture_update', 'scan_depth': 1}),
            ('rtti', {'pattern': '*MCPFixture*', 'count': 10}),
            ('rtti', {'name': 'MCPFixtureDerived'}),
            ('resolve_vcall', {'class': 'MCPFixtureDerived', 'index': 0}),
            ('basic_blocks', {'addr': 'mcp_fixture_update', 'include_instructions': True}),
            ('callgraph', {'addr': 'mcp_fixture_call', 'depth': 2, 'max_nodes': 10}),
            ('get_ast', {'addr': 'mcp_fixture_update', 'pattern': {'op': 'cot_asg'}, 'max_matches': 5}),
        ]:
            successful(name, arguments)
        backward_interprocedural_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': 'mcp_fixture_call', 'var': 'arg0', 'direction': 'backward', 'depth': 2
        }))
        assert any(
            item.get('type') == 'caller_arg_passed' and item.get('caller') == 'mcp_fixture_outer'
            for item in backward_interprocedural_flow['flow']
        ), backward_interprocedural_flow
        zero_depth_flow = decode_tool_text(successful('trace_data_flow', {
            'addr': 'mcp_fixture_call', 'var': 'arg0', 'direction': 'backward', 'depth': 0
        }))
        assert not any(item.get('type') == 'caller_arg_passed' for item in zero_depth_flow['flow']), zero_depth_flow
        direct_update_calls = decode_tool_text(successful('xref_query', {
            'addr': 'mcp_fixture_update', 'direction': 'to', 'type': 'call'
        }))
        callgraph_callee_root = next(item['function'] for item in direct_update_calls['xrefs'])
        callgraph_callees = decode_tool_text(successful('callgraph', {
            'addr': callgraph_callee_root, 'direction': 'callees', 'depth': 1
        }))
        callgraph_callers = decode_tool_text(successful('callgraph', {
            'addr': 'mcp_fixture_update', 'direction': 'callers', 'depth': 1
        }))
        callgraph_both = decode_tool_text(successful('callgraph', {
            'addr': 'mcp_fixture_update', 'direction': 'both', 'depth': 1
        }))
        callees = {node['name'] for node in callgraph_callees['nodes']}
        callers = {node['name'] for node in callgraph_callers['nodes']}
        both = {node['name'] for node in callgraph_both['nodes']}
        assert 'mcp_fixture_update' in callees, callgraph_callees
        assert any(name.startswith('mcp_fixture_call') for name in callers), callgraph_callers
        assert any(name.startswith('mcp_fixture_call') for name in both), callgraph_both
        forward_call_path = decode_tool_text(successful('find_path', {
            'from': 'mcp_fixture_call', 'to': 'mcp_fixture_update', 'max_depth': 5, 'budget': 1000
        }))
        assert forward_call_path['found'] and forward_call_path['paths'], forward_call_path
        bounded_path = decode_tool_text(successful('find_path', {
            'from': 'mcp_fixture_call', 'to': 'mcp_fixture_update', 'budget': 1, 'max_paths': 10, 'max_depth': 1
        }))
        assert bounded_path.get('truncated') is True and len(bounded_path['paths']) <= 1, bounded_path
        assert all(path['length'] <= 1 for path in bounded_path['paths']), bounded_path
        for name, arguments in [
            ('find_bytes', {'pattern': '90', 'func': '__missing_fixture_function__'}),
            ('find_bytes', {'pattern': '90', 'segment': '.mcp_missing'}),
            ('find_bytes', {'pattern': '90', 'cursor': 'not-an-address'}),
            ('find_bytes', {'pattern': '90', 'start': 'not-an-address'}),
            ('insn_query', {'func': '__missing_fixture_function__'}),
            ('insn_query', {'segment': '.mcp_missing'}),
            ('insn_query', {'start': 'not-an-address'}),
            ('rtti', {'sort': 'unexpected', 'count': 1}),
            ('basic_blocks', {'addr': '0x0'}),
            ('basic_blocks', {'func': 'mcp_fixture_add'}),
            ('stack_frame', {'func': 'mcp_fixture_add'}),
            ('trace_data_flow', {'addr': 'mcp_fixture_update', 'var': '__missing_fixture_var__'}),
            ('analyze_function', {'addr': 'mcp_fixture_add', 'max_callers': 501}),
            ('analyze_function', {'addr': 'mcp_fixture_add', 'max_callees': 501}),
            ('analyze_function', {'addr': 'mcp_fixture_add', 'max_callers': -1}),
            ('analyze_function', {'addr': 'mcp_fixture_add', 'max_callees': -1}),
            ('xref_query', {'addr': 'mcp_fixture_add', 'count': 0}),
            ('xref_query', {'addr': 'mcp_fixture_add', 'count': 2001}),
            ('xref_query', {'target': 'mcp_fixture_add'}),
            ('imports_query', {'offset': 2147483648}),
            ('imports_query', {'count': 2000}),
            ('get_exports', {'offset': 2147483648}),
            ('rtti', {'offset': -1, 'count': 1}),
            ('resolve_vcall', {'class': 'MCPFixtureDerived', 'index': -1}),
            ('resolve_vcall', {'class': 'MCPFixtureDerived', 'index': 512}),
            ('resolve_vcall', {'class': 'MCPFixtureDerived', 'index': 1, 'offset': '0x8'}),
            ('resolve_vcall', {'class': 'MCPFixtureDerived', 'offset': '0x1000'}),
            ('resolve_vcall', {'addr': '__missing_fixture_symbol__', 'index': 0}),
            ('get_bytes', {'addr': 'mcp_fixture_add', 'size': 0}),
            ('get_bytes', {'addr': 'mcp_fixture_add', 'size': 4097}),
            ('get_bytes', {'addr': 'mcp_fixture_add', 'size': '32'}),
            ('get_bytes', {'addr': '0xFFFFFFFFFFFFFFFE', 'size': 4}),
            ('find_bytes', {'pattern': '90', 'count': -1}),
            ('find_bytes', {'pattern': '90', 'count': 1001}),
            ('find_bytes', {'pattern': '90', 'func': 'mcp_fixture_add', 'start': '0x1'}),
            ('find_bytes', {'pattern': '90', 'segment': '.text', 'func': 'mcp_fixture_add'}),
            ('insn_query', {'func': 'mcp_fixture_add', 'count': -1}),
            ('insn_query', {'func': 'mcp_fixture_add', 'max_scan': -1}),
            ('insn_query', {'func': 'mcp_fixture_add', 'start': '0x1'}),
            ('insn_query', {'segment': '.text', 'func': 'mcp_fixture_add'}),
        ]:
            failed_scope = call(name, arguments)
            assert failed_scope['result']['isError'], (name, arguments, failed_scope)
        lvar_edit = decode_tool_text(successful('refactor', {
            'target': 'mcp_fixture_call', 'lvars': [{'index': 0, 'new_name': 'mcp_qa_local'}]
        }))
        assert lvar_edit['lvars'][0]['status'] == 'success', lvar_edit
        partial_lvar_edit = decode_tool_text(successful('refactor', {
            'target': 'mcp_fixture_call',
            'lvars': [{'index': 0, 'new_name': 'mcp_qa_partial', 'type': 'not a valid C type !!!'}]
        }))
        assert partial_lvar_edit['status'] == 'partial' and partial_lvar_edit['lvars'][0]['status'] == 'partial', partial_lvar_edit
        outside_comment = call('refactor', {
            'target': 'mcp_fixture_call',
            'comments': [{'addr': byte_result['address'], 'comment': 'must not escape target function'}]
        })
        assert outside_comment['result']['isError'], outside_comment
        comment_addr = int(byte_result['address'], 16)
        comment_text = 'IDA MCP in-scope comment QA'
        comment_receipt = decode_tool_text(successful('refactor', {
            'target': 'mcp_fixture_add',
            'comments': [{'addr': byte_result['address'], 'comment': comment_text}]
        }))
        assert comment_receipt['comments'][0]['status'] == 'success', comment_receipt
        observed_comment = decode_tool_text(successful('py', {
            'code': f'import idc\nidc.get_cmt({comment_addr}, 0)'
        }))
        assert observed_comment['result'] == comment_text, observed_comment
        successful('refactor', {
            'target': 'mcp_fixture_add',
            'comments': [{'addr': byte_result['address'], 'comment': ''}]
        })
        invalid_batch_address = decode_tool_text(successful('strings', {'addrs': ['not-an-address', byte_result['address']]}))
        assert len(invalid_batch_address['strings']) == 2 and invalid_batch_address['strings'][0]['status'] == 'error', invalid_batch_address
        # Put IDA into interactive mode. A non-Python MCP request must enable
        # batch mode while this database hook attempts modal SDK calls.
        assert decode_tool_text(successful('py', {'code': 'import idc\nidc.batch(0)'})) == {'result': 0}
        successful('py', {'code': '''import ida_idp, ida_kernwin
qa_warning_seen = False
qa_dialog_results = {}
class QAHooks(ida_idp.IDB_Hooks):
    def renamed(self, ea, new_name, local_name):
        global qa_warning_seen, qa_dialog_results
        qa_warning_seen = True
        ida_kernwin.warning('Fixture warning: must be suppressed by MCP')
        qa_dialog_results['ask_yn'] = ida_kernwin.ask_yn(0, 'Fixture question: must be suppressed by MCP')
        qa_dialog_results['ask_file'] = ida_kernwin.ask_file(False, None, 'Fixture file request: must be suppressed by MCP')
        qa_dialog_results['ask_str'] = ida_kernwin.ask_str('', 0, 'Fixture string request: must be suppressed by MCP')
        qa_dialog_results['ask_text'] = ida_kernwin.ask_text(1024, '', 'Fixture text request: must be suppressed by MCP')
        qa_dialog_results['ask_addr'] = ida_kernwin.ask_addr(0, 'Fixture address request: must be suppressed by MCP')
        qa_dialog_results['ask_seg'] = ida_kernwin.ask_seg(0, 'Fixture segment request: must be suppressed by MCP')
        qa_dialog_results['ask_long'] = ida_kernwin.ask_long(0, 'Fixture number request: must be suppressed by MCP')
        return 0
qa_hooks = QAHooks()
qa_hooks.hook()
'''})
        receipt = successful('refactor', {'target': 'mcp_fixture_add', 'name': 'mcp_fixture_sum'})
        assert '"code"' not in receipt, receipt
        dialog_results = decode_tool_text(successful('py', {
            'code': 'qa_hooks.unhook()\n(qa_warning_seen, qa_dialog_results)'
        }))['result']
        assert dialog_results[0] is True, dialog_results
        assert dialog_results[1]['ask_yn'] == 0 and dialog_results[1]['ask_file'] == '', dialog_results
        assert all(name in dialog_results[1] for name in ('ask_str', 'ask_text', 'ask_addr', 'ask_seg', 'ask_long')), dialog_results
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
