"""Exercise the built router against a disposable Win32 Named Pipe backend.

No installed IDA plugin or real database is used for tool execution.
"""
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import queue
import subprocess
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
K = C.WinDLL('kernel32', use_last_error=True)
K.CreateNamedPipeW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, W.DWORD, W.DWORD, W.DWORD, W.DWORD, W.LPVOID]
K.CreateNamedPipeW.restype = W.HANDLE
K.ConnectNamedPipe.argtypes = [W.HANDLE, W.LPVOID]
K.ConnectNamedPipe.restype = W.BOOL
K.ReadFile.argtypes = [W.HANDLE, W.LPVOID, W.DWORD, C.POINTER(W.DWORD), W.LPVOID]
K.ReadFile.restype = W.BOOL
K.WriteFile.argtypes = [W.HANDLE, W.LPCVOID, W.DWORD, C.POINTER(W.DWORD), W.LPVOID]
K.WriteFile.restype = W.BOOL
K.CloseHandle.argtypes = [W.HANDLE]
K.DisconnectNamedPipe.argtypes = [W.HANDLE]


class Backend:
    def __init__(self):
        self.pipe = rf'\\.\pipe\ida_mcp_{os.getpid()}'
        self.binary = 'mcp_disposable_fixture.dll'
        self.ready = threading.Event()
        self.started = threading.Event()
        self.cancelled = threading.Event()
        self.release = threading.Event()
        self.block = False
        self.token = None
        self.calls = []
        self.handles = set()
        self.stopping = False
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()
        assert self.ready.wait(3), 'fixture pipe failed to start'

    def accept(self):
        while not self.stopping:
            pipe = K.CreateNamedPipeW(self.pipe, 3, 0, 16, 65536, 65536, 0, None)
            if pipe == C.c_void_p(-1).value:
                return
            self.handles.add(pipe)
            self.ready.set()
            connected = K.ConnectNamedPipe(pipe, None) or C.get_last_error() == 535
            if connected and not self.stopping:
                threading.Thread(target=self.client, args=(pipe,), daemon=True).start()
            else:
                K.CloseHandle(pipe)
                self.handles.discard(pipe)
                return

    def client(self, pipe):
        buffer = C.create_string_buffer(8192)
        data = b''
        try:
            while not self.stopping:
                count = W.DWORD()
                if not K.ReadFile(pipe, buffer, len(buffer), C.byref(count), None) or not count.value:
                    return
                data += buffer.raw[:count.value]
                while b'\n' in data:
                    line, data = data.split(b'\n', 1)
                    req = json.loads(line)
                    method = req['method']
                    if method == 'ida/cancel':
                        if req['params']['token'] == self.token:
                            self.cancelled.set()
                            self.release.set()
                        continue
                    if method == 'get_instance_info':
                        result = {'pid': os.getpid(), 'binary': self.binary, 'idb_path': 'fixture.i64', 'backend': 'test'}
                    else:
                        name = req.get('params', {}).get('name')
                        self.calls.append(name)
                        if name == 'get_status':
                            result = {'content': [{'type': 'text', 'text': json.dumps({'busy': self.started.is_set() and not self.release.is_set()})}]}
                        else:
                            self.token = req.get('_cancel_token')
                            self.started.set()
                            if self.block:
                                self.release.wait(10)
                            failed = self.cancelled.is_set()
                            result = {'content': [{'type': 'text', 'text': 'cancelled' if failed else 'fixture-result'}], 'isError': failed}
                    response = json.dumps({'jsonrpc': '2.0', 'id': req['id'], 'result': result}).encode() + b'\n'
                    count = W.DWORD()
                    if not K.WriteFile(pipe, response, len(response), C.byref(count), None):
                        return
        finally:
            K.DisconnectNamedPipe(pipe)
            K.CloseHandle(pipe)
            self.handles.discard(pipe)

    def close(self):
        self.stopping = True
        self.release.set()
        # Wake the synchronous accept without touching any installed IDA pipe.
        try:
            with open(self.pipe, 'r+b', buffering=0):
                pass
        except OSError:
            pass
        self.thread.join(2)


class RouterTests(unittest.TestCase):
    def setUp(self):
        self.backend = Backend()
        self.process = subprocess.Popen([str(ROOT / 'bin/Release/router.exe')], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.responses = queue.Queue()
        def read():
            for line in self.process.stdout:
                self.responses.put(json.loads(line))
        self.reader = threading.Thread(target=read, daemon=True)
        self.reader.start()
        self.next_id = 0

    def tearDown(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.backend.close()
        self.process.stdout.close()
        self.process.stderr.close()

    def send(self, request):
        self.process.stdin.write(json.dumps(request).encode() + b'\n')
        self.process.stdin.flush()

    def request(self, method, params=None):
        self.next_id += 1
        request = {'jsonrpc': '2.0', 'id': self.next_id, 'method': method}
        if params is not None:
            request['params'] = params
        self.send(request)
        response = self.responses.get(timeout=8)
        self.assertEqual(response['id'], self.next_id)
        return response

    def tool(self, name, arguments=None):
        return self.request('tools/call', {'name': name, 'arguments': arguments or {}})

    def test_initialize_reports_release_version(self):
        response = self.request('initialize', {'protocolVersion': '2025-06-18'})
        self.assertEqual(response['result']['serverInfo']['version'], '2.0.0')

    def select_fixture(self):
        response = self.tool('switch_file', {'filename': self.backend.binary})
        self.assertFalse(response['result'].get('isError', False), response)

    def test_catalog_and_invalid_arguments_do_not_require_ida(self):
        result = self.request('tools/list')['result']
        self.assertEqual(len(result['tools']), 33)
        for name, arguments in [('get_bytes', {'addr': 'main', 'size': -1}),
                                ('decompile', {}), ('py', {'code': '1', 'timeout': 1}),
                                ('get_available_files', {'unused': True}),
                                ('switch_file', {'filename': self.backend.binary, 'unused': True}),
                                ('unknown_tool', {})]:
            self.assertTrue(self.tool(name, arguments)['result']['isError'])
        self.assertFalse(self.backend.calls)

    def test_malformed_requests_and_notifications(self):
        response = self.request('does/not/exist')
        self.assertEqual(response['error']['code'], -32601)
        self.send({'jsonrpc': '2.0', 'method': 'tools/call', 'params': {'name': 'get_bytes', 'arguments': {'addr': 'main'}}})
        response = self.request('ping')
        self.assertEqual(response['result'], {})
        self.assertFalse(self.backend.calls)

    def test_forwarding_heartbeat_busy_and_cancellation(self):
        self.select_fixture()
        self.backend.block = True
        self.next_id += 1
        running_id = self.next_id
        self.send({'jsonrpc': '2.0', 'id': running_id, 'method': 'tools/call',
                   'params': {'name': 'get_bytes', 'arguments': {'addr': '0x1000', 'size': 8}}})
        self.assertTrue(self.backend.started.wait(3))
        started = time.monotonic()
        self.assertEqual(self.request('ping')['result'], {})
        self.assertLess(time.monotonic() - started, 1)
        self.assertTrue(self.tool('get_bytes', {'addr': '0x1000'})['result']['isError'])
        status = self.tool('get_status')
        self.assertIn('true', status['result']['content'][0]['text'])
        # A cancellation for another request must have no effect.
        self.send({'jsonrpc': '2.0', 'method': 'notifications/cancelled', 'params': {'requestId': 9999}})
        self.assertFalse(self.backend.cancelled.wait(0.1))
        self.send({'jsonrpc': '2.0', 'method': 'notifications/cancelled', 'params': {'requestId': running_id}})
        self.assertTrue(self.backend.cancelled.wait(3))
        response = self.responses.get(timeout=3)
        self.assertEqual(response['id'], running_id)
        self.assertTrue(response['result']['isError'])

    def test_shutdown_cancels_outstanding_pipe_io(self):
        self.select_fixture()
        self.backend.block = True
        self.send({'jsonrpc': '2.0', 'id': 1000, 'method': 'tools/call',
                   'params': {'name': 'get_bytes', 'arguments': {'addr': '0x1000'}}})
        self.assertTrue(self.backend.started.wait(3))
        self.process.stdin.close()
        self.assertEqual(self.process.wait(timeout=3), 0)


if __name__ == '__main__':
    unittest.main()
