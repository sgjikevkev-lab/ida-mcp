import base64
import json
from pathlib import Path
import sys
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PythonRunnerTests(unittest.TestCase):
    def setUp(self):
        self.old_idc = sys.modules.get('idc')
        self.idc = types.ModuleType('idc')
        self.idc.eval_idc = lambda expression: 0
        sys.modules['idc'] = self.idc
        sys.modules.pop('_ida_mcp_runtime', None)
        source = (ROOT / 'plugin/tools/api_python/python_runner.h').read_text(encoding='utf-8')
        program = source.split('R"mcp_py(', 1)[1].split(')mcp_py"', 1)[0]
        namespace = {}
        exec(program, namespace)
        self.runner = namespace['__ida_mcp_execute']

    def tearDown(self):
        if self.old_idc is None:
            sys.modules.pop('idc', None)
        else:
            sys.modules['idc'] = self.old_idc
        sys.modules.pop('_ida_mcp_runtime', None)

    def run_code(self, source, filename='<mcp>', argv=()):
        encode = lambda text: base64.b64encode(text.encode()).decode()
        self.runner(encode(source), encode(filename), encode(json.dumps(list(argv))))
        return json.loads(sys.modules['_ida_mcp_runtime'].response)

    def test_expression_and_persistent_user_namespace(self):
        self.assertEqual(self.run_code('value = 41\nvalue + 1'), {'result': 42})
        self.assertEqual(self.run_code('value'), {'result': 41})

    def test_failure_restores_streams_argv_path_and_trace(self):
        original = sys.stdout, sys.stderr, sys.argv, list(sys.path), sys.gettrace()
        result = self.run_code("print('before')\nraise ValueError('broken')", '/tmp/example.py', ['arg'])
        self.assertEqual(result['error_code'], 'py_exec_error')
        self.assertEqual(result['stdout'], 'before\n')
        self.assertIn('ValueError: broken', result['message'])
        self.assertEqual((sys.stdout, sys.stderr, sys.argv, list(sys.path), sys.gettrace()), original)
        scope = sys.modules['_ida_mcp_runtime'].user_scope
        self.assertNotIn('__file__', scope)
        self.assertNotIn('runtime', scope)

    def test_system_exit_is_contained(self):
        self.assertEqual(self.run_code('raise SystemExit(2)')['error_code'], 'py_exec_error')

    def test_syntax_error(self):
        self.assertEqual(self.run_code('if')['error_code'], 'py_exec_error')

    def test_capture_is_bounded(self):
        result = self.run_code("print('a' * 400000)")
        self.assertEqual(len(result['stdout']), 262144)
        self.assertTrue(result['output_truncated'])

    def test_cooperative_cancellation(self):
        self.idc.eval_idc = lambda expression: 1
        result = self.run_code('while True:\n    pass')
        self.assertEqual(result['error_code'], 'cancelled')
        self.assertIsNone(sys.gettrace())

    def test_deadline(self):
        self.idc.eval_idc = lambda expression: 2
        self.assertEqual(self.run_code('while True:\n    pass')['error_code'], 'execution_timeout')

    def test_existing_trace_is_chained_and_restored(self):
        seen = []
        def tracer(frame, event, arg):
            if frame.f_code.co_filename == '<mcp>':
                seen.append(event)
            return tracer
        previous = sys.gettrace()
        try:
            sys.settrace(tracer)
            self.assertEqual(self.run_code('a = 1\na + 2'), {'result': 3})
            self.assertIs(sys.gettrace(), tracer)
        finally:
            sys.settrace(previous)
        self.assertIn('line', seen)

    def test_user_payload_is_not_rewritten(self):
        self.assertEqual(self.run_code("{'status': 'success', 'elapsed_sec': 5}"),
                         {'result': {'status': 'success', 'elapsed_sec': 5}})


if __name__ == '__main__':
    unittest.main()
