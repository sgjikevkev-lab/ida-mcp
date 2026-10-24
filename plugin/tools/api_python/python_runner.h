#pragma once
// Kept as a raw Python program so the capture/cancellation boundary can also
// be exercised without loading IDAPython or touching an IDA database.
inline constexpr const char* kPythonRunner = R"mcp_py(
def __ida_mcp_execute(code64, filename64, argv64):
    import ast, base64, io, json, math, os, sys, traceback, types
    import idc
    runtime = sys.modules.setdefault('_ida_mcp_runtime', types.ModuleType('_ida_mcp_runtime'))
    scope = runtime.__dict__.setdefault('user_scope', {'__name__': '__main__'})
    class Capture(io.TextIOBase):
        def __init__(self, limit):
            self.parts, self.length, self.truncated = [], 0, False
            self.limit = limit
        def write(self, text):
            if not isinstance(text, str):
                raise TypeError('write expects str')
            available = max(0, self.limit - self.length)
            self.parts.append(text[:available]) if available else None
            self.length += min(len(text), available)
            self.truncated |= len(text) > available
            return len(text)
        def flush(self):
            pass
        def getvalue(self):
            return ''.join(self.parts)
    stdout, stderr = Capture(65536), Capture(65536)
    old_stdout, old_stderr, old_argv = sys.stdout, sys.stderr, sys.argv
    old_path_object, old_path, old_trace = sys.path, list(sys.path), sys.gettrace()
    old_file = scope.get('__file__', None)
    had_file = '__file__' in scope
    traces, ticks = {}, 0
    response = {}
    result_budget = [524288]
    result_seen = set()

    def bounded_result(value, depth=0):
        if depth >= 32:
            response['output_truncated'] = True
            return '<maximum result depth reached>'
        if value is None or type(value) is bool:
            result_budget[0] -= 8
            return value
        if type(value) is int:
            if value.bit_length() > 4096:
                response['output_truncated'] = True
                return '<integer omitted: too large>'
            result_budget[0] -= min(1235, max(1, value.bit_length() // 3)) + 2
            return value
        if type(value) is float:
            result_budget[0] -= 32
            return value if math.isfinite(value) else ('nan' if math.isnan(value) else ('inf' if value > 0 else '-inf'))
        if type(value) is str:
            available = max(0, result_budget[0] // 6)
            if len(value) > available:
                value = value[:available]
                response['output_truncated'] = True
            result_budget[0] -= len(value) * 6 + 2
            return value
        if type(value) in (list, tuple, dict):
            identity = id(value)
            if identity in result_seen:
                response['output_truncated'] = True
                return '<recursive reference>'
            result_budget[0] -= 4
            result_seen.add(identity)
            try:
                if type(value) is dict:
                    bounded = {}
                    for index, (key, item) in enumerate(value.items()):
                        if index >= 4096 or result_budget[0] <= 64:
                            response['output_truncated'] = True
                            bounded['<truncated>'] = True
                            break
                        safe_key = key if type(key) is str else str(key)[:256]
                        safe_key = bounded_result(safe_key, depth + 1)
                        bounded[safe_key] = bounded_result(item, depth + 1)
                    return bounded
                bounded = []
                for index, item in enumerate(value):
                    if index >= 4096 or result_budget[0] <= 64:
                        response['output_truncated'] = True
                        bounded.append('<truncated>')
                        break
                    bounded.append(bounded_result(item, depth + 1))
                return bounded
            finally:
                result_seen.remove(identity)
        response['output_truncated'] = True
        return '<unsupported Python value>'
    def trace(frame, event, arg):
        nonlocal ticks
        ticks += 1
        if ticks % 256 == 0:
            stopped = idc.eval_idc('__ida_mcp_stop()')
            if stopped == 2:
                raise TimeoutError('Python execution exceeded the 30-minute limit')
            if stopped == 1:
                raise KeyboardInterrupt('MCP execution cancelled')
        # Preserve IDAPython's existing trace, including manual cancellation.
        previous = old_trace if event == 'call' else traces.get(id(frame))
        if previous is not None:
            following = previous(frame, event, arg)
            if event == 'return':
                traces.pop(id(frame), None)
            else:
                traces[id(frame)] = following
        return trace
    try:
        filename = base64.b64decode(filename64).decode('utf-8')
        code = base64.b64decode(code64).decode('utf-8-sig')
        arguments = json.loads(base64.b64decode(argv64).decode('utf-8'))
        if filename != '<mcp>':
            scope['__file__'] = filename
            sys.path.insert(0, os.path.dirname(filename))
        sys.argv = [filename] + arguments
        sys.stdout, sys.stderr = stdout, stderr
        tree = ast.parse(code, filename)
        sys.settrace(trace)
        result = None
        if tree.body and isinstance(tree.body[-1], ast.Expr):
            last = tree.body.pop()
            if tree.body:
                exec(compile(tree, filename, 'exec'), scope)
            result = eval(compile(ast.Expression(last.value), filename, 'eval'), scope)
        else:
            exec(compile(tree, filename, 'exec'), scope)
        if result is not None:
            response['result'] = bounded_result(result)
    except BaseException as exc:
        response['error_code'] = ('execution_timeout' if isinstance(exc, TimeoutError)
                                  else 'cancelled' if isinstance(exc, KeyboardInterrupt) else 'py_exec_error')
        response['message'] = traceback.format_exc()[-32768:]
    finally:
        sys.settrace(old_trace)
        sys.stdout, sys.stderr, sys.argv = old_stdout, old_stderr, old_argv
        sys.path = old_path_object
        old_path_object[:] = old_path
        sys.modules['_ida_mcp_runtime'] = runtime
        if had_file:
            scope['__file__'] = old_file
        else:
            scope.pop('__file__', None)
    if stdout.length:
        response['stdout'] = stdout.getvalue()
    if stderr.length:
        response['stderr'] = stderr.getvalue()
    if stdout.truncated or stderr.truncated:
        response['output_truncated'] = True
    serialized = json.dumps(response, ensure_ascii=True, allow_nan=False)
    runtime.response = serialized if len(serialized) <= 1800000 else json.dumps({
        'error_code': 'output_too_large', 'message': 'Python result exceeded the response limit'
    })
)mcp_py";
