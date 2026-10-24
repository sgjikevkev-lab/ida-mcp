#pragma once
// Kept as a raw Python program so the capture/cancellation boundary can also
// be exercised without loading IDAPython or touching an IDA database.
inline constexpr const char* kPythonRunner = R"mcp_py(
def __ida_mcp_execute(code64, filename64, argv64):
    import ast, base64, io, json, os, sys, traceback, types
    import idc
    runtime = sys.modules.setdefault('_ida_mcp_runtime', types.ModuleType('_ida_mcp_runtime'))
    scope = runtime.__dict__.setdefault('user_scope', {'__name__': '__main__'})
    class Capture(io.TextIOBase):
        def __init__(self):
            self.parts, self.length, self.truncated = [], 0, False
        def write(self, text):
            if not isinstance(text, str):
                raise TypeError('write expects str')
            available = max(0, 262144 - self.length)
            self.parts.append(text[:available]) if available else None
            self.length += min(len(text), available)
            self.truncated |= len(text) > available
            return len(text)
        def flush(self):
            pass
        def getvalue(self):
            return ''.join(self.parts)
    stdout, stderr = Capture(), Capture()
    old_stdout, old_stderr, old_argv = sys.stdout, sys.stderr, sys.argv
    old_path, old_trace = list(sys.path), sys.gettrace()
    old_file = scope.get('__file__', None)
    had_file = '__file__' in scope
    traces, ticks = {}, 0
    response = {}
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
            try:
                json.dumps(result)
                response['result'] = result
            except (TypeError, ValueError, OverflowError):
                response['result'] = repr(result)[:262144]
    except BaseException as exc:
        response['error_code'] = ('execution_timeout' if isinstance(exc, TimeoutError)
                                  else 'cancelled' if isinstance(exc, KeyboardInterrupt) else 'py_exec_error')
        response['message'] = traceback.format_exc()[-262144:]
    finally:
        sys.settrace(old_trace)
        sys.stdout, sys.stderr, sys.argv = old_stdout, old_stderr, old_argv
        sys.path[:] = old_path
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
    runtime.response = json.dumps(response, ensure_ascii=True)
)mcp_py";
