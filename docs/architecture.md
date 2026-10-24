# Architecture review and execution contract

This review concerns this repository, not Hex-Rays IDA Assist. The latter was used only as a comparison of model-facing output styles.

## Problems found in 1.2.1

1. Main-thread scheduling was implemented twice. Both implementations signalled completion from inside `execute()` and allowed another thread to destroy the request before IDA had returned from the callback. The timeout/abandon handshake also raced with completion.
2. Tool lambdas captured stack references. Returning from an off-thread synchronization timeout while a lambda was already running left references to expired stack variables.
3. A job captured its own `shared_ptr` through its work function, forming a reference cycle. Several shutdown paths also marked a still-running backend idle.
4. The server accepted one persistent client at a time. A connected router could prevent discovery and progress queries from other clients.
5. Some overlapped operations were cancelled and their events/buffers immediately destroyed. Windows cancellation does not mean the operation has finished using those objects. Server writes also used synchronous arguments on an overlapped handle, and disconnect flushed indefinitely.
6. Router shutdown disconnected a pipe concurrently with the worker using it. Instance discovery could change shared selection from the worker while the stdio thread read it. Losing a selected database could silently select another binary.
7. Timeouts varied between 30 seconds, 8 minutes, 10 minutes and a Python-specific maximum of an hour. A main-thread Python call bypassed the synchronization wait, so its advertised timeout did not interrupt it.
8. There was no operation-wide unattended UI scope. The plugin menu action used a modal `info()` call. Decompiler wait suppression alone did not cover other SDK dialogs.
9. Every tool response was pretty-printed JSON. The registry inserted `elapsed_sec` by replacing the last closing brace in text; that operation could damage an empty JSON object. Responses repeated status, pagination counts and derived size representations.
10. Decompilation always returned a separate local-variable table. Refactoring and applying reconstructed structures could return fresh pseudocode without a request for it. Xrefs always collected preceding assembly context. CFGs repeated edges as addresses and indices.
11. Input schemas were advertised but not consistently enforced. Wrong types, extra parameters and deep recursive input reached handlers. Several modules contained unused `CanHandle`/empty `GetSchema` methods, and identical copies of the JSON library were maintained in two directories.
12. A generation update to one side of the function-edge cache could mark stale edges on the other side fresh. Empty edge lists were never treated as cache hits. External IDB edits did not consistently invalidate caches.
13. Python capture used interpreter globals and unbounded `StringIO`. Failing scripts could mutate the database without invalidating caches. Integer shifts in Base64 encoding used a signed accumulator.
14. General name matching compiled an implicit backtracking regex for each candidate. C++ punctuation could unexpectedly become regex syntax.
15. A malformed embedded MBA pattern prevented the entire built-in rule table from loading. Native integration also reproduced an access violation in `trace_data_flow`: its path-condition walker dereferenced the null root parent provided to Hex-Rays traversal. Both defects are fixed and exercised by the integration checks.

## Execution ownership

The router owns stdio and one tool worker. It serves protocol heartbeat messages while a tool is running. It never automatically repeats a failed database operation.

The plugin accepts up to 16 local pipe clients. Discovery metadata and status do not require an IDA main-thread request. A single dispatcher admits one active database operation across all clients; additional operations receive `busy`.

All database operations use `MFF_WRITE | MFF_NOWAIT`. Even decompilation can change ordinary IDA metadata, so read flags cannot safely be inferred solely from a tool's name. Tool implementations execute inline on that main thread. Their synchronization wrappers assert this invariant instead of scheduling a second asynchronous lambda.

The dispatcher owns requests. A completed request stays alive until the next main-thread dispatch, when IDA's previous callback has returned. A successfully cancelled queued request can be retired independently because IDA has removed it. Shutdown joins pipe clients and cancels pending execution requests on the main thread.

SDK callbacks such as ctree visitors contain C++ exceptions, return the SDK's stop indication, and rethrow only after control returns to plugin code. Cancellation must not unwind arbitrarily through a foreign SDK callback.

## Thirty-minute deadline and cancellation

The fixed limit is 1,800,000 milliseconds. There is no per-call timeout argument.

The plugin operation deadline starts at submission, including time waiting for IDA's main thread. The router bounds the complete write/read transaction using a single deadline. An operation timeout requests cancellation and returns an error. A queued request is removed when cancellation succeeds. An already-running request remains busy until it actually returns or reaches a cooperative checkpoint.

Loops, recursive plugin analysis and Python tracing check cancellation/deadlines. Cancellation notifications use a separate pipe connection and a per-request internal token, so cancelling one router request does not inadvertently target another client's matching numeric ID. Early cancellations are retained in a bounded store to cover submission races.

The backend does not use `TerminateThread` or mark itself idle while code is still running. Arbitrary IDA/Hex-Rays native calls, Python extensions, or a script that defeats its tracing cannot be forcibly stopped safely inside the GUI process. A hard wall-clock limit for those calls requires a separate worker process with a separately opened database; killing the user's GUI process would lose unsaved work. That process-isolated backend is not implemented here.

## Dialog policy and native failures

Ordinary tool execution temporarily sets the IDA SDK's `batch` flag and restores its previous value afterward. Decompiler calls also use `DECOMP_NO_WAIT`. The SDK documents `batch` as the unattended mode: warning/info dialogs are redirected and input dialogs immediately return their default values. The plugin's own informational message uses `msg()`.

Python is the intentional exception. Its execution retains the previous interactive mode and chains/restores the existing trace, allowing IDAPython's manual cancellation mechanism to remain available. The wrapper also polls the MCP cancellation state. Python user variables live in a dedicated persistent namespace; capture state does not occupy that namespace. Stream, argv, path, file and trace state are restored on ordinary Python exceptions, `SystemExit`, cancellation and deadline errors.

Captured stdout/stderr are capped at 256 Ki characters each and report truncation. Script files are capped at 2 MiB. These are containment measures, not a sandbox: arbitrary Python still has the host process's capabilities.

A caught hardware exception quarantines the backend and refuses further database tools. `get_status` remains available. Recovery requires restarting IDA; silently continuing after an access violation is unsafe. SEH is best-effort containment and cannot guarantee survival of stack exhaustion, heap corruption, fail-fast termination, bugs in IDA itself, or direct Qt/native dialogs opened by unrelated third-party code. No claim of 100% crash prevention is made.

## Model-facing data

The wire protocol and input arguments remain JSON-RPC/JSON Schema. Tool content is rendered for language models:

- Small objects use compact JSON.
- Large uniform lists use a header and tab-separated scalar rows, with JSON quoting for strings and explicit column names.
- Multiline source code can be returned as an indented literal block instead of escaped `\\n` text.
- Irregular nested data falls back to compact JSON where that is shorter.

These text representations are not advertised as YAML, TOON or a machine-readable output schema. Clients should use the MCP `isError` flag; code consuming the result text must account for its model-oriented representation.

Routine execution telemetry is omitted. Useful timing is available only through `get_status`. Root success/error markers and list counts that repeat returned array sizes are omitted; actual totals, continuation cursors, failures, partial-read sizes and analytical limitations remain. Arbitrary nested Python result dictionaries retain their original keys and values.

Results above 2 MiB produce `output_too_large` instead of a sliced, invalid JSON document. Narrow the query or use the tool's pagination. Frame buffers are capped at 32 MiB and request nesting at 64 levels. Recursive plugin walkers have an additional depth limit.

## Input and default changes

- Unknown advertised parameters and wrong types return `invalid_params` before discovery/SDK execution. Batches are bounded and empty batches are rejected.
- `decompile` takes exactly one of `addr`/`addrs`. `include_lvars` defaults to false.
- `refactor` uses `target` or `items`. The duplicate top-level `addr` spelling is removed. `include_code` defaults to false.
- `reconstruct_struct` uses `include_code` instead of `decompile_now`; applying a type no longer implicitly returns refreshed code.
- `xref_query.context` and `stack_frame.include_lvars` default to false.
- `py` takes exactly one of `code`/`file`, plus optional string `argv`; `timeout`, `path` and `expr` are not part of its public contract.
- Redundant `demangle` switches, the RTTI `class` alias and the signature generator's internal candidate-budget knob are omitted from the model catalog. Meaningful filtering, pagination, graph bounds and mutation controls remain.
- Tools with continuation cursors expose `cursor` instead of a second `offset` spelling. Tools that paginate only by numeric offset retain that parameter. Callgraph node names are stored once in the node list; edge-only mode supplies names on edges instead.
- Name patterns are literal substrings or `*`/`?` globs, bounded to 1024 bytes. Implicit regex interpretation is removed to avoid repeated compilation, ambiguous C++ punctuation and recursive regex backtracking. Arbitrary regex work remains possible through the explicit Python tool.

## Validation

The automated checks cover contracts/output, the dispatcher with a minimal SDK scheduler double, real Win32 pipe routing, and Python wrapper behavior. The native integration runner launches a new IDA 9.2 process with a private `IDAUSR`, new plugin binary and a disposable fixture database. It never replaces installed plugins or attaches tests to existing databases.

Native checks exercise decompilation, Python failures/recovery, an infinite Python loop cancelled over MCP, and SDK warning/question dialogs attempted by a fixture-only rename hook. Passing those checks demonstrates these specific paths, not every possible binary or native SDK failure.
