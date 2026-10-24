# IDA MCP

A native C++ MCP router and IDA Pro plugin for language-model agents. This repository is independent of Hex-Rays IDA Assist.

The current release is **2.0.0**. It changes input contracts and response defaults from 1.2.1. The plugin targets Windows x64 and the bundled **IDA Pro 9.2 SDK**. Other IDA versions require separate compatibility work.

## Model interface

Inputs use JSON Schema and travel over JSON-RPC 2.0. Results use MCP text content, rendered for models: compact JSON for small objects, compact tables for repeated scalar records, and literal source blocks where useful. Irregular structures retain compact JSON.

Each tool returns its requested result. Routine timing, success markers, duplicate counts and derived size strings are omitted. Additional products are explicit:

| Tool | Default | Additional data |
| --- | --- | --- |
| `decompile` | Function address and C pseudocode | `include_lvars: true` adds indexed variable metadata |
| `refactor` | Edit receipts | `include_code: true` adds refreshed code for a single target |
| `reconstruct_struct` | Inferred layout and C declaration | `include_code: true` adds code after applying the type |
| `xref_query` | References and their locations | `context: true` adds argument preparation assembly |
| `stack_frame` | Stack layout | `include_lvars: true` adds decompiler variables |
| `get_bytes` | Address and hex bytes | Actual read size appears when the read is partial |

Failure responses have `isError: true` and a short error code/message. Mixed batches retain per-item failures; a fully failed decompilation batch is an error. An empty search result is successful. Actual totals and continuation cursors remain available for pagination.

Unknown parameters, incorrect types, empty batches and excessive nesting are rejected. Names use literal substrings or `*`/`?` globs; implicit regular expressions are no longer accepted. Use `py` when arbitrary regex processing is needed.

## Execution

```text
Model --JSON-RPC/stdio--> router.exe --Named Pipe--> ida_mcp64.dll
                                                    |
                                             One main-thread
                                             database operation
```

The router keeps protocol heartbeat requests responsive while a worker waits for IDA. The plugin accepts multiple local clients for discovery/status but admits one active database operation. Additional operations receive `busy` rather than overlapping IDA API calls.

The fixed operation deadline is **30 minutes**. Loops, recursive analysis and Python tracing check cancellation. MCP cancellation notifications are supported. The backend remains busy until an already-running operation actually stops; a timeout never falsely reports it idle. Native IDA calls and Python extensions cannot be forcibly interrupted safely in the GUI process.

Ordinary tools run in the SDK's unattended `batch` scope, with decompiler wait boxes disabled. Python retains IDAPython's interactive cancellation behavior. A caught native fault quarantines the backend; restart IDA before running further database tools.

There is no guarantee against every native crash or unrelated third-party GUI callback. A hard stop for uninterruptible SDK code requires a separate process/database backend. See [architecture review](docs/architecture.md) for the ownership rules, discovered defects, changes and limits.

## Install

Build outputs are in `bin/Release`:

- Put `ida_mcp64.dll` in the IDA Pro 9.2 `plugins` directory, then restart IDA.
- Register the built `router.exe` as a stdio MCP server.

```json
{
  "mcpServers": {
    "ida-pro": {
      "command": "C:\\Tools\\ida-mcp\\router.exe"
    }
  }
}
```

The router discovers plugin pipes. If several databases are open, call `get_available_files` and select an exact name with `switch_file`. An ambiguous name is an error. Losing the selected database does not silently route subsequent edits to another database.

## Tools

| Tool | Purpose |
| --- | --- |
| `get_available_files` | Discover open binaries |
| `switch_file` | Select the active database |
| `get_status` | Inspect execution state and elapsed time |
| `idb_save` | Save the database, optionally compact/backup/save elsewhere |
| `survey_binary` | Architecture, image base, entry point and database counts |
| `get_segments` | Segment ranges and permissions |
| `get_exports` | Filter and page exports |
| `imports_query` | Filter and page imported modules/symbols |
| `get_bytes` | Read mapped bytes |
| `strings` | Read string literals or search/page the string list |
| `find_bytes` | Find wildcard byte patterns |
| `list_funcs` | Filter and page functions |
| `list_globals` | Filter and page global symbols |
| `analyze_function` | Function metadata, arguments and bounded caller/callee analysis |
| `disasm` | Sequential or batched disassembly |
| `insn_query` | Search instructions |
| `basic_blocks` | CFG blocks, indexed edges and branch metadata |
| `xref_query` | Query references |
| `callgraph` | Bounded caller/callee graph |
| `find_path` | Bounded bidirectional call-path search |
| `decompile` | Hex-Rays C pseudocode |
| `get_ast` | Bounded ctree serialization or pattern matching |
| `mba_simplify` | MBA simplification candidates |
| `simplify_predicate` | Inspect/simplify predicates, with explicit persistence control |
| `types` | Inspect, search, declare or interpret C types |
| `stack_frame` | Stack layout |
| `reconstruct_struct` | Infer and optionally apply a structure |
| `rtti` | Inspect MSVC RTTI and optionally create types |
| `resolve_vcall` | Resolve vtable slots/calls |
| `refactor` | Rename, retype and comment symbols or variables |
| `make_signature` | Generate wildcard signatures |
| `trace_data_flow` | Bounded interprocedural variable/data-flow analysis |
| `py` | Run code or a script file with bounded stdout/stderr capture |

The tool catalog supplies exact arguments, bounds and descriptions. Analytical heuristics and traversal limits are not proofs of exhaustive behavior.

## Build and checks

Use Visual Studio with the v145 C++ toolset and Windows SDK. The solution contains the router and plugin; `shared/json.h` is their single vendored JSON dependency.

From a Visual Studio developer PowerShell:

```powershell
msbuild ida-mcp.sln /p:Configuration=Release /p:Platform=x64 /m
msbuild tests/contract_tests.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild tests/dispatcher_tests.vcxproj /p:Configuration=Release /p:Platform=x64
.\bin\Release\contract_tests.exe
.\bin\Release\dispatcher_tests.exe
python tests/test_python_runner.py
python tests/test_embedded_json.py
python tests/test_router.py
```

Optional integration checks use a **new** IDA 9.2 process, isolated user directory and disposable fixture. They do not replace installed plugins or use your open databases:

```powershell
msbuild tests/fixture.vcxproj /p:Configuration=Release /p:Platform=x64
python tests/test_native_ida.py --ida "C:\Program Files\IDA Professional 9.2\ida.exe"
```

The checks cover response contracts, bounds, request lifetime, queued cancellation, native fault quarantine, Python recovery, real Named Pipe routing and selected real IDA SDK paths. They do not establish crash freedom for all binaries.
