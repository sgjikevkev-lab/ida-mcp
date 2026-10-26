# IDA MCP

A native C++ MCP router and IDA Pro plugin for language-model agents. This repository is independent of Hex-Rays IDA Assist.

Original ida-mcp code is licensed under MIT; third-party components remain
under their own terms. See [LICENSE](LICENSE) and [NOTICE](NOTICE.md),
especially for the IDA SDK and statically linked RAX dependency.

The current release is **2.2.0**. It adds isolated x86-64 function emulation through the bundled RAX engine alongside machine-level register flow. The plugin targets Windows x64 and builds one DLL against the **IDA Pro 9.1 SDK** for the shared 9.1/9.2 API. SDK 9.2 is bundled in `plugin/!ibs/ida_92`; the local IDA 9.1 SDK belongs in `plugin/!ibs/ida_91` and is ignored by Git.

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

The router keeps protocol heartbeat requests responsive while a worker waits for IDA. Each open database has its own local pipe and dispatcher, so it can be enabled or disabled independently. A database dispatcher admits one active operation; IDA serializes the queued operations on its main thread.

The fixed operation deadline is **30 minutes**. Loops, recursive analysis and Python tracing check cancellation. MCP cancellation notifications are supported. The backend remains busy until an already-running operation actually stops; a timeout never falsely reports it idle. Native IDA calls and Python extensions cannot be forcibly interrupted safely in the GUI process.

Ordinary tools run in the SDK's unattended `batch` scope, with decompiler wait boxes disabled. IDA 9.2 does not suppress `ask_file` in batch mode, so ordinary tools also block that SDK request and return an empty path. Python retains IDAPython's interactive cancellation behavior. A caught native fault quarantines the backend. Inspect `get_status.last_fault`, then explicitly call `reset_quarantine` for a resettable read access violation, or restart IDA. Reset never retries the failed request and cannot repair corrupted process memory. Write/execute access violations, noncontinuable exceptions and other native fault classes require restarting IDA.

There is no guarantee against every native crash or unrelated third-party GUI callback. A hard stop for uninterruptible SDK code requires a separate process/database backend. See [architecture review](docs/architecture.md) for the ownership rules, discovered defects, changes and limits.

## Install

The project builds one plugin binary for both IDA 9.1 and 9.2, using the 9.1 SDK API subset shared by both versions. The local SDK must be present in `plugin/!ibs/ida_91`; there is no per-version build or fallback. IDA 9.2-only decompiler refresh functionality is omitted. The plugin and router are placed together in `bin/Release`.

```powershell
msbuild ida-mcp.sln /p:Configuration=Release /p:Platform=x64 /m
```

Build outputs:

- `bin/Release/ida_mcp64.dll` — the single IDA 9.1/9.2 plugin
- `bin/Release/router.exe` — MCP router

Install `bin/Release/ida_mcp64.dll` into the `plugins` directory used by both IDA versions, then restart IDA. RAX is statically linked into the plugin. Register `bin/Release/router.exe` as a stdio MCP server:

In IDA, choose **Edit → Plugins → IDA MCP** to open the compact per-database settings window. It displays the running IDA version; the animated switch applies and saves changes immediately. Closing the window keeps the current setting. When disabled, the database stays in the router's file list with `status: inactive`; MCP database tools are blocked for it. `get_status` also reports the host IDA version.

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
| `get_available_files` | Discover open binaries and show MCP state/IDA version |
| `switch_file` | Select the active database |
| `get_status` | Inspect execution state, elapsed time and IDA version |
| `reset_quarantine` | Explicitly clear a resettable idle quarantine, retaining the last native-fault diagnostic |
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
| `emulate_function` | Call an x86-64 function in a private guest with arguments, optional buffers and explicit external-call stubs |
| `py` | Run code or a script file with bounded stdout/stderr capture |

RAX is available where its machine-level view removes work for the model: `disasm` and `insn_query` can return per-instruction effects, `analyze_function` can add a compact aggregate with `semantic_summary: true`, and `trace_data_flow` supports bounded x86-64 register and exact-memory def-use across CFG blocks with `machine_level: true`. It tracks register slices, direct absolute or stable stack-slot aliases, and common x64 callee-saved registers across unknown calls; computed-pointer aliases and control dependencies remain outside the model. Unsupported effects and discarded state are reported. See [RAX integration notes](plugin/third_party/rax/README.md).

`emulate_function` runs a function in a private x86-64 user-mode guest using the Windows x64 ABI. It copies IDB segments into guest memory, defaults to 100,000 instructions, 5 seconds and 64 MiB of guest memory; hard caps are 5,000,000 instructions, 30 minutes and 256 MiB. Integer, floating-point, address and buffer arguments are supported; optional call stubs can provide a return value and bounded memory writes. Results contain only the return/stop summary and observed changed memory or buffers. Guest writes never modify the IDB. Unstubbed external calls and syscalls stop with a guest fault; the tool does not claim that one emulated path proves all function behavior.

Uninitialized IDB bytes are zero-filled in the private guest and reported through `uninitialized_bytes_zeroed` and `memory_assumption`; runtime initialization is not simulated. Signature generation instead scans only initialized byte ranges and never joins a pattern across an IDB hole.

Name filters accept `query` as an alias for `pattern` (`name` in `get_segments`). `list_funcs`, `list_globals`, `get_exports`, `imports_query` and `strings` also accept `name`. Supply one spelling per request. In `types` and `rtti`, `name` continues to inspect a specific type or class.

For real-binary regression checks, see [the test runner](tests/test_real_binary.py). It clones the supplied IDB and binary, launches a private IDA process, checks source SHA-256 hashes, and records requests/results and coverage in `bin/real-qa-*`.
The [real-binary report](docs/real-binary-qa.md) records the reproduced failures, final coverage and remaining limits for the supplied CS2 client database.

The tool catalog supplies exact arguments, bounds and descriptions. Analytical heuristics and traversal limits are not proofs of exhaustive behavior.

## Build and checks

Use Visual Studio with the v145 C++ toolset and Windows SDK. The solution contains the router and plugin; the plugin links the bundled Windows x86-64 RAX static library from `plugin/third_party/rax/lib/rax.lib` and does not need Git, Cargo/Rust, or network access to build.

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
