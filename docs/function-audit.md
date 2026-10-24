# Function audit ledger

This ledger tracks the public MCP tool handlers and shared execution boundaries reviewed for the reliability and model-facing API work. “Reviewed” means the handler was inspected and selected error/boundary cases were exercised; it does not promise that every IDA database or SDK condition is covered. Continue updating this file as the audit progresses.

## Public tool map

| Tool | Handler | Audit status |
| --- | --- | --- |
| `get_status` | `plugin/server/status_tracker.*`, router dispatch | Reviewed for status and transport behavior |
| `idb_save` | `plugin/tools/api_core/api_core.cpp` | Reviewed; native save path exercised |
| `get_segments` | `plugin/tools/api_core/api_core.cpp` | Reviewed |
| `get_exports` | `plugin/tools/api_core/api_core.cpp` | Reviewed; schema limit aligned |
| `imports_query` | `plugin/tools/api_core/api_core.cpp` | Reviewed |
| `get_bytes` | `plugin/tools/api_memory/api_memory.cpp` | Reviewed; strict size and mapped/loaded range checks added |
| `strings` | `plugin/tools/api_core/api_core.cpp` | Reviewed; pagination, malformed batch addresses, overflow-safe encoding heuristics, 64-result pages, and bounded string extraction/output checked |
| `find_bytes` | `plugin/tools/api_analysis/api_analysis.cpp` | Reviewed; scope, cursor, pattern, and count bounds; next-page lookahead added |
| `insn_query` | `plugin/tools/api_analysis/api_analysis.cpp` | Reviewed; scope, cursor, scan, and result bounds |
| `list_funcs` | `plugin/tools/api_core/api_core.cpp` | Reviewed |
| `list_globals` | `plugin/tools/api_core/api_core.cpp` | Reviewed |
| `decompile` | `plugin/tools/api_analysis/api_analysis.cpp` | Reviewed; batch/output/local-variable limits and truncation behavior added |
| `disasm` | `plugin/tools/api_analysis/api_analysis.cpp` | Reviewed; strict targets/counts and safe byte reads added |
| `basic_blocks` | `plugin/tools/api_analysis/api_analysis.cpp` | Reviewed; no automatic `add_func`, bounded CFG/instruction output |
| `xref_query` | `plugin/tools/api_analysis/api_analysis.cpp` | Reviewed; direction/type/cursor/count validation |
| `callgraph` | `plugin/tools/api_analysis/api_analysis.cpp` | Reviewed; traversal caps and schema limits aligned |
| `refactor` | `plugin/tools/api_modify/api_modify.cpp` | Reviewed; mutation scopes and partial-error receipts exercised; each item's edits are sequential, not transactional; optional refreshed pseudocode is capped at 512 KiB and reports truncation |
| `types` | `plugin/tools/api_types/api_types.cpp` | Reviewed; batch lookup no longer reparses rendered tool text |
| `stack_frame` | `plugin/tools/api_types/api_types.cpp` | Reviewed; BP displacement conversion and subtraction are checked for overflow |
| `rtti` | `plugin/tools/api_rtti/api_rtti.cpp` | Reviewed; bounded reads, overflow checks, and scan/output limits added |
| `survey_binary` | `plugin/tools/api_composite/api_composite.cpp` | Reviewed |
| `analyze_function` | `plugin/tools/api_composite/api_composite.cpp` | Reviewed; caller/callee limits match schema, sampled call-site lists identify truncation, scan caps report incomplete references |
| `trace_data_flow` | `plugin/tools/api_composite/api_composite.cpp` | Reviewed; unknown variables error, data-pointer reads check loaded bytes, and both Hex-Rays and fallback traversal report node/scan truncation |
| `make_signature` | `plugin/tools/api_sigmaker/api_sigmaker.cpp` | Reviewed; range and output limits added; segment scanner now includes matches at the final valid start when the first fixed byte is offset |
| `get_ast` | `plugin/tools/api_hexrays/api_hexrays.cpp` | Reviewed; one request-wide match cap (including database scans), lookahead-based truncation, bounded pattern grammar/depth, and bounded scan |
| `mba_simplify` | `plugin/tools/api_hexrays/api_hexrays.cpp` | Reviewed; custom rule shapes/depth/text are bounded, constant folding avoids signed overflow and masks result widths |
| `simplify_predicate` | `plugin/tools/api_hexrays/api_hexrays.cpp` | Reviewed; missing targets are explicit, batch schema is strict, persistence is opt-in, rel32 range conversion is checked |
| `py` | `plugin/tools/api_python/api_python.cpp`, `python_runner.h` | Reviewed; 30-minute deadline, cancellation, bounded output, and interpreter-state restoration exercised |
| `find_path` | `plugin/tools/api_analysis/api_analysis.cpp` | Reviewed; all paths share one node/edge budget, total and per-node edges are capped, vtable pointer reads and address math are checked, depth applies to the whole path |
| `reconstruct_struct` | `plugin/tools/api_types/api_types.cpp` | Reviewed; checked signed offsets/sizes, 2 MiB struct and 4096-field/context bounds, explicit missing-variable errors |
| `resolve_vcall` | `plugin/tools/api_rtti/api_rtti.cpp` | Reviewed; indices, offsets, vtable bounds, and method limits exercised |

## Shared boundaries

| Area | Location | Coverage |
| --- | --- | --- |
| Request validation and tool schemas | `shared/argument_validation.h`, `shared/ida_tools_schema.h` | Required fields, types, lengths, numeric bounds, strict unknown-field handling |
| Output formatting and size limits | `shared/model_output.h`, `plugin/tools/utils/utils.h` | Compact model-facing text, UTF-8 safety, 2 MiB result boundary |
| Dispatcher serialization and cancellation | `plugin/server/dispatcher.*`, `plugin/sync/*` | Main-thread execution, cancellation/deadline checkpoints, exception containment |
| Router transport and request handling | `router/router/ida_router.cpp` | Busy/deadline/cancel behavior, malformed request containment, response forwarding |
| Python runner state | `plugin/tools/api_python/python_runner.h` | Streams, argv, `sys.path`, trace hook, reserved module restoration, recursive/large values |
| GUI dialog suppression | `plugin/server/dispatcher.h` and `tests/test_native_ida.py` | Dispatcher enables IDA batch mode for every non-Python tool and restores the prior mode; Python keeps IDAPython cancellation. Native test starts with batch off and checks warning, button, file, string, text, address, segment, and number prompts from an IDB callback. |

## Verification commands

```powershell
& 'D:\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe' ida-mcp.sln /t:Build /p:Configuration=Release /p:Platform=x64 /m /v:minimal
python tests/test_native_ida.py --ida 'C:\Program Files\IDA Professional 9.2\ida.exe'
python -m unittest tests.test_python_runner tests.test_embedded_json tests.test_router -v
.\bin\Release\contract_tests.exe
.\bin\Release\dispatcher_tests.exe
```

### Latest audit pass

- `refactor` optional `include_code` used to accumulate all rendered pseudocode before the shared 2 MiB response guard. It now caps that field at 512 KiB and adds `code_truncated: true` when more pseudocode remains, avoiding an avoidable large allocation and generic whole-response failure. Removed an unused comment helper.
- `refactor` applies each requested edit sequentially and intentionally does not roll back a successful rename if a later type change fails. Added a native regression check that this returns `partial` at both item and local-variable level, so callers can detect the retained rename.
- `make_signature` segment scan passed a byte range ending at the last legal pattern start only when the first fixed byte was at offset zero. Expanded the `memchr` span by that offset so terminal-position matches are considered.
- `strings` auto-encoding detection compared UTF-16 and narrow string lengths using `l_c * 2`, which could wrap for extreme IDB lengths. Rewrote the equivalent comparison without multiplication.
- String search could materialize 2,000 arbitrarily long results before the shared output-size guard ran. Pages are now capped at 64, extraction at 8 KiB per string, and rendered text at 4 KiB per string with `string_truncated`; searches whose long candidate text was clipped report `truncated`. The schema and contract test enforce the page cap.
- `trace_data_flow`'s non-Hex-Rays fallback stopped after 100 visited addresses without identifying an incomplete graph, and a single node could expose an unbounded xref loop. It now reports truncation at the 100-node cap or 50,000 xref visits.
- Verified the changes with the direct Visual Studio MSBuild executable, the IDA 9.2 native suite, contract tests, Python/router suites, and `git diff --check`.

The current audit pass covers all listed public MCP tools and shared execution boundaries. Future defects should be added with a reproducer and regression test, and the affected row updated; no finite test suite can prove that every external IDA SDK or corrupted-IDB condition is crash-free.
