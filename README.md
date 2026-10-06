# IDA Pro MCP Server

A native C++ Model Context Protocol (MCP) server and plugin suite engineered for advanced, AI-assisted reverse engineering of Windows x64/x32 PE binaries.

> ### ⚠️ System Requirements & Compatibility
> - **Operating System**: Windows 10 or later (x64 only).
> - **IDA Pro Compatibility**: Tested **strictly on IDA Pro 9.2**. Stable behaviour is guaranteed solely on version 9.2; earlier releases (IDA 7.x / 8.x / 9.0) are unsupported due to internal SDK and Hex-Rays API changes.
> - **Compiler Toolset**: Built targeting MSVC **v145** (requires MSVC **v143** as an absolute minimum).

---

## 🏗 Architecture & Execution Flow

IDA Pro's database kernel and Hex-Rays decompiler are fundamentally single-threaded and bound to the primary GUI thread. Direct parallel invocations crash IDA's internal database structures. 

To overcome this whilst providing a responsive, non-blocking interface to modern AI agents, the project employs a decoupled two-tier architecture:

```
┌────────────────────────────────────────────────────────┐
│             AI Client (IDE / LLM / Agent)              │
└───────────────────────────┬────────────────────────────┘
                            │ JSON-RPC 2.0 (stdio)
                            ▼
┌────────────────────────────────────────────────────────┐
│                      router.exe                        │
│                                                        │
│  [Non-Blocking Stdio Loop]                             │
│       │                                                │
│       ├─► ping / get_status ──► [Instant Response]     │
│       │                         (< 0.1 ms directly)    │
│       │                                                │
│       └─► Heavy Tool Call   ──► [Async Worker Thread]  │
│                                       │                │
│                                       │ (Serialized)   │
│                                       ▼                │
│                            [IPC Transport Layer]       │
└───────────────────────────────────────┬────────────────┘
                                        │
                                        ▼
┌────────────────────────────────────────────────────────┐
│                   ida_mcp64.dll                        │
│             (Plugin inside IDA Pro 9.2)                │
│                                                        │
│  [execute_sync Dispatcher]                             │
│       │                                                │
│       ▼                                                │
│  [IDA Pro Main GUI Thread]                             │
│       ├─► Hex-Rays AST & Microcode Engine              │
│       ├─► Bidirectional BFS Path Search                │
│       ├─► MSVC RTTI Parser                             │
│       └─► IDB Type System & Struct Reconstructor       │
└────────────────────────────────────────────────────────┘
```

### Key Execution Highlights:
1. **Zero Stdio Blocking**: The router's standard input loop runs continuously. Long-running decompilation or path-finding operations are offloaded to dedicated background threads.
2. **Concurrent Liveness & Diagnostics**: Real-time diagnostic queries (`get_status`) and heartbeat pings (`ping`) are intercepted and resolved by the router in under **0.1 ms**, even whilst IDA Pro's engine is fully occupied with heavy computation.
3. **Collision Protection**: If an agent dispatches a concurrent tool invocation whilst an analysis is already in flight, the router returns an explicit, structured `busy` error detailing the active tool and its elapsed runtime, preventing database corruption.

---

## 🌐 Multi-Binary Context Switching

The router transparently coordinates multiple active IDA Pro sessions simultaneously. An AI agent can navigate an entire application ecosystem (e.g. executable and its supporting dynamic libraries) dynamically:

```
┌───────────────────────────┐
│     AI Agent Session      │
└─────────────┬─────────────┘
              │ 1. get_available_files
              ▼
┌───────────────────────────┐
│       router.exe          │ ──► Returns: ["game.exe", "engine.dll", "network.dll"]
└─────────────┬─────────────┘
              │ 2. switch_file("engine.dll")
              ▼
┌───────────────────────────┐
│ Context switched to       │ ──► Subsequent tool calls execute against engine.dll
│ active engine.dll session │
└───────────────────────────┘
```

The agent discovers open databases, monitors their status, and switches working context on the fly without session restarts or manual configuration.

---

## 🔬 In-Depth Mechanics of Complex Tools

### 1. `find_path` — Frontier-Balanced Bidirectional BFS
- **The Challenge**: Standard Depth-First Search (DFS) or naive Breadth-First Search (BFS) suffers from exponential state explosion in production binaries containing 200,000+ functions. Arbitrary hub-skipping heuristics lead to false negatives and missed critical code paths.
- **The Implementation**:
  - **Balanced Bidirectional Expansion**: Traverses forward from the source function (following call instructions and tail-call branches) and backward from the destination function (following incoming code cross-references `CodeRefsTo`).
  - **Dynamic Frontier Balancing**: At each iteration, the algorithm assesses the size of both frontiers and expands exclusively the smaller frontier, drastically reducing the search space.
  - **Tail-Call (`jmp`) Resolution**: Automatically detects indirect and direct jumps targeting function entry boundaries, treating them as tail calls rather than terminating blocks.
  - **Performance**: Delivers a **100% path discovery rate** (zero false negatives) across 286,000+ functions with typical response latencies between **1 and 3 milliseconds**.

---

### 2. `reconstruct_struct` — AST Memory Layout Inferrer
- **The Challenge**: Reconstructing complex C++ structures from raw stripped binaries typically demands hours of manual cross-referencing to deduce member boundaries, variable types, and alignment padding.
- **The Implementation**:
  - **AST Displacement Mapping**: Traverses the Hex-Rays Abstract Syntax Tree (`cfunc_t`) to capture all pointer arithmetic, array indexing, and member dereferences (`*(type*)(ptr + offset)`).
  - **Allocation Sniffing**: Inspects dynamic memory allocation call sites (`operator new`, `malloc`) linked to the object pointer to verify total memory allocation bounds.
  - **Zero-Initialisation Heuristics**: Detects and parses `memset(ptr, 0, size)` invocations to establish initialisation boundaries.
  - **Sub-Component Offset Shifting**: Tracks pointer offsets when nested sub-objects or inherited classes are passed into subroutines, correctly projecting nested offsets back into the root structure.
  - **Trailing Padding Synthesiser**: Automatically calculates internal alignment gaps and synthesises trailing padding fields (`_pad_tail`) to ensure the reconstructed C/C++ definition accurately mirrors memory layout.

---

### 3. `resolve_vcall` — MSVC RTTI Complete Object Locator
- **The Challenge**: Virtual function calls (`rax->vtable[index]()`) obscure concrete control flow in decompiled C++ output.
- **The Implementation**:
  - **RTTI Header Extraction**: Locates the virtual method table (`vftable`) in read-only memory and extracts the `RTTICompleteObjectLocator` descriptor located at `vftable[-1]`.
  - **Hierarchy Reconstitution**: Traverses the MSVC `TypeDescriptor`, `ClassHierarchyDescriptor`, and `BaseClassArray` to reconstruct full multi-inheritance and virtual inheritance chains.
  - **Virtual Method Indexing**: Parses sequential function pointers in the virtual table, correlating slot indices, virtual memory addresses, and relative displacement offsets to provide exact function targets for indirect call sites.

---

### 4. `mba_simplify` & `simplify_predicate` — AST & Decompiler De-obfuscation
- **The Challenge**: Obfuscated binaries employ Mixed Boolean-Arithmetic (MBA) expressions, opaque predicates, and synthetic dead-code branches to thwart decompilation and human analysis.
- **The Implementation**:
  - **ctree AST Analysis**: Operates directly on Hex-Rays Abstract Syntax Tree expressions (`cfunc_t`, `cexpr_t`, `cinsn_t`), avoiding brittle textual regexes while inspecting high-level decompiled expressions.
  - **Multi-Level MBA Simplification**: Implements a 3-tier simplification pipeline:
    1. *Rule-based AST rewriting*: Recognises canonical MBA identities (e.g. `(x ^ y) + 2*(x & y) => x + y`, `(x | y) - y => x & ~y`).
    2. *Constant folding*: Recursively folds compile-time known constants across nested bitwise and arithmetic operations.
    3. *Truth-table equivalence*: Evaluates single-variable bitwise expressions across permutations to prove functional identity.
  - **Opaque Predicate Elimination & IDB Patching**:
    - Discovers invariant conditions evaluating unconditionally to `always_true` or `always_false`.
    - Eliminates dead branches directly within the Hex-Rays AST pseudocode.
    - Optionally persists patches into the IDA database (`persist: true`), accurately rewriting short (`0x7x`) and near (`0x0F 0x8x`) conditional jumps into unconditional jumps (`0xEB`, `0xE9`) or NOPs (`0x90`), recalculating displacement offsets and preserving branch polarity.

---

## 📦 Setup & Connection

Pre-compiled production binaries (`router.exe` and `ida_mcp64.dll`) are provided in the [Releases](https://github.com/sgjikevkev-lab/ida-mcp/releases) section.

### 1. Plugin Installation
Place `ida_mcp64.dll` into your IDA Pro `plugins` directory:
```
C:\Program Files\IDA Professional 9.2\plugins\ida_mcp64.dll
```
The plugin initialises automatically whenever IDA Pro starts.

### 2. Client Configuration
Store `router.exe` in a persistent directory (e.g. `C:\Tools\ida-mcp\router.exe`) and register it in your `mcp_config.json`:

```json
{
  "mcpServers": {
    "ida-pro": {
      "command": "C:\\Tools\\ida-mcp\\router.exe"
    }
  }
}
```

---

## 🛠 Available Tools Reference

| Tool | Category | Description |
| :--- | :--- | :--- |
| `get_status` | Router & Diagnostics | Non-blocking diagnostic health check (< 0.1 ms); reports active tool, elapsed time, and IDB status even during heavy execution. |
| `get_available_files` | Router & Diagnostics | Discovers all active IDA Pro instances and open databases across the operating system. |
| `switch_file` | Router & Diagnostics | Switches the active router context to another running IDA Pro database on the fly with fuzzy matching. |
| `idb_save` | Binary & Core | Flushes and saves the active database (`.idb` / `.i64`) to disk. |
| `get_segments` | Binary & Core | Enumerates all memory segments with start/end boundaries, sizes, and R/W/X permissions. |
| `get_exports` | Binary & Core | Lists all exported functions, symbols, and entry points defined within the binary. |
| `imports_query` | Binary & Core | Queries imported modules and API functions with pattern filtering and cursor pagination. |
| `survey_binary` | Binary & Core | Produces a comprehensive structural summary of compilers, libraries, sections, and entry points. |
| `get_bytes` | Memory & Search | Reads raw memory bytes at a designated virtual address as hexadecimal data. |
| `strings` | Memory & Search | Unified string reader and search: retrieves strings at single or batch addresses, or searches binary literals by pattern/regex. |
| `find_bytes` | Memory & Search | Searches executable memory for byte sequences containing wildcard patterns (`?`). |
| `list_funcs` | Functions & Analysis | Lists defined functions with boundary addresses, sizes, frame sizes, flags, and cursor pagination. |
| `list_globals` | Functions & Analysis | Enumerates global data items and variables within specified segments with name filtering. |
| `analyze_function` | Functions & Analysis | Conducts deep function inspection: calling convention, arguments, variables, and cross-references. |
| `disasm` | Functions & Analysis | Disassembles sequential instructions or batch targets with optional mnemonic filtering. |
| `insn_query` | Functions & Analysis | Searches instructions by mnemonic across the binary or within a specified function. |
| `basic_blocks` | Functions & Analysis | Retrieves CFG basic blocks, successor/predecessor edges, loop detection, branch conditions (`jnz`, `jz`), and cyclomatic complexity. |
| `xref_query` | Functions & Analysis | Queries code/data cross-references enriched with caller function details and argument preparation assembly (`context_asm`). |
| `callgraph` | Functions & Analysis | Generates forward or reverse call trees up to a specified recursion depth. |
| `find_path` | Functions & Analysis | Frontier-balanced Bidirectional BFS algorithm calculating execution call chains between functions. |
| `decompile` | Hex-Rays & Decompiler | Decompiles target function(s) into clean C pseudocode with attached local variables and types. |
| `get_ast` | Hex-Rays & Decompiler | Serializes Hex-Rays ctree AST to structured JSON, or performs structural pattern matching with commutative logic. |
| `mba_simplify` | Hex-Rays & Decompiler | Simplifies Mixed Boolean-Arithmetic (MBA) and bitwise expressions in Hex-Rays AST via pattern rules and constant folding. |
| `simplify_predicate` | Hex-Rays & Decompiler | Detects opaque predicates, eliminates dead AST branches in pseudocode, and optionally patches Jcc in IDB. |
| `types` | Types & Structures | Unified type manager: inspect struct/union/enum definitions, search TIL types, batch inspect, or declare new C types. |
| `stack_frame` | Types & Structures | Inspects stack frame layout: local variables, argument offsets, saved registers, and return address. |
| `reconstruct_struct` | Types & Structures | Reconstructs C struct definitions by analyzing memory accesses, allocations, member offsets, and padding. |
| `rtti` | RTTI & Polymorphism | Unified MSVC RTTI inspector: lists polymorphic classes, inspects class hierarchies/vtables, and generates TIL structs. |
| `resolve_vcall` | RTTI & Polymorphism | Resolves virtual method invocations to concrete function implementations via vtable indexing. |
| `refactor` | Modification & Refactor | Unified batched refactoring: rename functions/globals/lvars, apply C types/prototypes, manage comments, and auto-recompile in synchronized transactions. |
| `make_signature` | Utilities | Generates unique byte pattern signatures (shortest resilient or function entry) with wildcard operands. |
| `trace_data_flow` | Utilities | Deep inter-procedural data flow tracking: variable identity via `lvar_idx`, pointer alias analysis, abstract memory locations (`Memory[obj+off]`), and path-sensitive conditions. |
| `py` | Utilities | Executes arbitrary IDAPython snippets or expressions inside IDA's main thread and captures stdout/stderr. |
