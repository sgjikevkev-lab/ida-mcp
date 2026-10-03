# IDA Pro MCP Server

A native C++ Model Context Protocol (MCP) server and plugin suite designed for AI-assisted reverse engineering of Windows x64/x32 PE binaries.

> ### ⚠️ System Requirements & Compatibility
> - **Operating System**: Windows 10 or later (x64 only).
> - **IDA Pro Compatibility**: Tested **strictly on IDA Pro 9.2**. Stable behaviour is guaranteed solely on version 9.2; earlier releases (IDA 7.x / 8.x / 9.0) are unsupported due to internal SDK and Hex-Rays API changes.
> - **Compiler Toolset**: Built targeting MSVC **v145** (requires MSVC **v143** as an absolute minimum).

---

## 🌐 Multi-Binary Support

The central router seamlessly supports multiple simultaneously open binaries across active IDA Pro sessions. An AI agent can independently query all open databases (`get_available_files`) and switch its working context between different binaries (`switch_file`) on the fly without session restarts or manual intervention.

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

## 🛠 Available Tools

| Tool | Category | Description |
| :--- | :--- | :--- |
| `get_status` | Router & Diagnostics | Non-blocking diagnostic health check (< 0.1 ms); reports active tool, elapsed time, and IDB status. |
| `get_available_files` | Router & Diagnostics | Discovers all active IDA Pro instances and open databases across the operating system. |
| `switch_file` | Router & Diagnostics | Switches the active router context to another running IDA Pro database on the fly. |
| `idb_save` | Binary & Core | Flushes and saves the active database (`.idb` / `.i64`) to disk. |
| `get_segments` | Binary & Core | Enumerates all memory segments with start/end boundaries, sizes, and R/W/X permissions. |
| `get_exports` | Binary & Core | Lists all exported functions, symbols, and entry points defined within the binary. |
| `imports_query` | Binary & Core | Queries imported modules and API functions with pattern filtering and cursor pagination. |
| `survey_binary` | Binary & Core | Produces a comprehensive structural summary of compilers, libraries, sections, and entry points. |
| `get_bytes` | Memory & Search | Reads raw memory bytes at a designated virtual address as hexadecimal data. |
| `get_string` | Memory & Search | Retrieves null-terminated ASCII or UTF-8 string literals from a specific address. |
| `search_strings` | Memory & Search | Scans binary string literals matching substrings, globs, or regular expressions. |
| `find_bytes` | Memory & Search | Searches executable memory for byte sequences containing wildcard patterns. |
| `list_funcs` | Functions & Analysis | Lists defined functions with boundary addresses, sizes, frame sizes, and flags. |
| `list_globals` | Functions & Analysis | Enumerates global data items and variables within specified segments. |
| `analyze_function` | Functions & Analysis | Conducts deep function inspection: calling convention, arguments, variables, and cross-references. |
| `disasm` | Functions & Analysis | Disassembles instructions within a specified address range. |
| `insn_query` | Functions & Analysis | Decodes single assembly instructions into structured operands and mnemonic details. |
| `basic_blocks` | Functions & Analysis | Retrieves Control Flow Graph (CFG) basic blocks, jump targets, and edge types. |
| `xref_query` | Functions & Analysis | Retrieves incoming and outgoing code and data cross-references. |
| `callgraph` | Functions & Analysis | Generates forward or reverse call trees up to a specified recursion depth. |
| `find_path` | Functions & Analysis | Frontier-balanced Bidirectional BFS algorithm calculating call paths between functions. |
| `decompile` | Hex-Rays & Decompiler | Decompiles target functions into clean C pseudocode. |
| `recompile` | Hex-Rays & Decompiler | Forces cache invalidation and recompilation of a previously decompiled function. |
| `get_ast` | Hex-Rays & Decompiler | Extracts structured Abstract Syntax Trees (cfunc / citem) from decompiled code. |
| `ast_match` | Hex-Rays & Decompiler | Matches structural patterns against Hex-Rays AST expressions. |
| `mba_simplify` | Hex-Rays & Decompiler | Inspects Microcode Block Architecture (MBA) graphs and applies optimisation passes. |
| `simplify_predicate` | Hex-Rays & Decompiler | Detects and simplifies opaque predicates and dead branches in microcode. |
| `declare_type` | Types & Structures | Parses and registers forward C declarations, typedefs, or struct definitions into Local Types. |
| `type_query` | Types & Structures | Searches the type library for registered structs, enums, unions, and typedefs. |
| `type_inspect` | Types & Structures | Inspects struct definitions: field names, types, offsets, sizes, and alignment padding. |
| `read_struct` | Types & Structures | Decodes memory at a given address according to a registered structure layout. |
| `stack_frame` | Types & Structures | Details stack frame layouts: local variables, saved registers, and return addresses. |
| `reconstruct_struct` | Types & Structures | Reconstructs struct layouts by analysing memory accesses, allocations, and offsets. |
| `rtti_list_classes` | RTTI & Polymorphism | Scans MSVC RTTI Complete Object Locators and enumerates polymorphic class definitions. |
| `rtti_get_class` | RTTI & Polymorphism | Retrieves class inheritance hierarchies, base class descriptors, and virtual function tables. |
| `rtti_create_struct` | RTTI & Polymorphism | Automatically converts discovered RTTI class layouts and vtables into IDA structure definitions. |
| `resolve_vcall` | RTTI & Polymorphism | Resolves virtual method invocations to concrete function implementations via vtable indexing. |
| `rename` | Modification | Renames functions, global variables, or labels. |
| `set_type` | Modification | Applies a C-style type signature to a function or variable. |
| `set_comment` | Modification | Adds regular or repeatable comments at a given virtual address. |
| `rename_lvar` | Modification | Renames local variables within decompiled function scopes. |
| `set_lvar_type` | Modification | Assigns C types to local variables within decompiled functions. |
| `make_signature` | Utilities | Generates unique byte pattern signatures with wildcards for target functions. |
| `trace_data_flow` | Utilities | Performs intra-procedural data flow tracking across registers and memory locations. |
| `py` | Utilities | Executes arbitrary IDAPython snippets in IDA's main thread and captures output. |
