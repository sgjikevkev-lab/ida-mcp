#pragma once
#pragma warning(push, 0)
#pragma warning(disable: 26819 26495 26812 26451 6001 6011)
#include "json.h"
#pragma warning(pop)

namespace mcp {
    using json = nlohmann::json;

    inline const json& GetDefaultIdaToolsSchema() {
        static const json kIdaTools = json::parse(R"schema([
            {
                "name": "get_status",
                "description": "Check IDA Pro availability and active database status.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "idb_save",
                "description": "Flush and save active IDA Pro database (.idb/.i64) to disk. Returns database path, file size, and status.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "compact": {"type": "boolean", "description": "Collect garbage and compact the database during save (default false)"},
                        "backup": {"type": "boolean", "description": "Create a backup file (.bak) alongside the database (default false)"},
                        "outfile": {"type": "string", "description": "Optional custom output file path to save database to"}
                    }
                }
            },
            {
                "name": "get_segments",
                "description": "List binary memory segments with start/end addresses, sizes, and R/W/X permissions. Optionally filter by segment name or address.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Optional segment name or glob pattern filter (e.g. '.text' or '*data*')"
                        },
                        "addr": {
                            "type": "string",
                            "description": "Optional address (hex or symbol); if provided, returns only the segment containing this address"
                        }
                    }
                }
            },
            {
                "name": "get_exports",
                "description": "List exported functions and symbols with optional pattern, address, or ordinal filtering, automatic C++ demangling, and pagination.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "description": "Optional symbol or demangled name glob pattern filter (e.g. '*Create*' or 'NvCloth*')"
                        },
                        "addr": {
                            "type": "string",
                            "description": "Optional function address (hex or symbol); if provided, returns only the export at this address"
                        },
                        "ordinal": {
                            "type": "integer",
                            "description": "Optional export ordinal number"
                        },
                        "demangle": {
                            "type": "boolean",
                            "description": "Whether to demangle C++ export names (default true)"
                        },
                        "offset": {
                            "type": "integer",
                            "description": "Pagination offset (default 0)"
                        },
                        "count": {
                            "type": "integer",
                            "description": "Maximum number of exports to return (default 100, max 2000)"
                        }
                    }
                }
            },
            {
                "name": "imports_query",
                "description": "Search imported libraries and API functions with module filter, symbol filter, address lookup, or list imported module names.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "module": {
                            "type": "string",
                            "description": "Optional module name filter pattern with wildcards (e.g. 'kernel32*' or 'USER32')"
                        },
                        "pattern": {
                            "type": "string",
                            "description": "Optional imported symbol pattern with wildcards (e.g. '*CreateFile*')"
                        },
                        "addr": {
                            "type": "string",
                            "description": "Optional IAT address (hex or symbol); if provided, returns only the import at this address"
                        },
                        "modules_only": {
                            "type": "boolean",
                            "description": "If true, returns only the list of all imported module/DLL names"
                        },
                        "offset": {
                            "type": "integer",
                            "description": "Pagination offset (default 0)"
                        },
                        "count": {
                            "type": "integer",
                            "description": "Max entries to return (default 50, max 1000)"
                        }
                    }
                }
            },
            {
                "name": "get_bytes",
                "description": "Read raw bytes from memory at specified address. Returns hex string and ASCII representation. To search memory for a byte pattern, use 'find_bytes'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Memory address (hex '0x140001000', integer, or symbol name like 'main')"},
                        "size": {"type": "integer", "description": "Number of bytes to read (default 32, max 4096)"}
                    },
                    "required": ["addr"]
                }
            },
            {
                "name": "strings",
                "description": "Unified string tool for IDA Pro. Read string literal at address ('addr'), batch read strings across multiple addresses ('addrs'), or search string literals across entire binary IDB by pattern/regex ('pattern').",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Memory address to read string from (hex '0x140001000' or symbol)"},
                        "addrs": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Batch of memory addresses to read strings from"
                        },
                        "pattern": {"type": "string", "description": "Search string literals across binary by substring, glob ('*text*'), or regex (default '*' when searching)"},
                        "type": {"type": "string", "description": "String encoding type: 'auto' (default), 'ascii', 'utf-8', 'utf-16', 'utf-32', or 'pascal'"},
                        "rebuild": {"type": "boolean", "description": "Force full rescan of IDB strings list when searching (default false)"},
                        "cursor": {"type": "string", "description": "Cursor address for pagination from previous next_cursor"},
                        "offset": {"type": "integer", "description": "Pagination offset (default 0)"},
                        "count": {"type": "integer", "description": "Maximum strings to return (default 100, max 2000)"}
                    }
                }
            },
            {
                "name": "find_bytes",
                "description": "Search memory for byte pattern with wildcards ('?' or '??'). Supports hex ('48 89 5C', '0x48', '\\x48'), continuous hex ('48895C'), and scope filtering by segment, function, or range. To read known bytes at an address, use 'get_bytes'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "Byte pattern with '?' wildcards (e.g. '48 89 5C 24 ? 55' or '48895C24??55')"},
                        "segment": {"type": "string", "description": "Optional segment name to restrict search (e.g. '.text')"},
                        "func": {"type": "string", "description": "Optional function name or address to restrict search to a single function"},
                        "start": {"type": "string", "description": "Optional start address for search range"},
                        "end": {"type": "string", "description": "Optional end address for search range"},
                        "cursor": {"type": "string", "description": "Cursor address for pagination from previous next_cursor"},
                        "offset": {"type": "integer", "description": "Index offset for pagination (default 0)"},
                        "count": {"type": "integer", "description": "Max matches to return (default 50, max 1000)"}
                    },
                    "required": ["pattern"]
                }
            },
            {
                "name": "insn_query",
                "description": "Search instructions by mnemonic (e.g. 'call', 'syscall', 'xor') and/or disassembly text pattern ('*eax, eax*') with cursor pagination. For sequential disassembly of a function, use 'disasm'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "mnemonic": {"type": "string", "description": "Instruction mnemonic filter (e.g. 'call', 'syscall', 'xor', default '*' for all)"},
                        "query": {"type": "string", "description": "Disassembly text filter/glob (e.g. '*eax, eax*', '*qword ptr*')"},
                        "func": {"type": "string", "description": "Optional function name or address (hex '0x140001000') to restrict search to a single function"},
                        "segment": {"type": "string", "description": "Optional segment name to restrict search (e.g. '.text')"},
                        "start": {"type": "string", "description": "Optional start address for search range"},
                        "end": {"type": "string", "description": "Optional end address for search range"},
                        "cursor": {"type": "string", "description": "Cursor address to continue search from previous next_cursor"},
                        "count": {"type": "integer", "description": "Max instructions to return (default 50, max 1000)"},
                        "max_scan": {"type": "integer", "description": "Maximum instructions to scan in one pass before returning (default 250000)"}
                    }
                }
            },
            {
                "name": "list_funcs",
                "description": "List and filter functions across binary by name pattern ('*name*') and byte size range with cursor pagination. Matches both raw and demangled C++ signatures. For an in-depth summary of a single function, use 'analyze_function'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "Function name filter (substring, glob '*Render*', or regex). Matches both raw and demangled C++ names."},
                        "named_only": {"type": "boolean", "description": "Filter out auto-generated sub_ functions, returning only named/user symbols (default false)"},
                        "no_thunks": {"type": "boolean", "description": "Filter out stub/thunk functions (default false)"},
                        "demangle": {"type": "boolean", "description": "Automatically demangle C++ symbol names (default true)"},
                        "min_size": {"type": "integer", "description": "Minimum function size in bytes"},
                        "max_size": {"type": "integer", "description": "Maximum function size in bytes"},
                        "cursor": {"type": "string", "description": "Cursor address for pagination from previous next_cursor"},
                        "offset": {"type": "integer", "description": "Function index offset for pagination (default 0)"},
                        "count": {"type": "integer", "description": "Max functions to return (default 100, max 2000)"}
                    }
                }
            },
            {
                "name": "list_globals",
                "description": "List global variables, tables, and data symbols with name pattern filter, segment filter, and cursor pagination. Matches raw and demangled C++ names.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "Symbol name filter (substring, glob '*Config*', or regex). Matches raw and demangled names."},
                        "segment": {"type": "string", "description": "Filter by segment name (e.g. '.data', '.rdata', '.bss')"},
                        "data_only": {"type": "boolean", "description": "Exclude code-segment symbols and return only symbols in data/bss segments (default false)"},
                        "writable_only": {"type": "boolean", "description": "Filter to writable variables only, excluding read-only constants (default false)"},
                        "demangle": {"type": "boolean", "description": "Automatically demangle C++ symbol names (default true)"},
                        "include_code_labels": {"type": "boolean", "description": "Include compiler switch jump tables (jpt_) and case labels (default false)"},
                        "cursor": {"type": "string", "description": "Cursor address for pagination from previous next_cursor"},
                        "offset": {"type": "integer", "description": "Global symbol index offset for pagination (default 0)"},
                        "count": {"type": "integer", "description": "Max symbols to return (default 100, max 2000)"}
                    }
                }
            },
            {
                "name": "decompile",
                "description": "Decompile target function(s) to clean Hex-Rays C pseudocode. Automatically returns local variable declarations and types table in 'lvars'. Supports single function ('addr') or batch decompilation across multiple functions ('addrs').",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Single function address (hex '0x140001000', integer, or symbol name like 'PreRender')"},
                        "addrs": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Batch of function addresses or symbol names to decompile in a single call"
                        }
                    }
                }
            },
            {
                "name": "disasm",
                "description": "Disassemble sequential instructions starting from address, or batch disassemble at multiple target addresses. Supports mnemonic filtering ('mnemonic': 'call'), optional opcode bytes, function metadata, and pagination cursor. To search for instructions across binary, use 'insn_query'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Start address (hex '0x140001000', integer, or symbol name like 'main')"},
                        "targets": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Batch of target addresses to disassemble around (e.g. call sites from xrefs)"
                        },
                        "mnemonic": {"type": "string", "description": "Optional mnemonic filter (e.g. 'call', 'jmp', 'xor') to filter returned instructions"},
                        "count": {"type": "integer", "description": "Number of instructions to disassemble (default 50 for single, default 5 per batch target, max 1000)"},
                        "bytes": {"type": "boolean", "description": "Include instruction opcode hex bytes in disassembly lines (default false)"},
                        "stop_at_func_end": {"type": "boolean", "description": "If true and start address is inside a function, stop disassembling at function end. If false, continue linearly across function boundaries (default true)"},
                        "detailed": {"type": "boolean", "description": "Include structured 'items' array with address, size, bytes, and disasm (default false)"}
                    }
                }
            },
            {
                "name": "basic_blocks",
                "description": "Extract Control Flow Graph (CFG) basic blocks for a function, including address ranges, block types, successor/predecessor edges, loop detection ('is_loop_header', 'is_back_edge'), conditional branch resolution ('branch' with true/false targets and condition), cyclomatic complexity, and optional disassembly.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Function address (hex '0x140001000', integer, or symbol name)"},
                        "no_external": {"type": "boolean", "description": "Exclude external jump target blocks from CFG (default false)"},
                        "include_instructions": {"type": "boolean", "description": "Include disassembly instructions for each basic block (default false)"}
                    },
                    "required": ["addr"]
                }
            },
            {
                "name": "xref_query",
                "description": "Query cross-references to or from an address with code/data/call/read/write filtering. Automatically enriches code references with preceding argument preparation instructions ('context_asm') and caller function offset details ('caller_func', 'caller_offset').",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Target address (hex '0x140001000', integer, or symbol name)"},
                        "direction": {"type": "string", "enum": ["to", "from", "both"], "description": "XREF direction: 'to' (incoming references), 'from' (outgoing references), or 'both' (default 'to')"},
                        "type": {"type": "string", "description": "Filter by XREF type: 'all', 'code', 'data', 'call', 'jump', 'read', 'write', 'offset' (default 'all')"},
                        "include_flow": {"type": "boolean", "description": "Include ordinary execution flow (fall-through to next instruction) xrefs (default false)"},
                        "cursor": {"type": "string", "description": "Pagination cursor from previous next_cursor or integer offset"},
                        "offset": {"type": "integer", "description": "Result offset index for pagination (default 0)"},
                        "count": {"type": "integer", "description": "Max XREFs to return (default 100, max 2000)"}
                    },
                    "required": ["addr"]
                }
            },
            {
                "name": "callgraph",
                "description": "Generate caller-callee execution graph starting from a root function with directional traversal (callees/callers/both), depth limit, demangled C++ names, and call site tracking.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Root function address (hex '0x140001000', integer, or symbol name)"},
                        "direction": {"type": "string", "enum": ["callees", "callers", "both"], "description": "Traversal direction: 'callees' (functions called by root), 'callers' (functions that call root), or 'both' (default 'callees')"},
                        "depth": {"type": "integer", "description": "Maximum call tree traversal depth (1..10, default 3)"},
                        "max_nodes": {"type": "integer", "description": "Maximum nodes to traverse in graph (default 500, max 2000)"},
                        "include_nodes": {"type": "boolean", "description": "Include structured 'nodes' array with metadata in response (default true)"}
                    },
                    "required": ["addr"]
                }
            },
            {
                "name": "refactor",
                "description": "Unified and atomic refactoring tool for IDA Pro. Modifies function names, global symbols in .data/.bss, types/prototypes, instruction comments, function comments, and decompilation local variables (lvars). Supports batching across multiple items in a single IDB transaction and automatically recompiles affected functions, returning fresh C pseudocode without secondary calls.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target address (hex '0x140001000' or integer) or symbol name to modify"},
                        "addr": {"type": "string", "description": "Alias for target"},
                        "name": {"type": "string", "description": "New symbol name for target (or leave empty if reset_name is true)"},
                        "reset_name": {"type": "boolean", "description": "Reset name to default auto-generated name (e.g. sub_... or dword_...)"},
                        "type": {"type": "string", "description": "New C type or function prototype declaration (e.g. 'int __fastcall(void *ctx, int len)')"},
                        "comment": {"type": "string", "description": "Comment text to set on target address or function"},
                        "repeatable": {"type": "boolean", "description": "Whether comment is repeatable (default false)"},
                        "func_comment": {"type": "boolean", "description": "Whether comment applies to function header (default false)"},
                        "clear_comment": {"type": "boolean", "description": "Whether to remove existing comment (default false)"},
                        "lvars": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string", "description": "Current local variable name (or specify 'index')"},
                                    "index": {"type": "integer", "description": "Optional local variable index (0-based)"},
                                    "new_name": {"type": "string", "description": "New name for local variable"},
                                    "type": {"type": "string", "description": "New C type for local variable"}
                                }
                            },
                            "description": "List of local variable modifications (renaming and retyping) for target function"
                        },
                        "comments": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "addr": {"type": "string", "description": "Instruction address"},
                                    "comment": {"type": "string", "description": "Comment text"},
                                    "repeatable": {"type": "boolean", "description": "Repeatable comment flag"}
                                },
                                "required": ["addr", "comment"]
                            },
                            "description": "Batch of instruction comments within target function"
                        },
                        "items": {
                            "type": "array",
                            "items": {"type": "object"},
                            "description": "Batch mode: array of modification items, each with 'target' and any combination of 'name', 'type', 'comment', 'lvars', 'comments'"
                        }
                    }
                }
            },
            {
                "name": "types",
                "description": "Unified type manipulation tool for IDA Pro. Handles compiling new C structs/unions/enums into TIL ('c_code'), inspecting struct definitions with field offsets and member types ('name' or 'names'), searching registered types across TILs ('pattern' or 'query'), and interpreting raw memory at address as a typed struct instance ('addr' + 'name').",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "c_code": {"type": "string", "description": "C source declarations to compile into TIL (e.g. 'struct Player { int hp; float pos[3]; };')"},
                        "name": {"type": "string", "description": "Type name to inspect, or struct type name to decode memory at 'addr'"},
                        "names": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Batch of type names to inspect in a single call"
                        },
                        "addr": {"type": "string", "description": "Memory address to interpret as struct instance (requires 'name')"},
                        "pattern": {"type": "string", "description": "Search pattern for types in TIL (e.g. '*Vector*' or '*Entity*')"},
                        "kind": {"type": "string", "enum": ["all", "struct", "union", "enum", "typedef", "function"], "description": "Filter by type kind when searching"},
                        "pack": {"type": "integer", "description": "Alignment pack value for c_code: 1, 2, 4, 8, 16"},
                        "cursor": {"type": "string", "description": "Pagination cursor for type searching"},
                        "offset": {"type": "integer", "description": "Pagination offset (default 0)"},
                        "count": {"type": "integer", "description": "Max results to return (default 50)"}
                    }
                }
            },
            {
                "name": "stack_frame",
                "description": "Inspect stack frame layout of a function: argument offsets, local variables, return address, signed frame pointer displacements (e.g. '[rbp-18h]'), variable categories, and Hex-Rays decompiler local variables with register allocations.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Function address (hex '0x140001000', integer, or symbol name)"},
                        "include_lvars": {"type": "boolean", "description": "Include Hex-Rays decompiler local variables (lvars) with C types and register locations (default true)"}
                    },
                    "required": ["addr"]
                }
            },
            {
                "name": "rtti",
                "description": "Unified C++ RTTI tool for IDA Pro. Discover and list MSVC RTTI classes with inheritance and method counts ('pattern', 'base_class'), inspect detailed class metadata and virtual tables ('name' or 'class' or 'addr'), generate class and vtable C struct into TIL ('create_struct': true), or force cache refresh ('refresh': true).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Class name (e.g. 'std::exception') or address (vtable, method, or RTTI descriptor) to inspect"},
                        "class": {"type": "string", "description": "Alternative alias for class name to inspect or create struct for"},
                        "addr": {"type": "string", "description": "Alternative address to lookup class from"},
                        "pattern": {"type": "string", "description": "Class name pattern filter with optional wildcards (e.g. '*Camera*', '*Player*') when listing"},
                        "base_class": {"type": "string", "description": "Filter classes inheriting from base class (e.g. 'Entity', 'std::exception') when listing"},
                        "min_methods": {"type": "integer", "description": "Filter classes having at least this many virtual methods"},
                        "sort": {"type": "string", "description": "Sort order: 'name' (alphabetical) or 'methods' (descending by method count, default 'name')"},
                        "count": {"type": "integer", "description": "Max classes to return per page (default 50, max 500)"},
                        "offset": {"type": "integer", "description": "0-based offset for pagination"},
                        "refresh": {"type": "boolean", "description": "Force cache invalidation and fresh scan of RTTI structures"},
                        "create_struct": {"type": "boolean", "description": "If true, generates C++ class structure and vtable struct in IDA Type Library (TIL)"},
                        "struct_name": {"type": "string", "description": "Optional custom name for the generated structure"},
                        "apply_to_vtable": {"type": "boolean", "description": "If true, applies the created vtable struct type directly to the vtable in IDB"}
                    }
                }
            },
            {
                "name": "survey_binary",
                "description": "High-level summary of the active binary: filename, architecture, bitness, image base, primary entry point, segment count, and total function count.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "analyze_function",
                "description": "Comprehensive summary of a single function: address range, demangled symbol, segment, calling convention, argument details, stack frame layout, basic block count, instruction count, callers count and call sites, and unique callees list. To discover or filter multiple functions, use 'list_funcs'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Function address (hex '0x140001000', integer, or symbol name like 'PreRender')"},
                        "max_callers": {"type": "integer", "description": "Maximum number of caller functions to return in callers array (default 50, max 500)"},
                        "max_callees": {"type": "integer", "description": "Maximum number of callee functions to return in callees array (default 100, max 500)"}
                    },
                    "required": ["addr"]
                }
            },
            {
                "name": "trace_data_flow",
                "description": "Deep inter-procedural data flow propagation starting from an address using Hex-Rays AST decompilation (or memory/XREF data flow if outside a function). Supports 'forward' (def->use: propagates into stores, callee arguments, conditions, returns) and 'backward' (use->def: reverse-AST evaluation, transitive sources, memory loads, callee return values, out-parameters, and caller argument origins).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Starting function, instruction, or memory address (hex '0x140001000', integer, or symbol name)"},
                        "var": {"type": "string", "description": "Optional variable name (lvar name), index ('0', '1'), or argument ('arg0') to trace. If omitted, deduced from address or function arguments"},
                        "direction": {"type": "string", "enum": ["forward", "backward"], "description": "Direction to trace: 'forward' (def->use, default) or 'backward' (use->def)"},
                        "depth": {"type": "integer", "description": "Max inter-procedural call traversal depth (default 2, max 5)"},
                        "include_calls": {"type": "boolean", "description": "Whether to follow data flow across function boundaries: into called functions (forward/backward) and caller call sites (backward) (default true)"}
                    },
                    "required": ["addr"]
                }
            },
            {
                "name": "make_signature",
                "description": "Generate unique pattern signatures for functions, global variables, or explicit address ranges with automatic operand wildcards ('?').\n\nHow to use:\n1. Standard Function Signature: Pass 'addr' of the function. Generates a unique signature starting from function entry.\n2. Shortest / Resilient Signature (Recommended): Pass 'addr' and set 'shortest': true. Deep-searches the function body, caller call sites, and variable XREFs to find the absolute shortest unique signature slice. Returns the pattern, 'offset' relative to target, and signature 'type'.\n3. Global Variable Signature: Pass 'addr' of a global variable in .data/.bss. Automatically locates code XREFs referencing the variable, masks displacement bytes, and returns a signature targeting the reference with 'disp_offset'.\n4. Explicit Range: Pass 'start' and 'end' addresses to generate a pattern for an exact byte/instruction slice.\n\nCRITICAL RULE FOR 'continue_outside_function':\nUse 'continue_outside_function': true ONLY in the absolute last resort when it is impossible to find a unique signature within the function boundary (e.g. tiny 1-2 instruction thunks or stubs). Crossing function boundaries makes signatures extremely fragile to compiler reordering and layout shifts across binary updates.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Target address of function or global variable (hex '0x140001000', integer, or symbol name)"},
                        "start": {"type": "string", "description": "Optional explicit range start address"},
                        "end": {"type": "string", "description": "Optional explicit range end address"},
                        "shortest": {"type": "boolean", "description": "Deep search for the shortest unique signature across the function body, caller sites, or code references for global variables (default false, recommended true)"},
                        "max_length": {"type": "integer", "description": "Max pattern length in bytes (default 250)"},
                        "candidate_limit": {"type": "integer", "description": "Max candidate starting positions inside function to evaluate when shortest=true (default 64)"},
                        "wildcard_operands": {"type": "boolean", "description": "Mask variable operands, relative offsets, and displacement bytes with '?' (default true)"},
                        "continue_outside_function": {"type": "boolean", "description": "Allow pattern search to cross function boundary into adjacent code. CRITICAL: Use ONLY as an absolute last resort when a unique pattern cannot be found within the function (e.g. tiny 1-2 instruction stubs), as crossing boundaries makes signatures extremely fragile across binary updates (default false)"}
                    }
                }
            },
            {
                "name": "get_ast",
                "description": "Unified Hex-Rays Abstract Syntax Tree (AST) tool. Dumps serialized ctree AST for a function ('addr'), or searches/matches AST subtrees against a JSON pattern ('pattern') within a function ('addr') or binary-wide ('func_pattern').",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Function address (hex '0x140001000', integer, or symbol name)"},
                        "pattern": {"type": "object", "description": "Optional AST JSON pattern to match (e.g. {\"op\": \"cot_call\", \"callee\": \"memcpy\"}, {\"op\": \"cot_asg\", \"y\": \"$val\"}). If provided, executes AST pattern matching"},
                        "func_pattern": {"type": "string", "description": "Optional glob pattern to filter function names when searching across binary (e.g. '*Alloc*', '*Crypt*')"},
                        "max_depth": {"type": "integer", "description": "Max AST recursion depth when dumping tree (default 128)"},
                        "limit": {"type": "integer", "description": "Max functions to decompile when searching across binary (default 200)"},
                        "max_matches": {"type": "integer", "description": "Max matched AST nodes to return when matching (default 50)"}
                    }
                }
            },
            {
                "name": "mba_simplify",
                "description": "Mixed Boolean-Arithmetic (MBA) deobfuscation and algebraic simplification using 3 analysis levels: 37 static rewrite rules, constant folding, and 1- and 2-variable brute-force symbolic verification. Optionally accepts custom pattern matching rules. For simplifying control flow if-statement conditions, use 'simplify_predicate'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Function address (hex '0x140001000', integer, or symbol name)"},
                        "expr_addr": {"type": "string", "description": "Optional specific expression address to analyze"},
                        "custom_rules": {
                            "type": "array",
                            "description": "Optional list of custom rewrite rules [{\"name\": \"...\", \"pattern\": {...}, \"simplified\": \"...\"}]",
                            "items": {"type": "object"}
                        }
                    },
                    "required": ["addr"]
                }
            },
            {
                "name": "simplify_predicate",
                "description": "Simplify opaque predicates in Hex-Rays decompilation with preview, optional IDB-only persistence (never modifies disk binary), multi-predicate batching, and automated opaque predicate detection with auto-simplification. For simplifying arithmetic/bitwise expressions, use 'mba_simplify'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Function address (hex '0x140001000', integer, or symbol name)"},
                        "predicate_addr": {"type": "string", "description": "Optional address of single if-statement condition to simplify (hex '0x140001000')"},
                        "force_branch": {"type": "string", "enum": ["always_true", "always_false"], "description": "Branch to force: 'always_true' or 'always_false'"},
                        "predicates": {
                            "type": "array",
                            "description": "Optional batch list of predicates to simplify: [{\"predicate_addr\": \"0x...\", \"force_branch\": \"always_true\"}]",
                            "items": {"type": "object"}
                        },
                        "persist": {"type": "boolean", "description": "Optional IDB persistence flag (default false). When true, patches conditional jump in IDA IDB database (only in IDB, never touches binary on disk)"},
                        "auto_detect": {"type": "boolean", "description": "Optional auto-detection flag (default false). When true, scans all if-statements in function for opaque predicates using constant folding and symbolic evaluation, and automatically simplifies them in pseudocode"}
                    },
                    "required": ["addr"]
                }
            },
            {
                "name": "py",
                "description": "Execute Python code or external script file inside IDA Pro via IDAPython. Captures stdout and stderr output, returns expression or variable evaluation results, captures runtime tracebacks with line numbers, and supports script arguments and timeout. Provide 'code' for inline execution or 'file' for external script file path.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "Python expression or statement(s) to execute"},
                        "file": {"type": "string", "description": "Absolute path to .py script file to run"},
                        "argv": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional list of command line arguments to pass to the script in sys.argv"
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Execution timeout in seconds (default 480, max 3600)"
                        }
                    }
                }
            },
            {
                "name": "find_path",
                "description": "Find execution call chains between two functions, imported APIs, or virtual methods using Bidirectional BFS with frontier balancing, tail-call (jmp) detection, C++ vtable/interface dispatch traversal, callback/function pointer resolution, instruction disassembly, and C++ demangling. By default, exhaustively searches both direct calls and indirect vtable/callback paths. Returns structured steps with caller, callee, call sites, edge_type, vtable details, and thunk/tail flags.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "from": {"type": "string", "description": "Starting function or instruction address (hex '0x140001000' or symbol name)"},
                        "to": {"type": "string", "description": "Target function, import, or instruction address (hex '0x140001000' or symbol name)"},
                        "max_depth": {"type": "integer", "description": "Maximum call chain depth to explore (default 100, max 2000)"},
                        "max_paths": {"type": "integer", "description": "Maximum number of alternative paths to return (default 1, max 10)"},
                        "budget": {"type": "integer", "description": "Maximum number of graph nodes to explore before stopping (default 100000)"},
                        "max_vtable_methods": {"type": "integer", "description": "Maximum virtual methods to inspect per vtable (default 64, max 256)"}
                    },
                    "required": ["from", "to"]
                }
            },
            {
                "name": "reconstruct_struct",
                "description": "Automatically reconstruct a C struct definition by analyzing memory accesses, Hex-Rays helper functions (LODWORD/BYTE4/etc.), member field offsets with scaled pointer arithmetic, alias assignments, allocation sizes (operator new/malloc), and memset zeroing across decompilation AST. Generates padded, non-overlapping C struct code and can optionally apply it to the local variable in Hex-Rays.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Function or instruction address where the struct/pointer is used (hex '0x140001000' or symbol name)"},
                        "var": {"type": "string", "description": "Variable or parameter name to reconstruct struct for (e.g. 'a1', 'this', 'v2', 'rcx'). If omitted, automatically detects variable referenced at instruction 'addr' or first pointer argument"},
                        "struct_name": {"type": "string", "description": "Optional custom name for the reconstructed structure (e.g. 'PlayerData')"},
                        "scan_depth": {"type": "integer", "description": "Inter-procedural scan depth into called functions passing this pointer (default 2, max 5)"},
                        "apply": {"type": "boolean", "description": "If true, compiles the structure into IDA Type Library (TIL) and applies it to the local variable in Hex-Rays (default false)"},
                        "decompile_now": {"type": "boolean", "description": "If true (or when apply is true), returns refreshed Hex-Rays C pseudocode showing the reconstructed struct applied (default false)"}
                    },
                    "required": ["addr"]
                }
            },
            {
                "name": "resolve_vcall",
                "description": "Inspect C++ virtual method tables (vtables), resolve virtual call sites or tail-calls (jmp) to concrete implementation functions, or find which classes/slots implement a virtual method. Works on any vtable in .rdata (with or without RTTI), virtual call sites, object instances, or method functions. Automatically decodes call displacements and caller 'this' context. Provide 'addr' (call site, vtable, instance, or method address) and/or 'class'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Address of either a virtual call site instruction (e.g. 'call [rax+28h]' or 'call rax'), a vtable address in .rdata, an object instance, or a virtual method function"},
                        "class": {"type": "string", "description": "Optional class name to look up vtable for (e.g. 'PlayerEntity' or 'Messiah::Win32Game')"},
                        "index": {"type": "integer", "description": "Optional specific method slot index (0-based) to resolve to a concrete function"},
                        "offset": {"type": "string", "description": "Optional byte offset in vtable (hex '0x28' or integer 40) as alternative to slot index"},
                        "max_methods": {"type": "integer", "description": "Maximum number of virtual methods to dump from vtable (default 128, max 512)"},
                        "all_methods": {"type": "boolean", "description": "If true, returns the full array of vtable methods even when a specific slot/call site is resolved (default false)"},
                        "demangle": {"type": "boolean", "description": "Whether to demangle C++ method names (default true)"}
                    }
                }
            }
        ])schema");
        return kIdaTools;
    }
}
