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
                "description": "Non-blocking diagnostic health check. Returns real-time status of IDA Pro, active tool execution, elapsed time, and IDB information even if IDA main thread is busy or blocked.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "idb_save",
                "description": "Flush and save active IDA Pro database (.idb/.i64) to disk. Returns {\"status\": \"success\"}.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "get_segments",
                "description": "List all binary memory segments with start/end addresses, sizes, and R/W/X permissions.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "get_exports",
                "description": "List all exported functions, symbols, and entry points defined in the binary.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "imports_query",
                "description": "Search imported libraries and API functions with module filter, symbol filter, and cursor pagination.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "module": {"type": "string", "description": "Module name filter pattern with optional wildcards (e.g. 'kernel32*')"},
                        "pattern": {"type": "string", "description": "Imported symbol pattern with optional wildcards (e.g. 'CreateFile*')"},
                        "cursor": {"type": "string", "description": "Pagination cursor from previous next_cursor"},
                        "count": {"type": "integer", "description": "Max entries to return (default 50)"}
                    }
                }
            },
            {
                "name": "get_bytes",
                "description": "Read raw bytes from memory at specified address as a hex dump. To search memory for a byte pattern, use 'find_bytes'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Memory address (hex '0x140001000', integer, or symbol name like 'main')"},
                        "size": {"type": "integer", "description": "Number of bytes to read (max 1048576)"}
                    },
                    "required": ["addr", "size"]
                }
            },
            {
                "name": "get_string",
                "description": "Read null-terminated ASCII or UTF-8 string at specified memory address. To search for strings across the binary, use 'search_strings'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Memory address of string literal (hex '0x140001000', integer, or symbol name)"}
                    },
                    "required": ["addr"]
                }
            },
            {
                "name": "search_strings",
                "description": "Search string literals across entire binary using substring, glob, or regex pattern. Uses IDA string list. Set rebuild=true to force full database rescan. To read a string at a known address, use 'get_string'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "Substring, glob ('*text*'), or regex pattern to search for"},
                        "cursor": {"type": "string", "description": "Cursor address for pagination from previous next_cursor"},
                        "count": {"type": "integer", "description": "Maximum strings to return (default 100)"},
                        "rebuild": {"type": "boolean", "description": "Force full rescan of IDB strings list (default false)"}
                    },
                    "required": ["pattern"]
                }
            },
            {
                "name": "find_bytes",
                "description": "Search executable memory for byte sequence with '?' wildcards (e.g. '48 89 5C 24 ? 55'). To read known bytes at an address, use 'get_bytes'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "Space-separated hex byte pattern with '?' wildcards"},
                        "cursor": {"type": "string", "description": "Address or offset to start search from (default segment start)"},
                        "count": {"type": "integer", "description": "Max matches to return (default 50)"}
                    },
                    "required": ["pattern"]
                }
            },
            {
                "name": "insn_query",
                "description": "Search instructions by mnemonic (e.g. 'call', 'syscall', 'xor') across binary or within specified function. For sequential disassembly of a function, use 'disasm'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "mnemonic": {"type": "string", "description": "Instruction mnemonic to search for (e.g. 'call', 'syscall')"},
                        "addr": {"type": "string", "description": "Optional function address (hex '0x140001000' or symbol name) to restrict search scope"},
                        "cursor": {"type": "string", "description": "Cursor address to continue search from"},
                        "count": {"type": "integer", "description": "Max instructions to return (default 50)"}
                    },
                    "required": ["mnemonic"]
                }
            },
            {
                "name": "list_funcs",
                "description": "List and filter functions across binary by name pattern/glob ('*name*') and byte size range with cursor pagination. For an in-depth summary of a single function (callers, callees, prototype), use 'analyze_function'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "Function name filter (substring, glob '*Render*', or regex)"},
                        "min_size": {"type": "integer", "description": "Minimum function size in bytes"},
                        "max_size": {"type": "integer", "description": "Maximum function size in bytes"},
                        "cursor": {"type": "string", "description": "Cursor address for pagination from previous next_cursor"},
                        "count": {"type": "integer", "description": "Max functions to return (default 100)"}
                    }
                }
            },
            {
                "name": "list_globals",
                "description": "List global variables, tables, and data symbols with name pattern filter and cursor pagination.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "Symbol name filter (substring, glob '*Config*', or regex)"},
                        "cursor": {"type": "string", "description": "Cursor address for pagination from previous next_cursor"},
                        "count": {"type": "integer", "description": "Max symbols to return (default 100)"}
                    }
                }
            },
            {
                "name": "decompile",
                "description": "Decompile target function to clean Hex-Rays C pseudocode. Returns raw C source text in 'code' field. To inspect the full AST syntax tree or variable types, use 'get_ast'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Function address (hex '0x140001000', integer, or symbol name like 'PreRender')"}
                    },
                    "required": ["addr"]
                }
            },
            {
                "name": "disasm",
                "description": "Disassemble sequential instructions starting from address. Returns raw assembly text lines in 'instructions'. To search for specific instructions (e.g. all 'call' or 'syscall'), use 'insn_query'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Start address (hex '0x140001000', integer, or symbol name like 'main')"},
                        "count": {"type": "integer", "description": "Number of instructions to disassemble (default 50, max 500)"}
                    },
                    "required": ["addr"]
                }
            },
            {
                "name": "basic_blocks",
                "description": "Extract Control Flow Graph (CFG) basic blocks for a function, including address ranges, sizes, and successor edges.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Function address (hex '0x140001000', integer, or symbol name)"}
                    },
                    "required": ["addr"]
                }
            },
            {
                "name": "xref_query",
                "description": "Query cross-references to or from an address with code/data filtering and cursor pagination.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Target address (hex '0x140001000', integer, or symbol name)"},
                        "direction": {"type": "string", "enum": ["to", "from", "both"], "description": "XREF direction: 'to' (incoming references), 'from' (outgoing references), or 'both' (default 'to')"},
                        "type": {"type": "string", "enum": ["all", "code", "data"], "description": "Filter by XREF type: 'all', 'code' (calls/jumps), or 'data' (reads/writes) (default 'all')"},
                        "cursor": {"type": "string", "description": "Cursor offset to continue pagination"},
                        "count": {"type": "integer", "description": "Max XREFs to return (default 100)"}
                    },
                    "required": ["addr"]
                }
            },
            {
                "name": "callgraph",
                "description": "Generate caller-callee execution graph starting from a root function up to specified depth.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Root function address (hex '0x140001000', integer, or symbol name)"},
                        "depth": {"type": "integer", "description": "Maximum call tree traversal depth (1..10, default 3)"}
                    },
                    "required": ["addr"]
                }
            },
            {
                "name": "rename",
                "description": "Rename global function, data symbol, or label in IDB. Supports single rename ('addr' + 'name') or batch rename ('items': [{'addr', 'name'}]). Returns state delta (address, old_name, new_name). For local variables inside decompiled functions, use 'rename_lvar'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Target address or current symbol name (single rename)"},
                        "name": {"type": "string", "description": "New symbol name (single rename)"},
                        "items": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "addr": {"type": "string", "description": "Address (hex '0x140001000') or current symbol name"},
                                    "name": {"type": "string", "description": "New symbol name"}
                                },
                                "required": ["addr", "name"]
                            },
                            "description": "Batch rename items array"
                        }
                    }
                }
            },
            {
                "name": "set_type",
                "description": "Apply C type declaration or function prototype to an existing symbol or address in IDB. Returns state delta (address, old_type, new_type). To register new struct/enum definitions, use 'declare_type'. To change local variable types in decompilation, use 'set_lvar_type'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Target address or symbol name (hex '0x140001000' or symbol name)"},
                        "type": {"type": "string", "description": "C type declaration string (e.g. 'int __fastcall(void *ctx, int len)')"}
                    },
                    "required": ["addr", "type"]
                }
            },
            {
                "name": "set_comment",
                "description": "Set comment at address in disassembly and/or Hex-Rays pseudocode. Returns state delta (address, old_comment, new_comment).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Target address (hex '0x140001000', integer, or symbol name)"},
                        "text": {"type": "string", "description": "Comment text string"},
                        "repeatable": {"type": "boolean", "description": "Set as repeatable disassembly comment visible across all call sites (default false)"},
                        "append": {"type": "boolean", "description": "Append to existing comment instead of overwriting (default false)"}
                    },
                    "required": ["addr", "text"]
                }
            },
            {
                "name": "rename_lvar",
                "description": "Rename a local variable or parameter inside Hex-Rays decompilation. Returns state delta (function, old_name, new_name). For global symbols or functions, use 'rename'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Function address containing the variable (hex '0x140001000' or symbol name)"},
                        "old_name": {"type": "string", "description": "Current local variable name (e.g. 'v1')"},
                        "new_name": {"type": "string", "description": "New local variable name (e.g. 'render_ctx')"}
                    },
                    "required": ["addr", "old_name", "new_name"]
                }
            },
            {
                "name": "set_lvar_type",
                "description": "Set C type for a local variable or parameter inside Hex-Rays decompilation. Returns state delta (function, variable, old_type, new_type). For global symbols or functions, use 'set_type'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Function address containing the variable (hex '0x140001000' or symbol name)"},
                        "name": {"type": "string", "description": "Local variable name (e.g. 'render_ctx')"},
                        "type": {"type": "string", "description": "C type declaration (e.g. 'DWORD*', 'Matrix3x4*', '__int64[3]')"}
                    },
                    "required": ["addr", "name", "type"]
                }
            },
            {
                "name": "recompile",
                "description": "Invalidate Hex-Rays decompilation cache for function(s) to force fresh decompilation on next call. Returns {\"status\": \"success\"}.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Optional function address to invalidate (hex '0x140001000' or symbol name). If omitted, flushes global cache."}
                    }
                }
            },
            {
                "name": "declare_type",
                "description": "Compile and register new C struct, union, enum, or typedef definitions into IDA Type Library (TIL). To apply a prototype or type to an existing function/symbol, use 'set_type'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "c_code": {"type": "string", "description": "C source declarations (e.g. 'struct PlayerStats { int hp; float speed; };')"}
                    },
                    "required": ["c_code"]
                }
            },
            {
                "name": "type_query",
                "description": "Search registered types, structures, and typedefs in IDA Type Library (TIL) by name pattern/glob.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "Type name pattern filter with optional wildcards (e.g. '*Vector*')"},
                        "cursor": {"type": "string", "description": "Cursor for pagination"},
                        "count": {"type": "integer", "description": "Max types to return (default 50)"}
                    }
                }
            },
            {
                "name": "type_inspect",
                "description": "Inspect structure, union, or enum definition from IDA Type Library (TIL), returning field offsets, field types, and total struct size. Does NOT read memory; to read actual memory values of a struct instance, use 'read_struct'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Structure or type name in TIL (e.g. 'Vector3')"}
                    },
                    "required": ["name"]
                }
            },
            {
                "name": "read_struct",
                "description": "Interpret actual memory at address as an instance of a registered structure type, decoding each field value and offset. Recursively expands nested structs, arrays, pointers, and enums. To inspect only the structure definition without reading memory, use 'type_inspect'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Memory address of structure instance (hex '0x140001000', integer, or symbol name)"},
                        "name": {"type": "string", "description": "Structure type name from TIL (e.g. 'Vector3')"},
                        "max_depth": {"type": "integer", "description": "Max recursion depth for nested structs/arrays (default 2, max 5)"},
                        "array_limit": {"type": "integer", "description": "Max array elements to show per array field (default 16, max 128)"}
                    },
                    "required": ["addr", "name"]
                }
            },
            {
                "name": "stack_frame",
                "description": "Inspect stack frame layout of a function: argument offsets, local variables, return address.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Function address (hex '0x140001000', integer, or symbol name)"}
                    },
                    "required": ["addr"]
                }
            },
            {
                "name": "rtti_list_classes",
                "description": "List all detected C++ classes from MSVC RTTI metadata with method counts and vtable addresses.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "Class name pattern filter with optional wildcards (e.g. '*Camera*')"},
                        "cursor": {"type": "string", "description": "Cursor for pagination from previous next_cursor"},
                        "count": {"type": "integer", "description": "Max classes to return (default 50)"}
                    }
                }
            },
            {
                "name": "rtti_get_class",
                "description": "Get detailed C++ class information: vtable address, virtual methods list, and base class hierarchy.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Class name (mangled or demangled like 'std::exception') or vtable address (hex '0x143bf9b80')"}
                    },
                    "required": ["name"]
                }
            },
            {
                "name": "rtti_create_struct",
                "description": "Generate C++ class structure and virtual function table (vtable) struct in IDA Type Library (TIL). Returns {\"status\": \"success\"}.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Class name from RTTI to generate structures for (e.g. 'std::exception')"}
                    },
                    "required": ["name"]
                }
            },
            {
                "name": "survey_binary",
                "description": "High-level summary of active binary: file name, architecture (32/64-bit), image base, segment count, entry points, function count.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "analyze_function",
                "description": "Comprehensive summary of a single function: address range, size, callers count, callees list, and prototype signature. To discover or filter multiple functions, use 'list_funcs'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Function address (hex '0x140001000', integer, or symbol name like 'PreRender')"}
                    },
                    "required": ["addr"]
                }
            },
            {
                "name": "trace_data_flow",
                "description": "Trace inter-procedural data flow propagation starting from an address using Hex-Rays AST decompilation (or memory/XREF data flow if outside a function). Tracks variable propagation through assignments, pointer stores, call arguments across functions, array indexing, and returns.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Starting function, instruction, or memory address (hex '0x140001000', integer, or symbol name)"},
                        "var": {"type": "string", "description": "Optional variable name (lvar name) to trace. If omitted, deduced from address or function arguments"},
                        "direction": {"type": "string", "enum": ["forward", "backward"], "description": "Direction to trace: 'forward' (def->use, default) or 'backward' (use->def)"},
                        "depth": {"type": "integer", "description": "Max inter-procedural call traversal depth (default 2, max 5)"},
                        "include_calls": {"type": "boolean", "description": "Whether to follow data flow into called functions (default true)"}
                    },
                    "required": ["addr"]
                }
            },
            {
                "name": "make_signature",
                "description": "Generate unique pattern signature for function or range with automatic operand wildcards. Useful for pattern scanning.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Function address (hex '0x140001000', integer, or symbol name)"},
                        "start": {"type": "string", "description": "Optional explicit range start address"},
                        "end": {"type": "string", "description": "Optional explicit range end address"},
                        "max_length": {"type": "integer", "description": "Max pattern length in bytes (default 250)"},
                        "wildcard_operands": {"type": "boolean", "description": "Mask variable operands with '?' (default true)"}
                    }
                }
            },
            {
                "name": "get_ast",
                "description": "Serialize Hex-Rays ctree Abstract Syntax Tree (AST) including local variables list to structured JSON. To search for specific AST patterns without dumping the entire tree, use 'ast_match'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Function address (hex '0x140001000', integer, or symbol name)"},
                        "max_depth": {"type": "integer", "description": "Max AST recursion depth (default 64)"}
                    },
                    "required": ["addr"]
                }
            },
            {
                "name": "ast_match",
                "description": "Match Hex-Rays AST subtrees against JSON pattern structure with commutative matching. To view the full AST tree, use 'get_ast'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Function address to scan (hex '0x140001000', integer, or symbol name)"},
                        "pattern": {"type": "object", "description": "AST JSON pattern to match (e.g. {\"op\": \"cit_return\"} or {\"op\": \"cot_call\"})"}
                    },
                    "required": ["pattern", "addr"]
                }
            },
            {
                "name": "mba_simplify",
                "description": "Mixed Boolean-Arithmetic (MBA) deobfuscation and algebraic simplification using 3 analysis levels: 37 static rewrite rules, constant folding, and single-variable brute-force symbolic verification. Optionally accepts custom pattern matching rules. For simplifying control flow if-statement conditions, use 'simplify_predicate'.",
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
                "description": "Simplify opaque predicates in Hex-Rays decompilation with preview, optional IDB-only persistence (never modifies disk binary), multi-predicate batching, and automated opaque predicate detection. For simplifying arithmetic/bitwise expressions, use 'mba_simplify'.",
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
                        "auto_detect": {"type": "boolean", "description": "Optional auto-detection flag (default false). When true, scans all if-statements in function for opaque predicates using constant folding and symbolic evaluation"}
                    },
                    "required": ["addr"]
                }
            },
            {
                "name": "py",
                "description": "Execute Python code or external script file inside IDA Pro via IDAPython. Captures stdout and stderr output. Provide 'code' for inline execution or 'file' for external script file path. Returns {result, stdout, stderr}.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "Python expression or statement(s) to execute"},
                        "file": {"type": "string", "description": "Absolute path to .py script file to run"}
                    }
                }
            },
            {
                "name": "find_path",
                "description": "Find execution call chains between two functions in the binary using Bidirectional BFS with frontier balancing and tail-call (jmp) detection. Returns structured steps with caller, callee, call sites, and thunk flags.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "from": {"type": "string", "description": "Starting function or instruction address (hex '0x140001000' or symbol name)"},
                        "to": {"type": "string", "description": "Target function or instruction address (hex '0x140001000' or symbol name)"},
                        "max_depth": {"type": "integer", "description": "Maximum call chain depth to explore (default 100, max 2000)"},
                        "max_paths": {"type": "integer", "description": "Maximum number of alternative paths to return (default 1, max 10)"},
                        "budget": {"type": "integer", "description": "Maximum number of graph nodes to explore before stopping (default 100000)"}
                    },
                    "required": ["from", "to"]
                }
            },
            {
                "name": "reconstruct_struct",
                "description": "Automatically reconstruct a C struct definition by analyzing memory accesses, member field offsets, allocation sizes (operator new/malloc), and memset zeroing to a pointer variable across Hex-Rays decompilation AST. Generates padded C struct code and can optionally apply it to the local variable in Hex-Rays.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Function or instruction address where the pointer is used (hex '0x140001000' or symbol name)"},
                        "var": {"type": "string", "description": "Variable or parameter name to reconstruct struct for (e.g. 'a1', 'this', 'v2'). If omitted, automatically selects the first pointer parameter"},
                        "struct_name": {"type": "string", "description": "Optional custom name for the reconstructed structure (e.g. 'PlayerData')"},
                        "scan_depth": {"type": "integer", "description": "Inter-procedural scan depth into called functions passing this pointer (default 1, max 3)"},
                        "apply": {"type": "boolean", "description": "If true, compiles the structure into IDA Type Library (TIL) and applies it to the local variable in Hex-Rays (default false)"}
                    },
                    "required": ["addr"]
                }
            },
            {
                "name": "resolve_vcall",
                "description": "Inspect C++ virtual method tables (vtables) or resolve virtual call sites to concrete implementation functions. Works on any vtable in .rdata (with or without RTTI) or at virtual call sites. Provide either 'addr' (vtable address or call site) or 'class' (class name to search in RTTI).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Address of either a virtual call site instruction (e.g. 'call [rax+28h]') or a vtable address in .rdata"},
                        "class": {"type": "string", "description": "Optional class name to look up vtable for (e.g. 'PlayerEntity' or 'Messiah::Win32Game')"},
                        "index": {"type": "integer", "description": "Optional specific method slot index (0-based) to resolve to a concrete function"},
                        "max_methods": {"type": "integer", "description": "Maximum number of virtual methods to dump from vtable (default 128, max 512)"},
                        "demangle": {"type": "boolean", "description": "Whether to demangle C++ method names (default true)"}
                    }
                }
            }
        ])schema");
        return kIdaTools;
    }
}
