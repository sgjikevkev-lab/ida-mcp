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
      "properties": {},
      "additionalProperties": false
    }
  },
  {
    "name": "idb_save",
    "description": "Flush and save active IDA Pro database (.idb/.i64) to disk. Returns database path, file size, and status.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "compact": {
          "type": "boolean",
          "description": "Collect garbage and compact the database during save (default false)"
        },
        "backup": {
          "type": "boolean",
          "description": "Create a backup file (.bak) alongside the database (default false)"
        },
        "outfile": {
          "type": "string",
          "description": "Optional custom output file path to save database to",
          "maxLength": 2097152
        }
      },
      "additionalProperties": false
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
          "description": "Optional segment name or glob pattern filter (e.g. '.text' or '*data*')",
          "maxLength": 2097152
        },
        "addr": {
          "type": "string",
          "description": "Optional address (hex or symbol); if provided, returns only the segment containing this address",
          "maxLength": 2097152
        }
      },
      "additionalProperties": false
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
          "description": "Optional symbol or demangled name glob pattern filter (e.g. '*Create*' or 'NvCloth*')",
          "maxLength": 1024
        },
        "addr": {
          "type": "string",
          "description": "Optional function address (hex or symbol); if provided, returns only the export at this address",
          "maxLength": 2097152
        },
        "ordinal": {
          "type": "integer",
          "description": "Optional export ordinal number",
          "minimum": 0,
          "maximum": 4294967295
        },
        "offset": {
          "type": "integer",
          "description": "Pagination offset (default 0)",
          "minimum": 0,
          "maximum": 2147483647
        },
        "count": {
          "type": "integer",
          "description": "Maximum number of exports to return (default 100, max 2000)",
          "minimum": 0,
          "maximum": 2000
        }
      },
      "additionalProperties": false
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
          "description": "Optional module name filter pattern with wildcards (e.g. 'kernel32*' or 'USER32')",
          "maxLength": 1024
        },
        "pattern": {
          "type": "string",
          "description": "Optional imported symbol pattern with wildcards (e.g. '*CreateFile*')",
          "maxLength": 1024
        },
        "addr": {
          "type": "string",
          "description": "Optional IAT address (hex or symbol); if provided, returns only the import at this address",
          "maxLength": 2097152
        },
        "modules_only": {
          "type": "boolean",
          "description": "If true, returns only the list of all imported module/DLL names"
        },
        "offset": {
          "type": "integer",
          "description": "Pagination offset (default 0)",
          "minimum": 0,
          "maximum": 2147483647
        },
        "count": {
          "type": "integer",
          "description": "Max entries to return (default 50, max 1000)",
          "minimum": 1,
          "maximum": 1000
        }
      },
      "additionalProperties": false
    }
  },
  {
    "name": "get_bytes",
    "description": "Read mapped bytes as hex. Returns address and bytes; partial reads include the actual size.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "addr": {
          "type": "string",
          "description": "Memory address (hex '0x140001000' or symbol name like 'main')",
          "maxLength": 2097152
        },
        "size": {
          "type": "integer",
          "description": "Number of bytes to read (default 32, max 4096)",
          "minimum": 1,
          "maximum": 4096
        }
      },
      "required": [
        "addr"
      ],
      "additionalProperties": false
    }
  },
  {
    "name": "strings",
    "description": "Unified string tool for IDA Pro. Read string literal at address ('addr'), batch read strings across multiple addresses ('addrs'), or search string literals across entire binary IDB by pattern ('pattern').",
    "inputSchema": {
      "type": "object",
      "properties": {
        "addr": {
          "type": "string",
          "description": "Memory address to read string from (hex '0x140001000' or symbol)",
          "maxLength": 2097152
        },
        "addrs": {
          "type": "array",
          "items": {
            "type": "string",
            "maxLength": 2097152
          },
          "description": "Batch of memory addresses to read strings from",
          "minItems": 1,
          "maxItems": 64
        },
        "pattern": {
          "type": "string",
          "description": "Search string literals across binary by substring, glob ('*text*'), (default '*' when searching)",
          "maxLength": 1024
        },
        "type": {
          "type": "string",
          "description": "String encoding type: 'auto' (default), 'ascii', 'utf-8', 'utf-16', 'utf-32', or 'pascal'",
          "maxLength": 2097152
        },
        "rebuild": {
          "type": "boolean",
          "description": "Force full rescan of IDB strings list when searching (default false)"
        },
        "cursor": {
          "type": "string",
          "description": "Cursor address for pagination from previous next_cursor",
          "maxLength": 2097152
        },
        "count": {
          "type": "integer",
          "description": "Maximum strings to return in one page (default 64, max 64)",
          "minimum": 0,
          "maximum": 64
        }
      },
      "additionalProperties": false
    }
  },
  {
    "name": "find_bytes",
    "description": "Search memory for byte pattern with wildcards ('?' or '??'). Supports hex ('48 89 5C', '0x48', '\\x48'), continuous hex ('48895C'), and scope filtering by segment, function, or range. To read known bytes at an address, use 'get_bytes'.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "pattern": {
          "type": "string",
          "description": "Byte pattern with '?' wildcards (e.g. '48 89 5C 24 ? 55' or '48895C24??55')",
          "maxLength": 1024
        },
        "segment": {
          "type": "string",
          "description": "Optional segment name to restrict search (e.g. '.text')",
          "maxLength": 2097152
        },
        "func": {
          "type": "string",
          "description": "Optional function name or address to restrict search to a single function",
          "maxLength": 2097152
        },
        "start": {
          "type": "string",
          "description": "Optional start address for search range",
          "maxLength": 2097152
        },
        "end": {
          "type": "string",
          "description": "Optional end address for search range",
          "maxLength": 2097152
        },
        "cursor": {
          "type": "string",
          "description": "Cursor address for pagination from previous next_cursor",
          "maxLength": 2097152
        },
        "count": {
          "type": "integer",
          "description": "Max matches to return (default 50, max 1000)",
          "minimum": 1,
          "maximum": 1000
        }
      },
      "required": [
        "pattern"
      ],
      "additionalProperties": false
    }
  },
  {
    "name": "insn_query",
    "description": "Search instructions by mnemonic and/or disassembly text pattern with cursor pagination. Optional x86-64 semantic effects can be included for up to 100 results. For sequential disassembly, use 'disasm'.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "mnemonic": {
          "type": "string",
          "description": "Instruction mnemonic filter (e.g. 'call', 'syscall', 'xor', default '*' for all)",
          "maxLength": 1024
        },
        "query": {
          "type": "string",
          "description": "Disassembly text filter/glob (e.g. '*eax, eax*', '*qword ptr*')",
          "maxLength": 1024
        },
        "func": {
          "type": "string",
          "description": "Optional function name or address (hex '0x140001000') to restrict search to a single function",
          "maxLength": 2097152
        },
        "segment": {
          "type": "string",
          "description": "Optional segment name to restrict search (e.g. '.text')",
          "maxLength": 2097152
        },
        "start": {
          "type": "string",
          "description": "Optional start address for search range",
          "maxLength": 2097152
        },
        "end": {
          "type": "string",
          "description": "Optional end address for search range",
          "maxLength": 2097152
        },
        "cursor": {
          "type": "string",
          "description": "Cursor address to continue search from previous next_cursor",
          "maxLength": 2097152
        },
        "count": {
          "type": "integer",
          "description": "Max instructions to return (default 50, max 1000)",
          "minimum": 0,
          "maximum": 1000
        },
        "max_scan": {
          "type": "integer",
          "description": "Maximum instructions to scan in one pass before returning (default 250000)",
          "minimum": 0,
          "maximum": 1000000
        },
        "semantic_effects": {
          "type": "boolean",
          "description": "Include RAX x86-64 register/memory/flag/control-flow effects for each result (max count 100, default false)"
        }
      },
      "additionalProperties": false
    }
  },
  {
    "name": "list_funcs",
    "description": "List and filter functions across binary by name pattern ('*name*') and byte size range with cursor pagination. Matches both raw and demangled C++ signatures. For an in-depth summary of a single function, use 'analyze_function'.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "pattern": {
          "type": "string",
          "description": "Function name filter (substring, glob '*Render*',). Matches both raw and demangled C++ names.",
          "maxLength": 1024
        },
        "named_only": {
          "type": "boolean",
          "description": "Filter out auto-generated sub_ functions, returning only named/user symbols (default false)"
        },
        "no_thunks": {
          "type": "boolean",
          "description": "Filter out stub/thunk functions (default false)"
        },
        "min_size": {
          "type": "integer",
          "description": "Minimum function size in bytes",
          "minimum": 0
        },
        "max_size": {
          "type": "integer",
          "description": "Maximum function size in bytes",
          "minimum": 0
        },
        "cursor": {
          "type": "string",
          "description": "Cursor address for pagination from previous next_cursor",
          "maxLength": 2097152
        },
        "count": {
          "type": "integer",
          "description": "Max functions to return (default 100, max 2000)",
          "minimum": 0,
          "maximum": 4096
        }
      },
      "additionalProperties": false
    }
  },
  {
    "name": "list_globals",
    "description": "List global variables, tables, and data symbols with name pattern filter, segment filter, and cursor pagination. Matches raw and demangled C++ names.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "pattern": {
          "type": "string",
          "description": "Symbol name filter (substring, glob '*Config*',). Matches raw and demangled names.",
          "maxLength": 1024
        },
        "segment": {
          "type": "string",
          "description": "Filter by segment name (e.g. '.data', '.rdata', '.bss')",
          "maxLength": 2097152
        },
        "data_only": {
          "type": "boolean",
          "description": "Exclude code-segment symbols and return only symbols in data/bss segments (default false)"
        },
        "writable_only": {
          "type": "boolean",
          "description": "Filter to writable variables only, excluding read-only constants (default false)"
        },
        "include_code_labels": {
          "type": "boolean",
          "description": "Include compiler switch jump tables (jpt_) and case labels (default false)"
        },
        "cursor": {
          "type": "string",
          "description": "Cursor address for pagination from previous next_cursor",
          "maxLength": 2097152
        },
        "count": {
          "type": "integer",
          "description": "Max symbols to return (default 100, max 2000)",
          "minimum": 0,
          "maximum": 4096
        }
      },
      "additionalProperties": false
    }
  },
  {
    "name": "decompile",
    "description": "Decompile function(s) to C pseudocode. Supply addr or addrs. Variable metadata is returned only with include_lvars=true.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "addr": {
          "type": "string",
          "description": "Single function address (hex '0x140001000' or symbol name like 'PreRender')",
          "maxLength": 4096
        },
        "addrs": {
          "type": "array",
          "items": {
            "type": "string",
            "maxLength": 4096
          },
          "description": "Batch of function addresses or symbol names to decompile in a single call",
          "minItems": 1,
          "maxItems": 64
        },
        "include_lvars": {
          "type": "boolean",
          "description": "Include indexed local-variable metadata for subsequent refactoring (default false)."
        }
      },
      "oneOf": [
        {
          "required": [
            "addr"
          ]
        },
        {
          "required": [
            "addrs"
          ]
        }
      ],
      "additionalProperties": false
    }
  },
  {
    "name": "disasm",
    "description": "Disassemble sequential instructions starting from an address, or batch disassemble at multiple target addresses. Supports mnemonic filtering, opcode bytes, function metadata, and pagination. For one address, 'semantic_effects': true adds opt-in x86-64 register, memory, flag, and control-flow effects from the RAX emulator analysis. To search across the binary, use 'insn_query'.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "addr": {
          "type": "string",
          "description": "Start address (hex '0x140001000' or symbol name like 'main')",
          "maxLength": 2097152
        },
        "targets": {
          "type": "array",
          "items": {
            "type": "string",
            "maxLength": 4096
          },
          "description": "Batch of target addresses to disassemble around (e.g. call sites from xrefs)",
          "minItems": 1,
          "maxItems": 64
        },
        "mnemonic": {
          "type": "string",
          "description": "Optional mnemonic filter (e.g. 'call', 'jmp', 'xor') to filter returned instructions",
          "maxLength": 1024
        },
        "count": {
          "type": "integer",
          "description": "Number of instructions to disassemble (default 50 for single, default 5 per batch target, max 1000)",
          "minimum": 0,
          "maximum": 1000
        },
        "bytes": {
          "type": "boolean",
          "description": "Include instruction opcode hex bytes in disassembly lines (default false)"
        },
        "stop_at_func_end": {
          "type": "boolean",
          "description": "If true and start address is inside a function, stop disassembling at function end. If false, continue linearly across function boundaries (default true)"
        },
        "detailed": {
          "type": "boolean",
          "description": "Include structured 'items' array with address, size, bytes, and disasm (default false)"
        },
        "semantic_effects": {
          "type": "boolean",
          "description": "For a single addr target, include RAX x86-64 register/memory/flag/control-flow effects per instruction. Implies detailed output; unsupported or partial instructions are labeled (default false)."
        }
      },
      "oneOf": [
        {
          "required": [
            "addr"
          ]
        },
        {
          "required": [
            "targets"
          ]
        }
      ],
      "additionalProperties": false
    }
  },
  {
    "name": "basic_blocks",
    "description": "Extract a bounded Control Flow Graph (CFG) for a function, including address ranges, block types, successor/predecessor edges, loop detection ('is_loop_header', 'is_back_edge'), conditional branch resolution ('branch' with true/false targets and condition), cyclomatic complexity, and optional disassembly. At most 512 blocks, 2,048 instructions, and 512 KiB of instruction text are returned; truncation is reported.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "addr": {
          "type": "string",
          "description": "Function address (hex '0x140001000' or symbol name)",
          "maxLength": 2097152
        },
        "no_external": {
          "type": "boolean",
          "description": "Exclude external jump target blocks from CFG (default false)"
        },
        "include_instructions": {
          "type": "boolean",
          "description": "Include disassembly instructions for each basic block (default false)"
        }
      },
      "required": [
        "addr"
      ],
      "additionalProperties": false
    }
  },
  {
    "name": "xref_query",
    "description": "Query references with direction and type filters. Caller argument preparation is included only with context=true.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "addr": {
          "type": "string",
          "description": "Target address (hex '0x140001000' or symbol name)",
          "maxLength": 2097152
        },
        "direction": {
          "type": "string",
          "enum": [
            "to",
            "from",
            "both"
          ],
          "description": "XREF direction: 'to' (incoming references), 'from' (outgoing references), or 'both' (default 'to')",
          "maxLength": 2097152
        },
        "type": {
          "type": "string",
          "description": "Filter by XREF type: 'all', 'code', 'data', 'call', 'jump', 'read', 'write', 'offset' (default 'all')",
          "maxLength": 2097152
        },
        "include_flow": {
          "type": "boolean",
          "description": "Include ordinary execution flow (fall-through to next instruction) xrefs (default false)"
        },
        "cursor": {
          "type": "string",
          "description": "Pagination cursor from previous next_cursor or integer offset",
          "maxLength": 2097152
        },
        "count": {
          "type": "integer",
          "description": "Max XREFs to return (default 100, range 1 to 2000)",
          "minimum": 1,
          "maximum": 2000
        },
        "context": {
          "type": "boolean",
          "description": "Include preceding argument preparation instructions (default false)."
        }
      },
      "required": [
        "addr"
      ],
      "additionalProperties": false
    }
  },
  {
    "name": "callgraph",
    "description": "Generate caller-callee execution graph starting from a root function with directional traversal (callees/callers/both), depth limit, demangled C++ names, and call site tracking.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "addr": {
          "type": "string",
          "description": "Root function address (hex '0x140001000' or symbol name)",
          "maxLength": 2097152
        },
        "direction": {
          "type": "string",
          "enum": [
            "callees",
            "callers",
            "both"
          ],
          "description": "Traversal direction: 'callees' (functions called by root), 'callers' (functions that call root), or 'both' (default 'callees')",
          "maxLength": 2097152
        },
        "depth": {
          "type": "integer",
          "description": "Maximum call tree traversal depth (1..10, default 3)",
          "minimum": 1,
          "maximum": 10
        },
        "max_nodes": {
          "type": "integer",
          "description": "Maximum nodes to traverse in graph (default 500, max 2000)",
          "minimum": 1,
          "maximum": 2000
        },
        "include_nodes": {
          "type": "boolean",
          "description": "Include structured 'nodes' array with metadata in response (default true)"
        }
      },
      "required": [
        "addr"
      ],
      "additionalProperties": false
    }
  },
  {
    "name": "refactor",
    "description": "Rename, retype or comment symbols and local variables. Supports a target or items batch. Returns edit receipts; refreshed pseudocode only with include_code=true.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "target": {
          "type": "string",
          "description": "Target address (hex '0x140001000') or symbol name to modify",
          "maxLength": 2097152
        },
        "name": {
          "type": "string",
          "description": "New symbol name for target (or leave empty if reset_name is true)",
          "maxLength": 2097152
        },
        "reset_name": {
          "type": "boolean",
          "description": "Reset name to default auto-generated name (e.g. sub_... or dword_...)"
        },
        "type": {
          "type": "string",
          "description": "New C type or function prototype declaration (e.g. 'int __fastcall(void *ctx, int len)')",
          "maxLength": 2097152
        },
        "comment": {
          "type": "string",
          "description": "Comment text to set on target address or function",
          "maxLength": 2097152
        },
        "repeatable": {
          "type": "boolean",
          "description": "Whether comment is repeatable (default false)"
        },
        "func_comment": {
          "type": "boolean",
          "description": "Whether comment applies to function header (default false)"
        },
        "clear_comment": {
          "type": "boolean",
          "description": "Whether to remove existing comment (default false)"
        },
        "lvars": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "name": {
                "type": "string",
                "description": "Current local variable name (or specify 'index')",
                "maxLength": 2097152
              },
              "index": {
                "type": "integer",
                "description": "Optional local variable index (0-based)",
                "minimum": 0
              },
              "new_name": {
                "type": "string",
                "description": "New name for local variable",
                "maxLength": 2097152
              },
              "type": {
                "type": "string",
                "description": "New C type for local variable",
                "maxLength": 2097152
                }
              },
              "oneOf": [
                {"required": ["name"]},
                {"required": ["index"]}
              ],
              "anyOf": [
                {"required": ["new_name"]},
                {"required": ["type"]}
              ],
              "additionalProperties": false
          },
          "description": "List of local variable modifications (renaming and retyping) for target function",
          "minItems": 1,
          "maxItems": 64
        },
        "comments": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "addr": {
                "type": "string",
                "description": "Instruction address",
                "maxLength": 2097152
              },
              "comment": {
                "type": "string",
                "description": "Comment text",
                "maxLength": 2097152
              },
              "repeatable": {
                "type": "boolean",
                "description": "Repeatable comment flag"
              }
            },
            "required": [
              "addr",
              "comment"
            ],
            "additionalProperties": false
          },
          "description": "Batch of instruction comments within target function",
          "minItems": 1,
          "maxItems": 64
        },
        "items": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "target": {
                "type": "string",
                "description": "Target address (hex '0x140001000' or integer) or symbol name to modify",
                "maxLength": 2097152
              },
              "name": {
                "type": "string",
                "description": "New symbol name for target (or leave empty if reset_name is true)",
                "maxLength": 2097152
              },
              "reset_name": {
                "type": "boolean",
                "description": "Reset name to default auto-generated name (e.g. sub_... or dword_...)"
              },
              "type": {
                "type": "string",
                "description": "New C type or function prototype declaration (e.g. 'int __fastcall(void *ctx, int len)')",
                "maxLength": 2097152
              },
              "comment": {
                "type": "string",
                "description": "Comment text to set on target address or function",
                "maxLength": 2097152
              },
              "repeatable": {
                "type": "boolean",
                "description": "Whether comment is repeatable (default false)"
              },
              "func_comment": {
                "type": "boolean",
                "description": "Whether comment applies to function header (default false)"
              },
              "clear_comment": {
                "type": "boolean",
                "description": "Whether to remove existing comment (default false)"
              },
              "lvars": {
                "type": "array",
                "items": {
                  "type": "object",
                  "properties": {
                    "name": {
                      "type": "string",
                      "description": "Current local variable name (or specify 'index')",
                      "maxLength": 2097152
                    },
                    "index": {
                      "type": "integer",
                      "description": "Optional local variable index (0-based)",
                      "minimum": 0
                    },
                    "new_name": {
                      "type": "string",
                      "description": "New name for local variable",
                      "maxLength": 2097152
                    },
                    "type": {
                      "type": "string",
                      "description": "New C type for local variable",
                      "maxLength": 2097152
                    }
                  },
                  "oneOf": [
                    {"required": ["name"]},
                    {"required": ["index"]}
                  ],
                  "anyOf": [
                    {"required": ["new_name"]},
                    {"required": ["type"]}
                  ],
                  "additionalProperties": false
                },
                "description": "List of local variable modifications (renaming and retyping) for target function",
                "minItems": 1,
                "maxItems": 64
              },
              "comments": {
                "type": "array",
                "items": {
                  "type": "object",
                  "properties": {
                    "addr": {
                      "type": "string",
                      "description": "Instruction address",
                      "maxLength": 2097152
                    },
                    "comment": {
                      "type": "string",
                      "description": "Comment text",
                      "maxLength": 2097152
                    },
                    "repeatable": {
                      "type": "boolean",
                      "description": "Repeatable comment flag"
                    }
                  },
                  "required": [
                    "addr",
                    "comment"
                  ],
                  "additionalProperties": false
                },
                "description": "Batch of instruction comments within target function",
                "minItems": 1,
                "maxItems": 64
              }
            },
            "required": [
              "target"
            ],
            "additionalProperties": false
          },
          "description": "Batch mode: array of modification items, each with 'target' and any combination of 'name', 'type', 'comment', 'lvars', 'comments'",
          "minItems": 1,
          "maxItems": 64
        },
        "include_code": {
          "type": "boolean",
          "description": "Return refreshed pseudocode after a single-target edit (default false)."
        }
      },
      "additionalProperties": false
    }
  },
  {
    "name": "types",
    "description": "Unified type manipulation tool for IDA Pro. Handles compiling new C structs/unions/enums into TIL ('c_code'), inspecting struct definitions with field offsets and member types ('name' or 'names'), searching registered types across TILs ('pattern' or 'query'), and interpreting raw memory at address as a typed struct instance ('addr' + 'name').",
    "inputSchema": {
      "type": "object",
      "properties": {
        "c_code": {
          "type": "string",
          "description": "C source declarations to compile into TIL (e.g. 'struct Player { int hp; float pos[3]; };')",
          "maxLength": 2097152
        },
        "name": {
          "type": "string",
          "description": "Type name to inspect, or struct type name to decode memory at 'addr'",
          "maxLength": 2097152
        },
        "names": {
          "type": "array",
          "items": {
            "type": "string",
            "maxLength": 2097152
          },
          "description": "Batch of type names to inspect in a single call",
          "minItems": 1,
          "maxItems": 64
        },
        "addr": {
          "type": "string",
          "description": "Memory address to interpret as struct instance (requires 'name')",
          "maxLength": 2097152
        },
        "pattern": {
          "type": "string",
          "description": "Search pattern for types in TIL (e.g. '*Vector*' or '*Entity*')",
          "maxLength": 1024
        },
        "kind": {
          "type": "string",
          "enum": [
            "all",
            "struct",
            "union",
            "enum",
            "typedef",
            "function"
          ],
          "description": "Filter by type kind when searching",
          "maxLength": 2097152
        },
        "pack": {
          "type": "integer",
          "description": "Alignment pack value for c_code: 1, 2, 4, 8, 16",
          "minimum": 0,
          "enum": [
            1,
            2,
            4,
            8,
            16
          ]
        },
        "cursor": {
          "type": "string",
          "description": "Pagination cursor for type searching",
          "maxLength": 2097152
        },
        "count": {
          "type": "integer",
          "description": "Max results to return (default 50)",
          "minimum": 0,
          "maximum": 4096
        }
      },
      "additionalProperties": false
    }
  },
  {
    "name": "stack_frame",
    "description": "Inspect stack frame layout of a function: argument offsets, local variables, return address, signed frame pointer displacements (e.g. '[rbp-18h]'), variable categories, and Hex-Rays decompiler local variables with register allocations.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "addr": {
          "type": "string",
          "description": "Function address (hex '0x140001000' or symbol name)",
          "maxLength": 2097152
        },
        "include_lvars": {
          "type": "boolean",
          "description": "Include decompiler variables and register locations (default false)."
        }
      },
      "required": [
        "addr"
      ],
      "additionalProperties": false
    }
  },
  {
    "name": "rtti",
    "description": "Unified C++ RTTI tool for IDA Pro. Discover and list MSVC RTTI classes with inheritance and method counts ('pattern', 'base_class'), inspect detailed class metadata and virtual tables ('name' or 'class' or 'addr'), generate class and vtable C struct into TIL ('create_struct': true), or force cache refresh ('refresh': true).",
    "inputSchema": {
      "type": "object",
      "properties": {
        "name": {
          "type": "string",
          "description": "Class name (e.g. 'std::exception') or address (vtable, method, or RTTI descriptor) to inspect",
          "maxLength": 2097152
        },
        "addr": {
          "type": "string",
          "description": "Alternative address to lookup class from",
          "maxLength": 2097152
        },
        "pattern": {
          "type": "string",
          "description": "Class name pattern filter with optional wildcards (e.g. '*Camera*', '*Player*') when listing",
          "maxLength": 1024
        },
        "base_class": {
          "type": "string",
          "description": "Filter classes inheriting from base class (e.g. 'Entity', 'std::exception') when listing",
          "maxLength": 1024
        },
        "min_methods": {
          "type": "integer",
          "description": "Filter classes having at least this many virtual methods",
          "minimum": 0
        },
        "sort": {
          "type": "string",
          "description": "Sort order: 'name' (alphabetical) or 'methods' (descending by method count, default 'name')",
          "maxLength": 2097152
        },
        "count": {
          "type": "integer",
          "description": "Max classes to return per page (default 50, max 500)",
          "minimum": 0,
          "maximum": 4096
        },
        "offset": {
          "type": "integer",
          "description": "0-based offset for pagination",
          "minimum": 0
        },
        "refresh": {
          "type": "boolean",
          "description": "Force cache invalidation and fresh scan of RTTI structures"
        },
        "create_struct": {
          "type": "boolean",
          "description": "If true, generates C++ class structure and vtable struct in IDA Type Library (TIL)"
        },
        "struct_name": {
          "type": "string",
          "description": "Optional custom name for the generated structure",
          "maxLength": 2097152
        },
        "apply_to_vtable": {
          "type": "boolean",
          "description": "If true, applies the created vtable struct type directly to the vtable in IDB"
        }
      },
      "additionalProperties": false
    }
  },
  {
    "name": "survey_binary",
    "description": "High-level summary of the active binary: filename, architecture, bitness, image base, primary entry point, segment count, and total function count.",
    "inputSchema": {
      "type": "object",
      "properties": {},
      "additionalProperties": false
    }
  },
  {
    "name": "analyze_function",
    "description": "Comprehensive summary of a single function: address range, demangled symbol, segment, calling convention, argument details, stack frame layout, basic block count, instruction count, callers count and call sites, and unique callees list. Set 'semantic_summary': true to add a compact x86-64 RAX summary of register, flag, memory, and control-flow effects. To discover or filter multiple functions, use 'list_funcs'.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "addr": {
          "type": "string",
          "description": "Function address (hex '0x140001000' or symbol name like 'PreRender')",
          "maxLength": 2097152
        },
        "max_callers": {
          "type": "integer",
          "description": "Maximum number of caller functions to return in callers array (default 50, max 500)",
          "minimum": 0,
          "maximum": 500
        },
        "max_callees": {
          "type": "integer",
          "description": "Maximum number of callee functions to return in callees array (default 100, max 500)",
          "minimum": 0,
          "maximum": 500
        },
        "semantic_summary": {
          "type": "boolean",
          "description": "Include a bounded aggregate of x86-64 RAX instruction effects (default false; analyzes at most 2048 instructions)"
        }
      },
      "required": [
        "addr"
      ],
      "additionalProperties": false
    }
  },
  {
    "name": "trace_data_flow",
    "description": "Trace data flow using Hex-Rays AST analysis or memory/XREF traversal. Set 'machine_level': true to use RAX for bounded x86-64 register def-use tracing through a function CFG; specify a register in 'var'. Machine-level mode merges branches conservatively, stops at unknown calls or incomplete instruction lifts, and reports that it does not track memory aliases, control dependencies, or cross function calls.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "addr": {
          "type": "string",
          "description": "Starting function, instruction, or memory address (hex '0x140001000' or symbol name)",
          "maxLength": 2097152
        },
        "var": {
          "type": "string",
          "description": "Hex-Rays mode: optional variable, index, or argument such as 'arg0'. Machine-level mode: required x86-64 register such as 'rax', 'rcx', 'r8', 'xmm0', or 'eflags'.",
          "maxLength": 2097152
        },
        "direction": {
          "type": "string",
          "enum": [
            "forward",
            "backward"
          ],
          "description": "Direction to trace: 'forward' (def->use, default) or 'backward' (use->def)",
          "maxLength": 2097152
        },
        "depth": {
          "type": "integer",
          "description": "Hex-Rays mode: max inter-procedural call traversal depth (default 2, max 5); ignored in machine-level mode",
          "minimum": 0
        },
        "include_calls": {
          "type": "boolean",
          "description": "Hex-Rays mode: whether to follow data flow across function boundaries (default true); machine-level mode always stops at calls"
        },
        "machine_level": {
          "type": "boolean",
          "description": "Use bounded RAX register def-use analysis over the x86-64 function CFG instead of Hex-Rays AST or data xrefs (default false)"
        }
      },
      "required": [
        "addr"
      ],
      "additionalProperties": false
    }
  },
  {
    "name": "make_signature",
    "description": "Generate a unique wildcard byte signature for addr, or an explicit start/end range. shortest=true searches body and references. Cross-function signatures require continue_outside_function=true and are less stable across builds.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "addr": {
          "type": "string",
          "description": "Target address of function or global variable (hex '0x140001000' or symbol name)",
          "maxLength": 2097152
        },
        "start": {
          "type": "string",
          "description": "Optional explicit range start address",
          "maxLength": 2097152
        },
        "end": {
          "type": "string",
          "description": "Optional explicit range end address",
          "maxLength": 2097152
        },
        "shortest": {
          "type": "boolean",
          "description": "Deep search for the shortest unique signature across the function body, caller sites, or code references for global variables (default false, recommended true)"
        },
        "max_length": {
          "type": "integer",
          "description": "Max pattern length in bytes (default 250)",
          "minimum": 1,
          "maximum": 4096
        },
        "wildcard_operands": {
          "type": "boolean",
          "description": "Mask variable operands, relative offsets, and displacement bytes with '?' (default true)"
        },
        "continue_outside_function": {
          "type": "boolean",
          "description": "Allow pattern search to cross function boundary into adjacent code. CRITICAL: Use ONLY as an absolute last resort when a unique pattern cannot be found within the function (e.g. tiny 1-2 instruction stubs), as crossing boundaries makes signatures extremely fragile across binary updates (default false)"
        }
      },
      "additionalProperties": false
    }
  },
  {
    "name": "get_ast",
    "description": "Unified Hex-Rays Abstract Syntax Tree (AST) tool. Dumps serialized ctree AST for a function ('addr'), or searches/matches AST subtrees against a JSON pattern ('pattern') within a function ('addr') or binary-wide ('func_pattern').",
    "inputSchema": {
      "type": "object",
      "properties": {
        "addr": {
          "type": "string",
          "description": "Function address (hex '0x140001000' or symbol name)",
          "maxLength": 2097152
        },
        "pattern": {
          "type": "object",
          "description": "Optional AST JSON pattern to match (e.g. {\"op\": \"cot_call\", \"callee\": \"memcpy\"}, {\"op\": \"cot_asg\", \"y\": \"$val\"}). If provided, executes AST pattern matching"
        },
        "func_pattern": {
          "type": "string",
          "description": "Optional glob pattern to filter function names when searching across binary (e.g. '*Alloc*', '*Crypt*')",
          "maxLength": 1024
        },
        "max_depth": {
          "type": "integer",
          "description": "Max AST recursion depth when dumping tree (default 128)",
          "minimum": 1,
          "maximum": 256
        },
        "limit": {
          "type": "integer",
          "description": "Max functions to inspect when searching across binary, including functions filtered by func_pattern (default 200)",
          "minimum": 0,
          "maximum": 4096
        },
        "max_matches": {
          "type": "integer",
          "description": "Max matched AST nodes to return when matching (default 50)",
          "minimum": 0,
          "maximum": 4096
        }
      },
      "additionalProperties": false
    }
  },
  {
    "name": "mba_simplify",
    "description": "Mixed Boolean-Arithmetic (MBA) deobfuscation and algebraic simplification using 3 analysis levels: 37 static rewrite rules, constant folding, and 1- and 2-variable brute-force symbolic verification. Optionally accepts custom pattern matching rules. For simplifying control flow if-statement conditions, use 'simplify_predicate'.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "addr": {
          "type": "string",
          "description": "Function address (hex '0x140001000' or symbol name)",
          "maxLength": 2097152
        },
        "expr_addr": {
          "type": "string",
          "description": "Optional specific expression address to analyze",
          "maxLength": 2097152
        },
        "custom_rules": {
          "type": "array",
          "description": "Optional list of custom rewrite rules [{\"name\": \"...\", \"pattern\": {...}, \"simplified\": \"...\"}]",
          "items": {
            "type": "object"
          },
          "minItems": 1,
          "maxItems": 64
        }
      },
      "required": [
        "addr"
      ],
      "additionalProperties": false
    }
  },
  {
    "name": "simplify_predicate",
    "description": "Simplify opaque predicates in Hex-Rays decompilation with preview, optional IDB-only persistence (never modifies disk binary), multi-predicate batching, and automated opaque predicate detection with auto-simplification. For simplifying arithmetic/bitwise expressions, use 'mba_simplify'.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "addr": {
          "type": "string",
          "description": "Function address (hex '0x140001000' or symbol name)",
          "maxLength": 2097152
        },
        "predicate_addr": {
          "type": "string",
          "description": "Optional address of single if-statement condition to simplify (hex '0x140001000')",
          "maxLength": 2097152
        },
        "force_branch": {
          "type": "string",
          "enum": [
            "always_true",
            "always_false"
          ],
          "description": "Branch to force: 'always_true' or 'always_false'",
          "maxLength": 2097152
        },
        "predicates": {
          "type": "array",
          "description": "Optional batch list of predicates to simplify: [{\"predicate_addr\": \"0x...\", \"force_branch\": \"always_true\"}]",
          "items": {
            "type": "object",
            "properties": {
              "predicate_addr": {
                "type": "string",
                "maxLength": 2097152
              },
              "force_branch": {
                "type": "string",
                "enum": [
                  "always_true",
                  "always_false"
                ],
                "maxLength": 2097152
              }
            },
            "required": [
              "predicate_addr",
              "force_branch"
            ],
            "additionalProperties": false
          },
          "minItems": 1,
          "maxItems": 64
        },
        "persist": {
          "type": "boolean",
          "description": "Optional IDB persistence flag (default false). When true, patches conditional jump in IDA IDB database (only in IDB, never touches binary on disk)"
        },
        "auto_detect": {
          "type": "boolean",
          "description": "Optional auto-detection flag (default false). When true, scans all if-statements in function for opaque predicates using constant folding and symbolic evaluation, and automatically simplifies them in pseudocode"
        }
      },
      "required": [
        "addr"
      ],
      "additionalProperties": false
    }
  },
  {
    "name": "py",
    "description": "Execute IDAPython code or a script file; capture output and the last expression. Fixed 30-minute cooperative deadline. IDAPython manual cancellation remains available. Native extension calls cannot be forcibly interrupted.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "code": {
          "type": "string",
          "description": "Python expression or statement(s) to execute",
          "maxLength": 2097152
        },
        "file": {
          "type": "string",
          "description": "Absolute path to .py script file to run",
          "maxLength": 2097152
        },
        "argv": {
          "type": "array",
          "items": {
            "type": "string",
            "maxLength": 2097152
          },
          "description": "Optional list of command line arguments to pass to the script in sys.argv",
          "minItems": 1,
          "maxItems": 64
        }
      },
      "oneOf": [
        {
          "required": [
            "code"
          ]
        },
        {
          "required": [
            "file"
          ]
        }
      ],
      "additionalProperties": false
    }
  },
  {
    "name": "find_path",
    "description": "Find execution call chains between two functions, imported APIs, or virtual methods using Bidirectional BFS with frontier balancing, tail-call (jmp) detection, C++ vtable/interface dispatch traversal, callback/function pointer resolution, instruction disassembly, and C++ demangling. By default, exhaustively searches both direct calls and indirect vtable/callback paths. Returns structured steps with caller, callee, call sites, edge_type, vtable details, and thunk/tail flags.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "from": {
          "type": "string",
          "description": "Starting function or instruction address (hex '0x140001000' or symbol name)",
          "maxLength": 2097152
        },
        "to": {
          "type": "string",
          "description": "Target function, import, or instruction address (hex '0x140001000' or symbol name)",
          "maxLength": 2097152
        },
        "max_depth": {
          "type": "integer",
          "description": "Maximum call chain depth to explore (default 100, max 2000)",
          "minimum": 1,
          "maximum": 2000
        },
        "max_paths": {
          "type": "integer",
          "description": "Maximum number of alternative paths to return (default 1, max 10)",
          "minimum": 1,
          "maximum": 10
        },
        "budget": {
          "type": "integer",
          "description": "Maximum graph scan steps and explored nodes (default 100000, max 1000000)",
          "minimum": 1,
          "maximum": 1000000
        },
        "max_vtable_methods": {
          "type": "integer",
          "description": "Maximum virtual methods to inspect per vtable (default 64, max 256)",
          "minimum": 1,
          "maximum": 256
        }
      },
      "required": [
        "from",
        "to"
      ],
      "additionalProperties": false
    }
  },
  {
    "name": "reconstruct_struct",
    "description": "Automatically reconstruct a C struct definition by analyzing memory accesses, Hex-Rays helper functions (LODWORD/BYTE4/etc.), member field offsets with scaled pointer arithmetic, alias assignments, allocation sizes (operator new/malloc), and memset zeroing across decompilation AST. Generates padded, non-overlapping C struct code and can optionally apply it to the local variable in Hex-Rays.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "addr": {
          "type": "string",
          "description": "Function or instruction address where the struct/pointer is used (hex '0x140001000' or symbol name)",
          "maxLength": 2097152
        },
        "var": {
          "type": "string",
          "description": "Variable or parameter name to reconstruct struct for (e.g. 'a1', 'this', 'v2', 'rcx'). If omitted, automatically detects variable referenced at instruction 'addr' or first pointer argument",
          "maxLength": 2097152
        },
        "struct_name": {
          "type": "string",
          "description": "Optional C identifier for the reconstructed structure (e.g. 'PlayerData')",
          "maxLength": 128
        },
        "scan_depth": {
          "type": "integer",
          "description": "Inter-procedural scan depth into called functions passing this pointer (default 2, max 5)",
          "minimum": 0
        },
        "apply": {
          "type": "boolean",
          "description": "If true, compiles the structure into IDA Type Library (TIL) and applies it to the local variable in Hex-Rays (default false)"
        },
        "include_code": {
          "type": "boolean",
          "description": "Return refreshed pseudocode after applying the inferred type (default false)."
        }
      },
      "required": [
        "addr"
      ],
      "additionalProperties": false
    }
  },
  {
    "name": "resolve_vcall",
    "description": "Inspect C++ virtual method tables (vtables), resolve virtual call sites or tail-calls (jmp) to concrete implementation functions, or find which classes/slots implement a virtual method. Works on any vtable in .rdata (with or without RTTI), virtual call sites, object instances, or method functions. Automatically decodes call displacements and caller 'this' context. Provide 'addr' (call site, vtable, instance, or method address) and/or 'class'.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "addr": {
          "type": "string",
          "description": "Address of either a virtual call site instruction (e.g. 'call [rax+28h]' or 'call rax'), a vtable address in .rdata, an object instance, or a virtual method function",
          "maxLength": 2097152
        },
        "class": {
          "type": "string",
          "description": "Optional class name to look up vtable for (e.g. 'PlayerEntity' or 'Messiah::Win32Game')",
          "maxLength": 2097152
        },
        "index": {
          "type": "integer",
          "description": "Optional specific method slot index (0-based, maximum 511) to resolve to a concrete function",
          "minimum": 0,
          "maximum": 511
        },
        "offset": {
          "type": "string",
          "description": "Optional pointer-aligned byte offset in vtable (hex '0x28' or integer 40) as alternative to slot index; resolved index must be at most 511",
          "maxLength": 2097152
        },
        "max_methods": {
          "type": "integer",
          "description": "Maximum number of virtual methods to dump from vtable (default 128, max 512)",
          "minimum": 0,
          "maximum": 512
        },
        "all_methods": {
          "type": "boolean",
          "description": "If true, returns the full array of vtable methods even when a specific slot/call site is resolved (default false)"
        }
      },
      "additionalProperties": false
    }
  }
])schema");
        return kIdaTools;
    }
}
