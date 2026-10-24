# RAX instruction effects

This integration vendors the upstream RAX C API header and statically links the prebuilt Windows x86-64 library `lib/rax.lib` into `ida_mcp64.dll`. The library was built from upstream commit `b13a6978d1d882f340ed9dfd2b2621aba1655cc9` for `x86_64-pc-windows-msvc`.

RAX's optional KVM and SMIR JIT features were disabled when the library was built. The library remains upstream multi-ISA code: upstream does not currently provide a feature to compile out guest ISAs. ida-mcp calls only its x86-64 analysis API.

`disasm` can opt into one-instruction semantic effects with `semantic_effects: true`; it also enables detailed output. `insn_query` can attach the same effects to at most 100 results. `analyze_function` can aggregate register, flag, memory, and control-flow effects for up to 2,048 instructions. `trace_data_flow` has an opt-in machine mode that follows register def-use across IDA CFG blocks, merges branch states conservatively, and stops at unknown calls or incomplete RAX lifts. It does not follow memory aliases, model control dependencies, or cross function boundaries. Results preserve RAX's complete, partial, unsupported, invalid, or mismatched status; the effects are not proof that every x86 instruction is supported or lifted correctly.

Building ida-mcp requires no Rust toolchain or network access for RAX. The static library and header are included in this project, so the RAX code ships inside `ida_mcp64.dll`. See the adjacent upstream licenses and notices before redistributing the plugin.
