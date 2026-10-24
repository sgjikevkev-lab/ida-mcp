# Third-party components and licensing scope

The MIT license in `LICENSE` applies to original ida-mcp material authored by
the project contributors. It does not relicense third-party components or
files that carry their own notices.

## Hex-Rays IDA SDK

`plugin/!ibs/ida_92/` contains IDA Pro 9.2 SDK headers and libraries. They are
provided under Hex-Rays' SDK terms, not the ida-mcp MIT license.

## RAX

`plugin/third_party/rax/` contains the RAX C API header and a prebuilt static
library from [HexRaysSA/rax commit
`b13a6978d1d882f340ed9dfd2b2621aba1655cc9`](https://github.com/HexRaysSA/rax/tree/b13a6978d1d882f340ed9dfd2b2621aba1655cc9).
RAX is MIT-licensed; preserve its `LICENSE`, `CAPI_LICENSE`, and third-party
notices and license texts in that directory.

The upstream notices identify Hexagon opcode data derived from QEMU and covered
by GPL-2.0-or-later. Since ida-mcp statically links RAX into `ida_mcp64.dll`,
the MIT license for ida-mcp's own code does not replace the terms applicable
to RAX or the resulting binary. The pinned RAX source is the corresponding
upstream source reference for the bundled library; its commit and build target
are recorded in `plugin/third_party/rax/README.md`.
