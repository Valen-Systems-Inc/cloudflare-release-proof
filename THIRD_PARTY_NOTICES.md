# Third-party notices

The portable bundle contains original Valen Systems code and bundled third-party code. Each component retains its own license; the bundle is not described as MIT-only.

## Runtime dependency closure

- `@modelcontextprotocol/server` 2.0.0, including `@modelcontextprotocol/core` 2.0.0: license text in `licenses/MCP-LICENSE.txt`. The published package metadata identifies MIT, while the shipped upstream license records its Apache-2.0-to-MIT transition. License SHA-256: `0382b0057770ca05e9c350a50aa3b1c1fea84da0bc81d723bf00b9aa841be58a`.
- `zod` 4.5.4: MIT License in `licenses/zod-LICENSE.txt`. License SHA-256: `3f1189b28e3866e0d979968d466b78f813f76827cfdca1fbb124cc0a5c8841f8`.

## Build-only dependency

- `esbuild` 0.28.2: MIT License in `licenses/esbuild-LICENSE.txt`. License SHA-256: `b40ec5baec7bb34fa5b1c09521fa3cd52d5fad7adafed74932a2010d3612a681`.

Esbuild creates the portable JavaScript bundle but is not included as a runtime package.
