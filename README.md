# Cloudflare Release Proof

Cloudflare Release Proof is a v0.1 release candidate for proving that a local release folder matches a manifest and that the same bytes are available from a public HTTPS origin. It produces deterministic manifests and portable verification receipts without requiring a Cloudflare account or API token.

Cloudflare Release Proof is an independent Valen Systems utility. It is not affiliated with, sponsored by, or endorsed by Cloudflare, Inc.

It proves byte length and SHA-256 equality at the time a command runs. It does not prove deployment ownership, continuous availability, future content, customer delivery, or that a public origin is operated by Cloudflare.

## Prerequisite

Install Node.js 22.13.0 or newer. Node.js is not bundled in the portable ZIP.

## Five-minute CLI

From the extracted portable folder:

```sh
./cf-release-proof --help
./cf-release-proof --version
./cf-release-proof manifest create examples/release --output release-manifest.json
./cf-release-proof manifest verify examples/release --manifest release-manifest.json
./cf-release-proof public verify --base-url https://release.example/ --manifest release-manifest.json
./cf-release-proof mcp --root examples
```

The six supported surfaces are `manifest create`, `manifest verify`, `public verify`, `mcp`, `--help`, and `--version`. Commands are non-interactive. `manifest create` requires `--output`; verification writes canonical JSON to stdout unless `--output` is explicitly supplied. Human status and diagnostics go to stderr.

Exit codes are:

- `0`: success or verified match
- `2`: verified mismatch
- `64`: invalid input or unsafe local data
- `69`: public verification could not be completed
- `70`: unexpected internal failure

## Stdio MCP

Configure a local MCP client with an explicit readable root:

```json
{
  "mcpServers": {
    "cloudflare-release-proof": {
      "command": "node",
      "args": [
        "/path/to/cloudflare-release-proof-v0.1.0/cf-release-proof.mjs",
        "mcp",
        "--root",
        "/path/to/releases"
      ]
    }
  }
}
```

The server exposes exactly `create_release_manifest`, `verify_release_folder`, and `verify_public_release`. Local tool paths are relative to the startup root. The MCP surface is read-only and has no credential, arbitrary-header, account, deployment, or mutation parameters.

## Safety and limits

Release traversal rejects symlinks, unsafe paths, ambiguous cross-platform names, more than 10,000 files, and more than 64 GiB of input. Public verification accepts HTTPS only, restricts optional header checks to a small non-sensitive allowlist, streams responses, and caps each response at 64 MiB.

Public DNS results are checked against private and special-use address ranges. This local CLI check is not hardened hosted SSRF protection, so do not expose the verifier as an arbitrary-URL network service.

## Build from source

```sh
npm ci
npm test
npm run lint
npm run typecheck
npm run build:portable
npm run verify:package
```

The generated ZIP and checksum are written under `dist/` and remain build outputs rather than source authority.

## License

Original Valen Systems source is licensed under the MIT License in `LICENSE`. Bundled dependencies retain their own licenses; see `THIRD_PARTY_NOTICES.md` and `licenses/`. The bundle is not represented as MIT-only.
