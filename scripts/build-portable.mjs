import { execFile as execFileCallback } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { createReadStream } from 'node:fs';
import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  stat,
  utimes,
  writeFile
} from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import { pathToFileURL } from 'node:url';

import { build as esbuild } from 'esbuild';

import { VERSION } from '../src/version.mjs';

const execFile = promisify(execFileCallback);
const FIXED_TIME = new Date('2000-01-01T00:00:00Z');

export const PORTABLE_ROOT = `cloudflare-release-proof-v${VERSION}`;
export const PORTABLE_ARCHIVE = `${PORTABLE_ROOT}-portable.zip`;
export const PORTABLE_FILES = Object.freeze(
  [
    'cf-release-proof.mjs',
    'cf-release-proof',
    'cf-release-proof.cmd',
    'README.md',
    'LICENSE',
    'THIRD_PARTY_NOTICES.md',
    'licenses/MCP-LICENSE.txt',
    'licenses/zod-LICENSE.txt',
    'licenses/esbuild-LICENSE.txt',
    'schemas/release-manifest-v1.schema.json',
    'examples/release/hello.txt',
    'examples/release-manifest.json'
  ]
    .map((relativePath) => `${PORTABLE_ROOT}/${relativePath}`)
    .sort()
);

const COPIED_FILES = Object.freeze({
  'README.md': 'README.md',
  LICENSE: 'LICENSE',
  'THIRD_PARTY_NOTICES.md': 'THIRD_PARTY_NOTICES.md',
  'licenses/MCP-LICENSE.txt': 'licenses/MCP-LICENSE.txt',
  'licenses/zod-LICENSE.txt': 'licenses/zod-LICENSE.txt',
  'licenses/esbuild-LICENSE.txt': 'licenses/esbuild-LICENSE.txt',
  'schemas/release-manifest-v1.schema.json': 'schemas/release-manifest-v1.schema.json',
  'examples/release/hello.txt': 'examples/release/hello.txt',
  'examples/release-manifest.json': 'examples/release-manifest.json'
});

const POSIX_LAUNCHER = `#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec node "$SCRIPT_DIR/cf-release-proof.mjs" "$@"
`;
const WINDOWS_LAUNCHER = '@echo off\r\nnode "%~dp0cf-release-proof.mjs" %*\r\n';

/** @param {string} filePath */
async function sha256File(filePath) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(filePath)) hash.update(chunk);
  return hash.digest('hex');
}

/**
 * Build one allowlisted portable ZIP without placing dependencies or source trees in it.
 *
 * @param {{packageRoot:string,outDir:string}} options
 */
export async function buildPortable({ packageRoot, outDir }) {
  const resolvedPackageRoot = path.resolve(packageRoot);
  const resolvedOutDir = path.resolve(outDir);
  await mkdir(resolvedOutDir, { recursive: true });
  const stage = await mkdtemp(path.join(resolvedOutDir, '.portable-stage-'));
  const stagedRoot = path.join(stage, PORTABLE_ROOT);
  const nonce = `${process.pid}-${randomBytes(8).toString('hex')}`;
  const archivePath = path.join(resolvedOutDir, PORTABLE_ARCHIVE);
  const checksumPath = `${archivePath}.sha256`;
  const temporaryArchive = path.join(resolvedOutDir, `.${PORTABLE_ARCHIVE}.${nonce}.tmp`);
  const temporaryChecksum = `${temporaryArchive}.sha256`;

  try {
    await mkdir(stagedRoot, { recursive: true });
    const entryPoint = path.join(resolvedPackageRoot, 'src/cli.mjs');
    await esbuild({
      entryPoints: [entryPoint],
      outfile: path.join(stagedRoot, 'cf-release-proof.mjs'),
      bundle: true,
      platform: 'node',
      format: 'esm',
      target: 'node22',
      sourcemap: false,
      legalComments: 'none',
      logLevel: 'silent',
      plugins: [
        {
          name: 'bundle-release-proof-mcp',
          setup(build) {
            build.onLoad({ filter: /[/\\]src[/\\]cli\.mjs$/ }, async (args) => {
              const source = await readFile(args.path, 'utf8');
              const contents = source.replace('import(MCP_MODULE)', "import('./mcp.mjs')");
              if (contents === source) throw new Error('CLI MCP import boundary was not found');
              return { contents, loader: 'js' };
            });
          }
        }
      ]
    });

    await writeFile(path.join(stagedRoot, 'cf-release-proof'), POSIX_LAUNCHER);
    await writeFile(path.join(stagedRoot, 'cf-release-proof.cmd'), WINDOWS_LAUNCHER);
    for (const [destination, source] of Object.entries(COPIED_FILES)) {
      const stagedPath = path.join(stagedRoot, ...destination.split('/'));
      await mkdir(path.dirname(stagedPath), { recursive: true });
      await copyFile(path.join(resolvedPackageRoot, ...source.split('/')), stagedPath);
    }

    for (const entry of PORTABLE_FILES) {
      const relativePath = entry.slice(PORTABLE_ROOT.length + 1);
      const stagedPath = path.join(stagedRoot, ...relativePath.split('/'));
      const executable = relativePath === 'cf-release-proof.mjs' || relativePath === 'cf-release-proof';
      await chmod(stagedPath, executable ? 0o755 : 0o644);
      await utimes(stagedPath, FIXED_TIME, FIXED_TIME);
    }

    await execFile('/usr/bin/zip', ['-X', '-q', temporaryArchive, ...PORTABLE_FILES], {
      cwd: stage,
      maxBuffer: 4 * 1024 * 1024
    });
    const sha256 = await sha256File(temporaryArchive);
    const bytes = (await stat(temporaryArchive)).size;
    await writeFile(temporaryChecksum, `${sha256}  ${PORTABLE_ARCHIVE}\n`, {
      flag: 'wx',
      mode: 0o644
    });
    await rename(temporaryArchive, archivePath);
    await rename(temporaryChecksum, checksumPath);
    return {
      archivePath,
      checksumPath,
      sha256,
      bytes,
      entries: [...PORTABLE_FILES]
    };
  } finally {
    await rm(stage, { recursive: true, force: true });
    await rm(temporaryArchive, { force: true });
    await rm(temporaryChecksum, { force: true });
  }
}

const isMain =
  process.argv[1] !== undefined && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
if (isMain) {
  try {
    if (process.argv.length !== 2) throw new Error('unexpected arguments');
    const packageRoot = path.resolve(import.meta.dirname, '..');
    const result = await buildPortable({ packageRoot, outDir: path.join(packageRoot, 'dist') });
    process.stderr.write(`Built ${PORTABLE_ARCHIVE} (${result.bytes} bytes, ${result.sha256})\n`);
  } catch {
    process.stderr.write('PACKAGE_BUILD_FAILED: Portable package was not built\n');
    process.exitCode = 1;
  }
}
