import { execFile as execFileCallback } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { createReadStream } from 'node:fs';
import {
  lstat,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  writeFile
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { pathToFileURL } from 'node:url';

import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

import { canonicalJson } from '../src/canonical-json.mjs';
import { VERSION } from '../src/version.mjs';
import { PORTABLE_ARCHIVE, PORTABLE_FILES, PORTABLE_ROOT } from './build-portable.mjs';

const execFile = promisify(execFileCallback);
const APPROVED_TOOLS = Object.freeze([
  'create_release_manifest',
  'verify_public_release',
  'verify_release_folder'
]);
const WINDOWS_LAUNCHER = Buffer.from('@echo off\r\nnode "%~dp0cf-release-proof.mjs" %*\r\n');
const PRIVACY_PATTERNS = Object.freeze([
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/u,
  /\/Users\//u,
  /\/private\/(?:tmp|var)\//u,
  /\/data\/(?:work-control|private-owner)(?:\/|\b)/u,
  /\bprivate-owner\/work-control\b/iu,
  /\bprivate-host\b/iu,
  /\blocalhost:\d+\b/iu,
  /\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{8,}\b/u,
  /\bprice_[A-Za-z0-9]{8,}\b/u,
  /\b(?:CLOUDFLARE_API_TOKEN|CF_API_TOKEN|CF_ACCESS_CLIENT_SECRET|STRIPE_SECRET_KEY)\s*[:=]\s*[^\s"']{8,}/iu,
  /\bAuthorization:\s*Bearer\s+[A-Za-z0-9._~-]{8,}\b/iu
]);

/** @param {string} message @returns {never} */
function fail(message) {
  throw new Error(message);
}

/** @param {string} filePath */
async function sha256File(filePath) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(filePath)) hash.update(chunk);
  return hash.digest('hex');
}

/**
 * Reject names before extraction. Exact order is part of the deterministic ZIP contract.
 *
 * @param {unknown} entries
 * @returns {string[]}
 */
export function validateArchiveEntries(entries) {
  if (!Array.isArray(entries)) fail('Invalid archive entry list');
  const seen = new Set();
  for (const entry of entries) {
    if (typeof entry !== 'string') fail('Unsafe archive entry');
    const segments = entry.split('/');
    if (
      entry.length === 0 ||
      entry.startsWith('/') ||
      entry.endsWith('/') ||
      entry.includes('\\') ||
      /^[A-Za-z]:/u.test(entry) ||
      /[\u0000-\u001f\u007f]/u.test(entry) ||
      segments.some((segment) => segment === '' || segment === '.' || segment === '..') ||
      segments[0] !== PORTABLE_ROOT
    ) {
      fail('Unsafe archive entry');
    }
    if (seen.has(entry)) fail('Duplicate archive entry');
    seen.add(entry);
  }
  if (
    entries.length !== PORTABLE_FILES.length ||
    entries.some((entry, index) => entry !== PORTABLE_FILES[index])
  ) {
    fail('Archive allowlist mismatch');
  }
  return [...entries];
}

/** @param {string} archivePath @param {string[]} entries */
async function validateArchiveTypes(archivePath, entries) {
  const { stdout } = await execFile('/usr/bin/unzip', ['-Z', '-l', archivePath], {
    maxBuffer: 4 * 1024 * 1024
  });
  const lines = stdout.split('\n');
  for (const entry of entries) {
    const matching = lines.filter((line) => line.endsWith(` ${entry}`));
    if (matching.length !== 1 || !matching[0].startsWith('-')) fail('Archive entry is not regular');
  }
}

/** @param {string} root */
async function extractedFiles(root) {
  /** @type {string[]} */
  const files = [];
  /** @param {string} directory @param {string[]} segments */
  async function visit(directory, segments) {
    for (const name of await readdir(directory)) {
      const absolutePath = path.join(directory, name);
      const info = await lstat(absolutePath);
      if (info.isSymbolicLink()) fail('Extracted package contains a symlink');
      if (info.isDirectory()) await visit(absolutePath, [...segments, name]);
      else if (info.isFile()) files.push([...segments, name].join('/'));
      else fail('Extracted package contains a non-regular entry');
    }
  }
  await visit(root, []);
  return files.sort();
}

/** @param {string} extractedRoot */
async function scanPrivacy(extractedRoot) {
  for (const entry of PORTABLE_FILES) {
    const contents = new TextDecoder('utf-8', { fatal: true }).decode(
      await readFile(path.join(extractedRoot, ...entry.split('/')))
    );
    if (PRIVACY_PATTERNS.some((pattern) => pattern.test(contents))) {
      fail('Archive privacy scan failed');
    }
  }
}

/** @param {string} filePath @param {string[]} args @param {string} [cwd] */
async function run(filePath, args, cwd) {
  return execFile(filePath, args, { cwd, maxBuffer: 4 * 1024 * 1024 });
}

/** @param {string} outputPath @param {unknown} value */
async function writeEvidence(outputPath, value) {
  const temporaryPath = `${outputPath}.tmp-${process.pid}-${randomBytes(8).toString('hex')}`;
  try {
    await writeFile(temporaryPath, canonicalJson(value), { flag: 'wx', mode: 0o600 });
    await rename(temporaryPath, outputPath);
  } finally {
    await rm(temporaryPath, { force: true });
  }
}

/**
 * Verify one portable package entirely offline and optionally write its candidate evidence.
 *
 * @param {{packageRoot:string,archivePath:string,checksumPath:string,evidencePath?:string|null}} options
 */
export async function verifyPortablePackage({
  packageRoot,
  archivePath,
  checksumPath,
  evidencePath = null
}) {
  const sidecar = await readFile(checksumPath, 'utf8');
  const sidecarMatch = /^([0-9a-f]{64})  ([^\r\n]+)\n$/u.exec(sidecar);
  if (sidecarMatch === null || sidecarMatch[2] !== path.basename(archivePath)) {
    fail('Invalid archive checksum sidecar');
  }
  const sha256 = await sha256File(archivePath);
  if (sha256 !== sidecarMatch[1]) fail('Archive checksum mismatch');

  const listing = await execFile('/usr/bin/unzip', ['-Z1', archivePath], {
    maxBuffer: 4 * 1024 * 1024
  });
  const entries = validateArchiveEntries(listing.stdout.trimEnd().split('\n'));
  await validateArchiveTypes(archivePath, entries);

  const extractionRoot = await mkdtemp(path.join(tmpdir(), 'release-proof-package-verify-'));
  const smokeRoot = await mkdtemp(path.join(tmpdir(), 'release-proof-package-smoke-'));
  try {
    await execFile('/usr/bin/unzip', ['-q', archivePath, '-d', extractionRoot], {
      maxBuffer: 4 * 1024 * 1024
    });
    const packageDirectory = path.join(extractionRoot, PORTABLE_ROOT);
    const files = await extractedFiles(extractionRoot);
    if (files.length !== entries.length || files.some((entry, index) => entry !== entries[index])) {
      fail('Extracted package allowlist mismatch');
    }
    await scanPrivacy(extractionRoot);

    const bundle = path.join(packageDirectory, 'cf-release-proof.mjs');
    const launcher = path.join(packageDirectory, 'cf-release-proof');
    const cmdLauncher = path.join(packageDirectory, 'cf-release-proof.cmd');
    const exampleFolder = path.join(packageDirectory, 'examples/release');
    const exampleManifest = path.join(packageDirectory, 'examples/release-manifest.json');
    const generatedManifest = path.join(smokeRoot, 'release-manifest.json');

    const version = await run(process.execPath, [bundle, '--version']);
    if (version.stdout !== `${VERSION}\n` || version.stderr !== '') fail('Bundled CLI version smoke failed');
    const created = await run(process.execPath, [
      bundle,
      'manifest',
      'create',
      exampleFolder,
      '--output',
      generatedManifest
    ]);
    if (created.stdout !== '' || created.stderr !== 'Manifest written.\n') {
      fail('Bundled CLI manifest-create smoke failed');
    }
    const generatedManifestText = await readFile(generatedManifest, 'utf8');
    if (generatedManifestText !== await readFile(exampleManifest, 'utf8')) {
      fail('Bundled CLI manifest differs from example');
    }
    const verified = await run(process.execPath, [
      bundle,
      'manifest',
      'verify',
      exampleFolder,
      '--manifest',
      generatedManifest
    ]);
    const receipt = JSON.parse(verified.stdout);
    if (verified.stderr !== 'Local release matches manifest.\n' || receipt.result?.outcome !== 'match') {
      fail('Bundled CLI local verification smoke failed');
    }
    const launcherVersion = await run(launcher, ['--version'], packageDirectory);
    if (launcherVersion.stdout !== `${VERSION}\n` || launcherVersion.stderr !== '') {
      fail('POSIX launcher smoke failed');
    }
    if (!Buffer.from(await readFile(cmdLauncher)).equals(WINDOWS_LAUNCHER)) {
      fail('Windows launcher bytes are invalid');
    }

    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [bundle, 'mcp', '--root', packageDirectory],
      cwd: packageDirectory,
      stderr: 'pipe'
    });
    const client = new Client({ name: 'release-proof-package-verifier', version: VERSION });
    let listedTools;
    let mcpManifest;
    try {
      await client.connect(transport);
      listedTools = (await client.listTools()).tools.map((tool) => tool.name).sort();
      if (listedTools.length !== APPROVED_TOOLS.length || listedTools.some((tool, index) => tool !== APPROVED_TOOLS[index])) {
        fail('Bundled MCP tool allowlist mismatch');
      }
      const result = await client.callTool({
        name: 'create_release_manifest',
        arguments: { folder: 'examples/release' }
      });
      if (result.isError || result.structuredContent === undefined) fail('Bundled MCP manifest smoke failed');
      mcpManifest = result.structuredContent;
      if (canonicalJson(mcpManifest) !== generatedManifestText) fail('Bundled MCP manifest differs from CLI');
    } finally {
      await client.close().catch(() => {});
    }

    const sourceCommit = (await run('git', ['rev-parse', 'HEAD'], path.resolve(packageRoot))).stdout.trim();
    const npmVersion = (await run('npm', ['--version'], path.resolve(packageRoot))).stdout.trim();
    const evidence = {
      schemaVersion: 1,
      candidateVersion: VERSION,
      sourceCommit,
      runtime: { node: process.version, npm: npmVersion },
      artifact: {
        file: path.basename(archivePath),
        checksumFile: path.basename(checksumPath),
        bytes: (await stat(archivePath)).size,
        sha256,
        entries
      },
      verification: {
        checksum: true,
        archiveEntries: true,
        extractedFiles: true,
        privacyScan: true,
        cliVersion: true,
        cliManifestMatch: true,
        cliVerificationOutcome: receipt.result.outcome,
        posixLauncher: true,
        windowsLauncherBytes: true,
        mcpTools: listedTools,
        mcpManifestMatch: canonicalJson(mcpManifest) === generatedManifestText,
        networkCalls: 0
      },
      state: {
        implemented: true,
        tested: true,
        archiveVerified: true,
        ownerAccepted: false,
        public: false,
        deployed: false,
        toolsPage: false,
        fieldNotes: false,
        observedUse: false,
        revenue: false
      }
    };
    if (evidencePath !== null) await writeEvidence(path.resolve(evidencePath), evidence);
    return evidence;
  } finally {
    await rm(extractionRoot, { recursive: true, force: true });
    await rm(smokeRoot, { recursive: true, force: true });
  }
}

const isMain =
  process.argv[1] !== undefined && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
if (isMain) {
  try {
    const args = process.argv.slice(2);
    let evidencePath = null;
    if (args.length === 2 && args[0] === '--evidence') evidencePath = path.resolve(args[1]);
    else if (args.length !== 0) throw new Error('unexpected arguments');
    const packageRoot = path.resolve(import.meta.dirname, '..');
    const evidence = await verifyPortablePackage({
      packageRoot,
      archivePath: path.join(packageRoot, 'dist', PORTABLE_ARCHIVE),
      checksumPath: path.join(packageRoot, 'dist', `${PORTABLE_ARCHIVE}.sha256`),
      evidencePath
    });
    process.stderr.write(`Verified ${PORTABLE_ARCHIVE} (${evidence.artifact.bytes} bytes, ${evidence.artifact.sha256})\n`);
  } catch {
    process.stderr.write('PACKAGE_VERIFY_FAILED: Portable package was not verified\n');
    process.exitCode = 1;
  }
}
