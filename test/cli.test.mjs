import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, readdir, symlink, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import test from 'node:test';

import { canonicalJson } from '../src/canonical-json.mjs';
import { AppError, EXIT_CODES } from '../src/errors.mjs';
import { parseCli, runCli } from '../src/cli.mjs';
import { makeTempDirectory, writeTree } from './helpers.mjs';

const PACKAGE_ROOT = fileURLToPath(new URL('..', import.meta.url));
const CLI_PATH = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));
const HELP = `Usage:
  cf-release-proof manifest create <folder> --output <manifest.json>
  cf-release-proof manifest verify <folder> --manifest <manifest.json> [--output <receipt.json>]
  cf-release-proof public verify --base-url <https-url> --manifest <manifest.json> [--expect-header <name=value>] [--output <receipt.json>]
  cf-release-proof mcp --root <folder>
  cf-release-proof --help
  cf-release-proof --version
`;

/** @param {string} command @param {string[]} args */
function spawnProcess(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: PACKAGE_ROOT,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('error', reject);
    child.on('close', (exitCode, signal) => resolve({ exitCode, signal, stdout, stderr }));
  });
}

/** @param {string[]} args */
function spawnCli(args) {
  return spawnProcess(process.execPath, [CLI_PATH, ...args]);
}

function captureStream() {
  let value = '';
  return {
    stream: {
      write(chunk) {
        value += String(chunk);
        return true;
      }
    },
    read() {
      return value;
    }
  };
}

/** @param {unknown} error */
function isInvalid(error) {
  assert.equal(error instanceof AppError, true);
  assert.equal(error.exitCode, EXIT_CODES.invalid);
  return true;
}

test('parseCli accepts only the documented command shapes', () => {
  const cases = [
    [['--help'], { command: 'help' }],
    [['--version'], { command: 'version' }],
    [
      ['manifest', 'create', 'release', '--output', 'manifest.json'],
      { command: 'manifest-create', folder: 'release', output: 'manifest.json' }
    ],
    [
      ['manifest', 'verify', 'release', '--manifest', 'manifest.json'],
      { command: 'manifest-verify', folder: 'release', manifest: 'manifest.json', output: null }
    ],
    [
      ['public', 'verify', '--base-url', 'https://example.com/release/', '--manifest', 'manifest.json', '--expect-header', 'x-release=v1', '--output', 'receipt.json'],
      { command: 'public-verify', baseUrl: 'https://example.com/release/', manifest: 'manifest.json', expectHeader: 'x-release=v1', output: 'receipt.json' }
    ],
    [['mcp', '--root', 'release'], { command: 'mcp', root: 'release' }]
  ];

  for (const [argv, expected] of cases) assert.deepEqual(parseCli(argv), expected);

  for (const argv of [
    [],
    ['manifest', 'create', 'release', '--output', 'one.json', '--output', 'two.json'],
    ['manifest', 'verify', 'release', '--manifest'],
    ['manifest', 'create', 'release', 'extra', '--output', 'manifest.json'],
    ['public', 'verify', '--base-url', 'https://example.com/', '--manifest', 'manifest.json', '--unknown', 'value'],
    ['public', 'verify', '--base-url', 'https://example.com/', '--manifest', 'manifest.json', '--token', 'secret'],
    ['mcp', '--root', 'release', '--output', 'receipt.json'],
    ['x'.repeat(4097)]
  ]) {
    assert.throws(() => parseCli(argv), isInvalid);
  }
});

test('CLI help and version keep their exact streams separate', async () => {
  assert.deepEqual(await spawnCli(['--help']), {
    exitCode: 0,
    signal: null,
    stdout: '',
    stderr: HELP
  });
  assert.deepEqual(await spawnCli(['--version']), {
    exitCode: 0,
    signal: null,
    stdout: '0.1.0\n',
    stderr: ''
  });
});

test('the declared CLI entrypoint runs through an npm-style symlink', async (t) => {
  const binRoot = await makeTempDirectory(t, 'cf-release-proof-bin-');
  const cliLink = path.join(binRoot, 'cf-release-proof');
  await symlink(CLI_PATH, cliLink);

  assert.deepEqual(await spawnProcess(cliLink, ['--version']), {
    exitCode: 0,
    signal: null,
    stdout: '0.1.0\n',
    stderr: ''
  });
});

test('manifest create writes canonical JSON atomically and excludes its explicit output', async (t) => {
  const parent = await makeTempDirectory(t, 'cf-release-proof-cli-');
  const folder = path.join(parent, 'release ü space');
  const output = path.join(folder, 'manifest.json');
  await writeTree(folder, { 'asset.txt': 'abc', 'manifest.json': 'stale output' });

  const result = await spawnCli(['manifest', 'create', folder, '--output', output]);
  assert.equal(result.exitCode, EXIT_CODES.success);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, 'Manifest written.\n');

  const text = await readFile(output, 'utf8');
  const manifest = JSON.parse(text);
  assert.equal(text, canonicalJson(manifest));
  assert.deepEqual(manifest.entries.map((entry) => entry.path), ['asset.txt']);
  assert.deepEqual((await readdir(folder)).filter((name) => name.includes('.tmp-')), []);
});

test('local verification emits stdout or an atomic file and maps match/mismatch exits', async (t) => {
  const folder = await makeTempDirectory(t, 'cf-release-proof-cli-local-');
  const manifestPath = path.join(folder, 'manifest.json');
  const receiptPath = path.join(folder, 'receipt.json');
  await writeTree(folder, { 'asset.txt': 'abc' });

  assert.equal((await spawnCli(['manifest', 'create', folder, '--output', manifestPath])).exitCode, 0);
  const match = await spawnCli(['manifest', 'verify', folder, '--manifest', manifestPath]);
  assert.equal(match.exitCode, EXIT_CODES.success);
  const matchReceipt = JSON.parse(match.stdout);
  assert.equal(match.stdout, canonicalJson(matchReceipt));
  assert.equal(matchReceipt.result.outcome, 'match');
  assert.equal(match.stderr, 'Local release matches manifest.\n');

  await writeFile(path.join(folder, 'asset.txt'), 'changed');
  const mismatch = await spawnCli([
    'manifest', 'verify', folder, '--manifest', manifestPath, '--output', receiptPath
  ]);
  assert.equal(mismatch.exitCode, EXIT_CODES.mismatch);
  assert.equal(mismatch.stdout, '');
  assert.equal(mismatch.stderr, 'Local release differs from manifest.\n');
  const receiptText = await readFile(receiptPath, 'utf8');
  assert.equal(receiptText, canonicalJson(JSON.parse(receiptText)));
  assert.equal(JSON.parse(receiptText).result.outcome, 'mismatch');
  assert.deepEqual((await readdir(folder)).filter((name) => name.includes('.tmp-')), []);
});

test('public verification uses injected transport and maps match/unverified exits', async (t) => {
  const root = await makeTempDirectory(t, 'cf-release-proof-cli-public-');
  const manifestPath = path.join(root, 'manifest.json');
  const payload = 'abc';
  const manifest = {
    schemaVersion: 1,
    algorithm: 'sha256',
    pathEncoding: 'utf8-nfc',
    entries: [{
      path: 'asset.txt',
      bytes: Buffer.byteLength(payload),
      sha256: createHash('sha256').update(payload).digest('hex')
    }]
  };
  await writeFile(manifestPath, canonicalJson(manifest));
  const lookup = async () => [{ address: '1.1.1.1', family: 4 }];

  const matchedOut = captureStream();
  const matchedErr = captureStream();
  const matchedCode = await runCli([
    'public', 'verify', '--base-url', 'https://public.example/release/', '--manifest', manifestPath
  ], {
    cwd: root,
    stdout: matchedOut.stream,
    stderr: matchedErr.stream,
    fetch: async () => new Response(payload),
    lookup
  });
  assert.equal(matchedCode, EXIT_CODES.success);
  assert.equal(JSON.parse(matchedOut.read()).result.outcome, 'match');
  assert.equal(matchedErr.read(), 'Public release matches manifest.\n');

  const failedOut = captureStream();
  const failedErr = captureStream();
  const failedCode = await runCli([
    'public', 'verify', '--base-url', 'https://public.example/release/', '--manifest', manifestPath
  ], {
    cwd: root,
    stdout: failedOut.stream,
    stderr: failedErr.stream,
    fetch: async () => {
      throw new Error('private transport detail');
    },
    lookup
  });
  assert.equal(failedCode, EXIT_CODES.network);
  assert.equal(JSON.parse(failedOut.read()).result.outcome, 'unverified');
  assert.equal(failedErr.read(), 'Public release could not be fully verified.\n');
  assert.equal(failedErr.read().includes('private transport detail'), false);
});

test('invalid input returns 64 without partial JSON or absolute-path leakage', async (t) => {
  const root = await makeTempDirectory(t, 'cf-release-proof-cli-private-');
  const malformed = path.join(root, 'private-manifest.json');
  await writeFile(malformed, '{not json');

  const result = await spawnCli(['manifest', 'verify', root, '--manifest', malformed]);
  assert.equal(result.exitCode, EXIT_CODES.invalid);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr.includes(root), false);
  assert.match(result.stderr, /^INVALID_MANIFEST: /u);

  const missingPath = path.join(root, 'missing-private-manifest.json');
  const missing = await spawnCli(['manifest', 'verify', root, '--manifest', missingPath]);
  assert.equal(missing.exitCode, EXIT_CODES.invalid);
  assert.equal(missing.stdout, '');
  assert.equal(missing.stderr, 'MANIFEST_READ_FAILED: Manifest could not be read\n');

  for (const argv of [['mcp'], ['mcp', '--root', root, '--output', 'receipt.json']]) {
    const invalid = await spawnCli(argv);
    assert.equal(invalid.exitCode, EXIT_CODES.invalid);
    assert.equal(invalid.stdout, '');
    assert.equal(invalid.stderr.includes(root), false);
  }
});

test('unexpected failures return only the stable internal diagnostic', async () => {
  const stderr = captureStream();
  const exitCode = await runCli(['--version'], {
    stdout: {
      write() {
        throw new Error('/private/raw/error');
      }
    },
    stderr: stderr.stream
  });

  assert.equal(exitCode, EXIT_CODES.internal);
  assert.equal(stderr.read(), 'INTERNAL_ERROR: Release proof failed\n');
});
