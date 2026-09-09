#!/usr/bin/env node

import { randomBytes } from 'node:crypto';
import { readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from './canonical-json.mjs';
import { AppError, EXIT_CODES } from './errors.mjs';
import { verifyReleaseFolder } from './local-verify.mjs';
import { createReleaseManifest, parseReleaseManifest } from './manifest.mjs';
import { normalizeManifestPath } from './paths.mjs';
import { verifyPublicRelease } from './public-verify.mjs';
import { VERSION } from './version.mjs';

const MAX_ARGUMENTS = 16;
const MAX_ARGUMENT_LENGTH = 4096;
const MCP_MODULE = './mcp.mjs';
const CREDENTIAL_OPTIONS = new Set(['--authorization', '--cookie', '--header', '--token']);
const HELP = `Usage:
  cf-release-proof manifest create <folder> --output <manifest.json>
  cf-release-proof manifest verify <folder> --manifest <manifest.json> [--output <receipt.json>]
  cf-release-proof public verify --base-url <https-url> --manifest <manifest.json> [--expect-header <name=value>] [--output <receipt.json>]
  cf-release-proof mcp --root <folder>
  cf-release-proof --help
  cf-release-proof --version
`;

/** @typedef {{command:'help'}} HelpCommand */
/** @typedef {{command:'version'}} VersionCommand */
/** @typedef {{command:'manifest-create',folder:string,output:string}} ManifestCreateCommand */
/** @typedef {{command:'manifest-verify',folder:string,manifest:string,output:string|null}} ManifestVerifyCommand */
/** @typedef {{command:'public-verify',baseUrl:string,manifest:string,expectHeader:string|null,output:string|null}} PublicVerifyCommand */
/** @typedef {{command:'mcp',root:string}} McpCommand */
/** @typedef {HelpCommand|VersionCommand|ManifestCreateCommand|ManifestVerifyCommand|PublicVerifyCommand|McpCommand} CliCommand */

/** @param {string} message @param {string} [code] */
function invalid(message, code = 'INVALID_ARGUMENTS') {
  return new AppError(message, EXIT_CODES.invalid, code);
}

/**
 * @param {string[]} tokens
 * @param {Set<string>} allowedOptions
 * @param {number} positionalCount
 */
function parseTail(tokens, allowedOptions, positionalCount) {
  /** @type {string[]} */
  const positionals = [];
  /** @type {Map<string, string>} */
  const options = new Map();

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (!token.startsWith('--')) {
      positionals.push(token);
      continue;
    }
    if (!allowedOptions.has(token)) throw invalid('Unknown command option');
    if (options.has(token)) throw invalid('Duplicate command option');
    const value = tokens[index + 1];
    if (value === undefined || value.startsWith('--')) throw invalid('Command option is missing a value');
    options.set(token, value);
    index += 1;
  }

  if (positionals.length !== positionalCount) throw invalid('Invalid command arguments');
  return { positionals, options };
}

/**
 * Parse the intentionally small, non-interactive v0.1 command grammar.
 *
 * @param {string[]} argv
 * @returns {CliCommand}
 */
export function parseCli(argv) {
  if (
    !Array.isArray(argv) ||
    argv.length === 0 ||
    argv.length > MAX_ARGUMENTS ||
    argv.some((argument) =>
      typeof argument !== 'string' || argument.length === 0 || argument.length > MAX_ARGUMENT_LENGTH
    )
  ) {
    throw invalid('Invalid command arguments');
  }
  if (argv.some((argument) => CREDENTIAL_OPTIONS.has(argument.toLowerCase()))) {
    throw invalid('Credential options are not supported', 'UNSUPPORTED_CREDENTIAL_OPTION');
  }

  if (argv.length === 1 && argv[0] === '--help') return { command: 'help' };
  if (argv.length === 1 && argv[0] === '--version') return { command: 'version' };

  if (argv[0] === 'manifest' && argv[1] === 'create') {
    const { positionals, options } = parseTail(argv.slice(2), new Set(['--output']), 1);
    const output = options.get('--output');
    if (output === undefined) throw invalid('Manifest output is required');
    return {
      command: 'manifest-create',
      folder: /** @type {string} */ (positionals[0]),
      output
    };
  }

  if (argv[0] === 'manifest' && argv[1] === 'verify') {
    const { positionals, options } = parseTail(
      argv.slice(2),
      new Set(['--manifest', '--output']),
      1
    );
    const manifest = options.get('--manifest');
    if (manifest === undefined) throw invalid('Manifest input is required');
    return {
      command: 'manifest-verify',
      folder: /** @type {string} */ (positionals[0]),
      manifest,
      output: options.get('--output') ?? null
    };
  }

  if (argv[0] === 'public' && argv[1] === 'verify') {
    const { options } = parseTail(
      argv.slice(2),
      new Set(['--base-url', '--manifest', '--expect-header', '--output']),
      0
    );
    const baseUrl = options.get('--base-url');
    const manifest = options.get('--manifest');
    if (baseUrl === undefined || manifest === undefined) {
      throw invalid('Public target and manifest are required');
    }
    return {
      command: 'public-verify',
      baseUrl,
      manifest,
      expectHeader: options.get('--expect-header') ?? null,
      output: options.get('--output') ?? null
    };
  }

  if (argv[0] === 'mcp') {
    const { options } = parseTail(argv.slice(1), new Set(['--root']), 0);
    const root = options.get('--root');
    if (root === undefined) throw invalid('MCP root is required');
    return { command: 'mcp', root };
  }

  throw invalid('Unknown command');
}

/** @param {string} root @param {string} candidate */
function descendantManifestPath(root, candidate) {
  const relative = path.relative(root, candidate);
  if (
    relative === '' ||
    relative === '..' ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    return null;
  }
  return normalizeManifestPath(relative.split(path.sep).join('/'));
}

/** @param {Array<string | null>} candidates */
function exclusions(candidates) {
  return new Set(candidates.filter((candidate) => candidate !== null));
}

/** @param {string} manifestPath */
async function readManifest(manifestPath) {
  let bytes;
  try {
    bytes = await readFile(manifestPath);
  } catch {
    throw invalid('Manifest could not be read', 'MANIFEST_READ_FAILED');
  }
  return parseReleaseManifest(bytes);
}

/** @param {string} outputPath @param {unknown} value */
async function writeCanonicalFile(outputPath, value) {
  const temporaryPath = `${outputPath}.tmp-${process.pid}-${randomBytes(8).toString('hex')}`;
  try {
    await writeFile(temporaryPath, canonicalJson(value), { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    await rename(temporaryPath, outputPath);
  } catch {
    try {
      await rm(temporaryPath, { force: true });
    } catch {
      // Cleanup is best effort and its native error is never exposed.
    }
    throw invalid('Output could not be written', 'OUTPUT_WRITE_FAILED');
  }
}

/** @param {unknown} outcome */
function verificationExit(outcome) {
  if (outcome === 'match') return EXIT_CODES.success;
  if (outcome === 'mismatch') return EXIT_CODES.mismatch;
  if (outcome === 'unverified') return EXIT_CODES.network;
  throw new Error('Unexpected verification result');
}

/** @param {AppError} error */
function boundedDiagnostic(error) {
  return `${error.code}: ${error.message}`.replace(/[\u0000-\u001f\u007f]+/gu, ' ').slice(0, 512);
}

/**
 * Execute one CLI command without terminating the host process.
 *
 * @param {string[]} argv
 * @param {{cwd?:string,stdout?:Pick<NodeJS.WritableStream,'write'>,stderr?:Pick<NodeJS.WritableStream,'write'>,observationTime?:string|null,fetch?:typeof fetch,lookup?:typeof import('node:dns/promises').lookup}} [options]
 */
export async function runCli(argv, {
  cwd = process.cwd(),
  stdout = process.stdout,
  stderr = process.stderr,
  observationTime = null,
  fetch: fetchImpl = globalThis.fetch,
  lookup
} = {}) {
  try {
    const command = parseCli(argv);

    if (command.command === 'help') {
      stderr.write(HELP);
      return EXIT_CODES.success;
    }
    if (command.command === 'version') {
      stdout.write(`${VERSION}\n`);
      return EXIT_CODES.success;
    }
    if (command.command === 'manifest-create') {
      const folder = path.resolve(cwd, command.folder);
      const output = path.resolve(cwd, command.output);
      const exclude = exclusions([descendantManifestPath(folder, output)]);
      const manifest = await createReleaseManifest(folder, { exclude });
      await writeCanonicalFile(output, manifest);
      stderr.write('Manifest written.\n');
      return EXIT_CODES.success;
    }
    if (command.command === 'manifest-verify') {
      const folder = path.resolve(cwd, command.folder);
      const manifestPath = path.resolve(cwd, command.manifest);
      const output = command.output === null ? null : path.resolve(cwd, command.output);
      const manifest = await readManifest(manifestPath);
      const exclude = exclusions([
        descendantManifestPath(folder, manifestPath),
        output === null ? null : descendantManifestPath(folder, output)
      ]);
      const receipt = await verifyReleaseFolder(folder, manifest, { exclude, observationTime });
      if (output === null) stdout.write(canonicalJson(receipt));
      else await writeCanonicalFile(output, receipt);
      stderr.write(
        receipt.result.outcome === 'match'
          ? 'Local release matches manifest.\n'
          : 'Local release differs from manifest.\n'
      );
      return verificationExit(receipt.result.outcome);
    }
    if (command.command === 'public-verify') {
      const manifestPath = path.resolve(cwd, command.manifest);
      const output = command.output === null ? null : path.resolve(cwd, command.output);
      const manifest = await readManifest(manifestPath);
      const receipt = await verifyPublicRelease(command.baseUrl, manifest, {
        expectHeader: command.expectHeader ?? undefined,
        fetch: fetchImpl,
        lookup,
        observationTime
      });
      if (output === null) stdout.write(canonicalJson(receipt));
      else await writeCanonicalFile(output, receipt);
      if (receipt.result.outcome === 'match') stderr.write('Public release matches manifest.\n');
      else if (receipt.result.outcome === 'mismatch') stderr.write('Public release differs from manifest.\n');
      else stderr.write('Public release could not be fully verified.\n');
      return verificationExit(receipt.result.outcome);
    }

    const mcp = await import(MCP_MODULE);
    await mcp.startMcpServer(path.resolve(cwd, command.root), { stderr, fetch: fetchImpl, lookup });
    return EXIT_CODES.success;
  } catch (error) {
    if (error instanceof AppError) {
      stderr.write(`${boundedDiagnostic(error)}\n`);
      return error.exitCode;
    }
    stderr.write('INTERNAL_ERROR: Release proof failed\n');
    return EXIT_CODES.internal;
  }
}

async function isMainModule() {
  if (process.argv[1] === undefined) return false;
  try {
    const [executedPath, modulePath] = await Promise.all([
      realpath(path.resolve(process.argv[1])),
      realpath(fileURLToPath(import.meta.url))
    ]);
    return executedPath === modulePath;
  } catch {
    return false;
  }
}

if (await isMainModule()) process.exitCode = await runCli(process.argv.slice(2));
