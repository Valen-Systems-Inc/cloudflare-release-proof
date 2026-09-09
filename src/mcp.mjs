import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';

import { AppError, EXIT_CODES } from './errors.mjs';
import { verifyReleaseFolder } from './local-verify.mjs';
import { createReleaseManifest, parseReleaseManifest } from './manifest.mjs';
import {
  isSafeMcpFilePath,
  isSafeMcpFolderPath,
  normalizeManifestPath,
  resolveReadableRoot,
  resolveRootedDirectory,
  resolveRootedFile
} from './paths.mjs';
import { verifyPublicRelease } from './public-verify.mjs';
import { VERSION } from './version.mjs';

const MAX_ERROR_TEXT = 512;
const READ_ONLY_ANNOTATIONS = Object.freeze({
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false
});
const PUBLIC_READ_ONLY_ANNOTATIONS = Object.freeze({
  ...READ_ONLY_ANNOTATIONS,
  openWorldHint: true
});

const safeFolder = z
  .string()
  .max(1024)
  .refine((value) => isSafeMcpFolderPath(value), 'Folder must be a safe relative path');
const safeFile = z
  .string()
  .max(1024)
  .refine((value) => isSafeMcpFilePath(value), 'File must be a safe relative path');

const createManifestInput = z.strictObject({
  folder: safeFolder.default('.')
});
const verifyFolderInput = z.strictObject({
  folder: safeFolder.default('.'),
  manifestPath: safeFile
});
const verifyPublicInput = z.strictObject({
  manifestPath: safeFile,
  baseUrl: z.string().min(1).max(2048),
  expectHeader: z.string().min(1).max(1024).optional()
});

/**
 * @param {string} message
 * @param {string} code
 */
function invalid(message, code) {
  return new AppError(message, EXIT_CODES.invalid, code);
}

/** @param {string} value */
function boundedText(value) {
  if (value.length <= MAX_ERROR_TEXT) return value;
  return `${value.slice(0, MAX_ERROR_TEXT - 3)}...`;
}

/**
 * @param {unknown} error
 * @returns {import('@modelcontextprotocol/server').CallToolResult}
 */
function toolError(error) {
  const text =
    error instanceof AppError
      ? boundedText(`${error.code}: ${error.message}`)
      : 'INTERNAL_ERROR: Release proof failed';
  return { isError: true, content: [{ type: 'text', text }] };
}

/**
 * @param {string} text
 * @param {Record<string, unknown>} structuredContent
 * @returns {import('@modelcontextprotocol/server').CallToolResult}
 */
function toolSuccess(text, structuredContent) {
  return { content: [{ type: 'text', text }], structuredContent };
}

/**
 * @param {string} manifestPath
 */
async function readManifest(manifestPath) {
  try {
    return parseReleaseManifest(await readFile(manifestPath));
  } catch (error) {
    if (error instanceof AppError) throw error;
    throw invalid('Release manifest could not be read', 'MANIFEST_READ_FAILED');
  }
}

/**
 * Exclude the manifest itself only when it is strictly below the selected
 * release folder. Both paths have already passed rooted realpath checks.
 *
 * @param {string} folder
 * @param {string} manifestPath
 * @returns {Set<string> | undefined}
 */
function manifestExclusion(folder, manifestPath) {
  const relative = path.relative(folder, manifestPath);
  if (
    relative === '' ||
    path.isAbsolute(relative) ||
    relative === '..' ||
    relative.startsWith(`..${path.sep}`)
  ) {
    return undefined;
  }
  const portable = normalizeManifestPath(relative.split(path.sep).join('/'));
  return new Set([portable]);
}

/**
 * Construct the rooted, read-only release proof MCP server.
 *
 * @param {{resolvedRoot:string,fetch?:typeof globalThis.fetch,lookup?:typeof import('node:dns/promises').lookup}} options
 */
export function createReleaseProofServer({ resolvedRoot, fetch, lookup }) {
  const server = new McpServer({ name: 'cloudflare-release-proof', version: VERSION });

  server.registerTool(
    'create_release_manifest',
    {
      title: 'Create release manifest',
      description: 'Hash a folder below the configured read-only root.',
      inputSchema: createManifestInput,
      annotations: READ_ONLY_ANNOTATIONS
    },
    async ({ folder }) => {
      try {
        const resolvedFolder = await resolveRootedDirectory(resolvedRoot, folder);
        const manifest = await createReleaseManifest(resolvedFolder);
        return toolSuccess(
          'Release manifest created.',
          /** @type {Record<string, unknown>} */ (manifest)
        );
      } catch (error) {
        return toolError(error);
      }
    }
  );

  server.registerTool(
    'verify_release_folder',
    {
      title: 'Verify release folder',
      description: 'Compare a rooted folder with a rooted release manifest.',
      inputSchema: verifyFolderInput,
      annotations: READ_ONLY_ANNOTATIONS
    },
    async ({ folder, manifestPath }) => {
      try {
        const resolvedFolder = await resolveRootedDirectory(resolvedRoot, folder);
        const resolvedManifest = await resolveRootedFile(resolvedRoot, manifestPath);
        const manifest = await readManifest(resolvedManifest);
        const receipt = await verifyReleaseFolder(resolvedFolder, manifest, {
          exclude: manifestExclusion(resolvedFolder, resolvedManifest)
        });
        return toolSuccess(
          'Local release verification completed.',
          /** @type {Record<string, unknown>} */ (receipt)
        );
      } catch (error) {
        return toolError(error);
      }
    }
  );

  server.registerTool(
    'verify_public_release',
    {
      title: 'Verify public release',
      description: 'Compare public HTTPS bytes with a rooted release manifest.',
      inputSchema: verifyPublicInput,
      annotations: PUBLIC_READ_ONLY_ANNOTATIONS
    },
    async ({ manifestPath, baseUrl, expectHeader }) => {
      try {
        const resolvedManifest = await resolveRootedFile(resolvedRoot, manifestPath);
        const manifest = await readManifest(resolvedManifest);
        const receipt = await verifyPublicRelease(baseUrl, manifest, {
          expectHeader,
          fetch,
          lookup
        });
        return toolSuccess(
          'Public release verification completed.',
          /** @type {Record<string, unknown>} */ (receipt)
        );
      } catch (error) {
        return toolError(error);
      }
    }
  );

  return server;
}

/**
 * Resolve one startup root, reserve stdout for MCP transport frames, and
 * return the installed SDK's closeable stdio handle.
 *
 * @param {string} root
 * @param {{stderr?:NodeJS.WritableStream,fetch?:typeof globalThis.fetch,lookup?:typeof import('node:dns/promises').lookup}} [options]
 * @returns {Promise<import('@modelcontextprotocol/server/stdio').StdioServerHandle>}
 */
export async function startMcpServer(
  root,
  { stderr = process.stderr, fetch = globalThis.fetch, lookup } = {}
) {
  const resolvedRoot = await resolveReadableRoot(root);
  stderr.write('cloudflare-release-proof MCP ready\n');
  return serveStdio(
    () => createReleaseProofServer({ resolvedRoot, fetch, lookup }),
    {
      onerror(_error) {
        stderr.write('MCP_ERROR: Release proof transport failed\n');
      }
    }
  );
}
