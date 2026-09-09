import { lstat, opendir, realpath } from 'node:fs/promises';
import path from 'node:path';

import { AppError, EXIT_CODES } from './errors.mjs';

export const LIMITS = Object.freeze({
  maxFiles: 10_000,
  maxBytes: 68_719_476_736
});

const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/u;
const WINDOWS_DRIVE_QUALIFIED = /^[A-Za-z]:/u;

/**
 * @param {string} message
 * @param {string} code
 */
function invalid(message, code) {
  return new AppError(message, EXIT_CODES.invalid, code);
}

/**
 * Convert native traversal failures without retaining filesystem paths.
 *
 * @param {unknown} error
 */
export function toTraversalAppError(error) {
  if (error instanceof AppError) return error;
  return invalid('Release traversal failed', 'TRAVERSAL_FAILED');
}

/**
 * Normalize one portable manifest path while rejecting ambiguous spellings.
 *
 * @param {string} raw
 */
export function normalizeManifestPath(raw) {
  if (
    typeof raw !== 'string' ||
    raw.length === 0 ||
    !raw.isWellFormed() ||
    raw.startsWith('/') ||
    WINDOWS_DRIVE_QUALIFIED.test(raw) ||
    raw.includes('\\') ||
    CONTROL_CHARACTERS.test(raw)
  ) {
    throw invalid('Unsafe manifest path', 'UNSAFE_MANIFEST_PATH');
  }

  const segments = raw.split('/');
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
    throw invalid('Unsafe manifest path', 'UNSAFE_MANIFEST_PATH');
  }

  return segments.map((segment) => segment.normalize('NFC')).join('/');
}

/**
 * Produce the comparison key used to reject cross-platform path collisions.
 * The stored manifest spelling remains NFC and is never replaced by this key.
 *
 * @param {string} raw
 */
export function manifestCollisionKey(raw) {
  return normalizeManifestPath(raw).normalize('NFKC').toUpperCase().toLowerCase().normalize('NFC');
}

/** @param {string} raw */
export function isSafeMcpFolderPath(raw) {
  if (raw === '.') return true;
  try {
    normalizeManifestPath(raw);
    return true;
  } catch {
    return false;
  }
}

/** @param {string} raw */
export function isSafeMcpFilePath(raw) {
  try {
    normalizeManifestPath(raw);
    return true;
  } catch {
    return false;
  }
}

/**
 * @param {string} root
 */
export async function resolveReadableRoot(root) {
  if (typeof root !== 'string' || root.length === 0) {
    throw invalid('Readable root must be a non-empty directory path', 'INVALID_READABLE_ROOT');
  }

  let stats;
  try {
    stats = await lstat(root);
  } catch {
    throw invalid('Readable root does not exist or is not readable', 'INVALID_READABLE_ROOT');
  }

  if (stats.isSymbolicLink()) {
    throw invalid('Readable root must not be a symlink', 'SYMLINK_NOT_ALLOWED');
  }
  if (!stats.isDirectory()) {
    throw invalid('Readable root must be a directory', 'INVALID_READABLE_ROOT');
  }

  try {
    return await realpath(root);
  } catch {
    throw invalid('Readable root does not exist or is not readable', 'INVALID_READABLE_ROOT');
  }
}

/**
 * @param {string} resolvedRoot
 * @param {string} candidate
 */
function isWithinRoot(resolvedRoot, candidate) {
  if (candidate === resolvedRoot) return true;
  const rootPrefix = resolvedRoot.endsWith(path.sep) ? resolvedRoot : `${resolvedRoot}${path.sep}`;
  return candidate.startsWith(rootPrefix);
}

/**
 * @param {string} resolvedRoot
 * @param {string} normalizedPath
 */
async function inspectRootedPath(resolvedRoot, normalizedPath) {
  let candidate = resolvedRoot;
  let stats;

  for (const segment of normalizedPath.split('/')) {
    candidate = path.join(candidate, segment);
    try {
      stats = await lstat(candidate);
    } catch {
      throw invalid('Rooted path does not exist or is not readable', 'INVALID_ROOTED_PATH');
    }
    if (stats.isSymbolicLink()) {
      throw invalid('Rooted path must not contain a symlink', 'SYMLINK_NOT_ALLOWED');
    }
  }

  let resolvedCandidate;
  try {
    resolvedCandidate = await realpath(candidate);
  } catch {
    throw invalid('Rooted path does not exist or is not readable', 'INVALID_ROOTED_PATH');
  }

  if (!isWithinRoot(resolvedRoot, resolvedCandidate)) {
    throw invalid('Rooted path escapes the readable root', 'PATH_OUTSIDE_ROOT');
  }

  return { resolvedCandidate, stats };
}

/**
 * @param {string} root
 * @param {string} relativePath
 */
export async function resolveRootedDirectory(root, relativePath) {
  const resolvedRoot = await resolveReadableRoot(root);
  if (relativePath === '.') return resolvedRoot;

  const normalizedPath = normalizeManifestPath(relativePath);
  const { resolvedCandidate, stats } = await inspectRootedPath(resolvedRoot, normalizedPath);
  if (!stats?.isDirectory()) {
    throw invalid('Rooted path must be a directory', 'EXPECTED_DIRECTORY');
  }
  return resolvedCandidate;
}

/**
 * @param {string} root
 * @param {string} relativePath
 */
export async function resolveRootedFile(root, relativePath) {
  const resolvedRoot = await resolveReadableRoot(root);
  const normalizedPath = normalizeManifestPath(relativePath);
  const { resolvedCandidate, stats } = await inspectRootedPath(resolvedRoot, normalizedPath);
  if (!stats?.isFile()) {
    throw invalid('Rooted path must be a regular file', 'EXPECTED_REGULAR_FILE');
  }
  return resolvedCandidate;
}

/**
 * Compare strings by Unicode code point rather than locale or UTF-16 code unit.
 *
 * @param {string} left
 * @param {string} right
 */
function compareCodePoints(left, right) {
  const leftPoints = Array.from(left, (character) => /** @type {number} */ (character.codePointAt(0)));
  const rightPoints = Array.from(right, (character) => /** @type {number} */ (character.codePointAt(0)));
  const sharedLength = Math.min(leftPoints.length, rightPoints.length);

  for (let index = 0; index < sharedLength; index += 1) {
    if (leftPoints[index] !== rightPoints[index]) return leftPoints[index] - rightPoints[index];
  }
  return leftPoints.length - rightPoints.length;
}

/**
 * @param {number | undefined} value
 * @param {number} hardLimit
 * @param {string} name
 */
function boundedLimit(value, hardLimit, name) {
  if (value === undefined) return hardLimit;
  if (!Number.isSafeInteger(value) || value < 0 || value > hardLimit) {
    throw invalid(`${name} must be a nonnegative integer within the production limit`, 'INVALID_LIMIT');
  }
  return value;
}

/**
 * @param {Set<string> | undefined} exclude
 */
function normalizedExclusions(exclude) {
  if (exclude === undefined) return new Set();
  if (!(exclude instanceof Set)) {
    throw invalid('Release exclusions must be a Set of manifest paths', 'INVALID_EXCLUSIONS');
  }
  return new Set(Array.from(exclude, (entry) => normalizeManifestPath(entry)));
}

/**
 * @typedef {{path:string, absolutePath:string, bytes:number}} WalkedReleaseEntry
 */

/**
 * Walk a release without following links or reading payload bytes.
 *
 * @param {string} root
 * @param {{exclude?: Set<string>, maxFiles?: number, maxBytes?: number}} [options]
 * @returns {Promise<WalkedReleaseEntry[]>}
 */
export async function walkRelease(root, options = {}) {
  const resolvedRoot = await resolveReadableRoot(root);
  const maxFiles = boundedLimit(options.maxFiles, LIMITS.maxFiles, 'File limit');
  const maxBytes = boundedLimit(options.maxBytes, LIMITS.maxBytes, 'Byte limit');
  const exclusions = normalizedExclusions(options.exclude);
  const normalizedPaths = new Set();
  const collisionKeys = new Set();
  /** @type {WalkedReleaseEntry[]} */
  const files = [];
  let totalBytes = 0;

  /**
   * @param {string} absoluteDirectory
   * @param {string[]} relativeSegments
   */
  async function visit(absoluteDirectory, relativeSegments) {
    try {
      const directory = await opendir(absoluteDirectory);
      for await (const directoryEntry of directory) {
        const rawPath = [...relativeSegments, directoryEntry.name].join('/');
        const normalizedPath = normalizeManifestPath(rawPath);
        const absolutePath = path.join(absoluteDirectory, directoryEntry.name);
        const stats = await lstat(absolutePath);

        if (stats.isSymbolicLink()) {
          throw invalid('Release must not contain a symlink', 'SYMLINK_NOT_ALLOWED');
        }
        if (!stats.isDirectory() && !stats.isFile()) {
          throw invalid('Release contains an unsupported filesystem entry', 'UNSUPPORTED_ENTRY');
        }

        const collisionKey = manifestCollisionKey(normalizedPath);
        if (normalizedPaths.has(normalizedPath) || collisionKeys.has(collisionKey)) {
          throw invalid('Release contains a path collision', 'PATH_COLLISION');
        }
        normalizedPaths.add(normalizedPath);
        collisionKeys.add(collisionKey);

        if (stats.isDirectory()) {
          if (exclusions.has(normalizedPath)) {
            throw invalid('Release exclusion must not name a directory', 'EXCLUDED_DIRECTORY');
          }
          await visit(absolutePath, [...relativeSegments, directoryEntry.name]);
          continue;
        }

        if (exclusions.has(normalizedPath)) continue;

        if (files.length + 1 > maxFiles) {
          throw invalid('Release exceeds the file limit', 'FILE_LIMIT_EXCEEDED');
        }
        totalBytes += stats.size;
        if (totalBytes > maxBytes) {
          throw invalid('Release exceeds the byte limit', 'BYTE_LIMIT_EXCEEDED');
        }
        files.push({ path: normalizedPath, absolutePath, bytes: stats.size });
      }
    } catch (error) {
      throw toTraversalAppError(error);
    }
  }

  await visit(resolvedRoot, []);
  files.sort((left, right) => compareCodePoints(left.path, right.path));
  return files;
}
