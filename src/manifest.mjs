import { createHash } from 'node:crypto';
import { createReadStream as nodeCreateReadStream } from 'node:fs';

import { canonicalJson, sha256Bytes } from './canonical-json.mjs';
import { AppError, EXIT_CODES } from './errors.mjs';
import { LIMITS, manifestCollisionKey, normalizeManifestPath, walkRelease } from './paths.mjs';

/** @typedef {{path:string, bytes:number, sha256:string}} ReleaseManifestEntry */
/** @typedef {{schemaVersion:1, algorithm:'sha256', pathEncoding:'utf8-nfc', entries:ReleaseManifestEntry[]}} ReleaseManifest */

const MANIFEST_KEYS = Object.freeze(['schemaVersion', 'algorithm', 'pathEncoding', 'entries']);
const ENTRY_KEYS = Object.freeze(['path', 'bytes', 'sha256']);
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;

/**
 * @param {string} message
 * @param {string} code
 */
function invalid(message, code) {
  return new AppError(message, EXIT_CODES.invalid, code);
}

/**
 * @param {unknown} error
 * @param {string} message
 * @param {string} code
 */
function classify(error, message, code) {
  if (error instanceof AppError) return error;
  return invalid(message, code);
}

/**
 * @param {unknown} value
 * @returns {value is Record<PropertyKey, unknown>}
 */
function isOrdinaryObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/**
 * @param {Record<PropertyKey, unknown>} value
 * @param {readonly string[]} expected
 */
function hasExactOwnKeys(value, expected) {
  const keys = Reflect.ownKeys(value);
  return (
    keys.length === expected.length &&
    keys.every((key) => typeof key === 'string' && expected.includes(key))
  );
}

/**
 * @param {unknown[]} value
 */
function isDenseUnadornedArray(value) {
  for (const key of Reflect.ownKeys(value)) {
    if (key === 'length') continue;
    if (typeof key !== 'string') return false;
    const index = Number(key);
    if (!Number.isInteger(index) || index < 0 || index >= value.length || String(index) !== key) return false;
  }
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.hasOwn(value, index)) return false;
  }
  return true;
}

/**
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
 * Hash one payload using its byte stream.
 *
 * @param {string} absolutePath
 * @param {{createReadStream?: typeof import('node:fs').createReadStream}} [options]
 * @returns {Promise<{bytes:number, sha256:string}>}
 */
export async function hashFile(absolutePath, options = {}) {
  try {
    const streamFactory = options.createReadStream ?? nodeCreateReadStream;
    if (typeof streamFactory !== 'function') {
      throw invalid('Release content stream factory is invalid', 'INVALID_STREAM_FACTORY');
    }

    const hash = createHash('sha256');
    let bytes = 0;
    for await (const chunk of streamFactory(absolutePath)) {
      if (!(chunk instanceof Uint8Array)) {
        throw invalid('Release content stream produced invalid bytes', 'INVALID_CONTENT_CHUNK');
      }
      bytes += chunk.byteLength;
      if (!Number.isSafeInteger(bytes) || bytes > LIMITS.maxBytes) {
        throw invalid('Release content exceeds the byte limit', 'BYTE_LIMIT_EXCEEDED');
      }
      hash.update(chunk);
    }
    return { bytes, sha256: hash.digest('hex') };
  } catch (error) {
    throw classify(error, 'Release content stream failed', 'CONTENT_STREAM_FAILED');
  }
}

/**
 * @param {unknown} value
 * @returns {ReleaseManifest}
 */
export function validateReleaseManifest(value) {
  try {
    if (!isOrdinaryObject(value) || !hasExactOwnKeys(value, MANIFEST_KEYS)) {
      throw invalid('Invalid release manifest', 'INVALID_MANIFEST');
    }
    if (value.schemaVersion !== 1 || value.algorithm !== 'sha256' || value.pathEncoding !== 'utf8-nfc') {
      throw invalid('Invalid release manifest', 'INVALID_MANIFEST');
    }
    if (!Array.isArray(value.entries) || !isDenseUnadornedArray(value.entries)) {
      throw invalid('Invalid release manifest', 'INVALID_MANIFEST');
    }
    if (value.entries.length > LIMITS.maxFiles) {
      throw invalid('Release manifest exceeds the file limit', 'FILE_LIMIT_EXCEEDED');
    }

    /** @type {ReleaseManifestEntry[]} */
    const entries = [];
    const normalizedPaths = new Set();
    const collisionKeys = new Set();
    let previousPath;
    let totalBytes = 0;

    for (const candidate of value.entries) {
      if (!isOrdinaryObject(candidate) || !hasExactOwnKeys(candidate, ENTRY_KEYS)) {
        throw invalid('Invalid release manifest entry', 'INVALID_MANIFEST');
      }

      const relativePath = candidate.path;
      if (typeof relativePath !== 'string') {
        throw invalid('Invalid release manifest path', 'INVALID_MANIFEST');
      }
      const normalizedPath = normalizeManifestPath(relativePath);
      if (normalizedPath !== relativePath) {
        throw invalid('Release manifest path must be NFC', 'INVALID_MANIFEST');
      }

      const collisionKey = manifestCollisionKey(relativePath);
      if (normalizedPaths.has(relativePath)) {
        throw invalid('Release manifest contains a duplicate path', 'PATH_COLLISION');
      }
      if (collisionKeys.has(collisionKey)) {
        throw invalid('Release manifest contains a path collision', 'PATH_COLLISION');
      }
      if (previousPath !== undefined && compareCodePoints(previousPath, relativePath) >= 0) {
        throw invalid('Release manifest entries are not sorted', 'INVALID_MANIFEST');
      }

      const bytes = candidate.bytes;
      if (
        typeof bytes !== 'number' ||
        !Number.isSafeInteger(bytes) ||
        bytes < 0 ||
        bytes > LIMITS.maxBytes
      ) {
        throw invalid('Invalid release manifest byte count', 'INVALID_MANIFEST');
      }
      totalBytes += bytes;
      if (!Number.isSafeInteger(totalBytes) || totalBytes > LIMITS.maxBytes) {
        throw invalid('Release manifest exceeds the byte limit', 'BYTE_LIMIT_EXCEEDED');
      }

      const sha256 = candidate.sha256;
      if (typeof sha256 !== 'string' || !SHA256_PATTERN.test(sha256)) {
        throw invalid('Invalid release manifest SHA-256', 'INVALID_MANIFEST');
      }

      normalizedPaths.add(relativePath);
      collisionKeys.add(collisionKey);
      previousPath = relativePath;
      entries.push({ path: relativePath, bytes, sha256 });
    }

    return { schemaVersion: 1, algorithm: 'sha256', pathEncoding: 'utf8-nfc', entries };
  } catch (error) {
    throw classify(error, 'Invalid release manifest', 'INVALID_MANIFEST');
  }
}

/**
 * @param {string | Uint8Array} text
 * @returns {ReleaseManifest}
 */
export function parseReleaseManifest(text) {
  try {
    let jsonText;
    if (typeof text === 'string') {
      jsonText = text;
    } else if (text instanceof Uint8Array) {
      jsonText = new TextDecoder('utf-8', { fatal: true }).decode(text);
    } else {
      throw invalid('Invalid release manifest input', 'INVALID_MANIFEST');
    }
    return validateReleaseManifest(JSON.parse(jsonText));
  } catch (error) {
    throw classify(error, 'Invalid release manifest', 'INVALID_MANIFEST');
  }
}

/**
 * @param {string} root
 * @param {{exclude?: Set<string>, maxFiles?: number, maxBytes?: number, createReadStream?: typeof import('node:fs').createReadStream}} [options]
 * @returns {Promise<ReleaseManifest>}
 */
export async function createReleaseManifest(root, options = {}) {
  const walkedEntries = await walkRelease(root, {
    exclude: options.exclude,
    maxFiles: options.maxFiles,
    maxBytes: options.maxBytes
  });
  /** @type {ReleaseManifestEntry[]} */
  const entries = [];

  for (const walkedEntry of walkedEntries) {
    const hashed = await hashFile(walkedEntry.absolutePath, { createReadStream: options.createReadStream });
    if (hashed.bytes !== walkedEntry.bytes) {
      throw invalid('Release content size changed during manifest creation', 'CONTENT_SIZE_CHANGED');
    }
    entries.push({ path: walkedEntry.path, bytes: hashed.bytes, sha256: hashed.sha256 });
  }

  return validateReleaseManifest({
    schemaVersion: 1,
    algorithm: 'sha256',
    pathEncoding: 'utf8-nfc',
    entries
  });
}

/**
 * @param {ReleaseManifest} manifest
 */
export function manifestDigest(manifest) {
  return sha256Bytes(canonicalJson(validateReleaseManifest(manifest)));
}
