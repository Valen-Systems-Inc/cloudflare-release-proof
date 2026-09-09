import { createHash } from 'node:crypto';

import { AppError, EXIT_CODES } from './errors.mjs';
import { manifestDigest, validateReleaseManifest } from './manifest.mjs';
import { normalizeManifestPath } from './paths.mjs';
import { validatePublicBaseUrl, validateSameOriginRedirect } from './public-target.mjs';
import { VERSION } from './version.mjs';

const DEFAULT_CONCURRENCY = 4;
const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_RESPONSE_BYTES = 64 * 1024 * 1024;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

const EXPECTED_HEADER_NAME_LIST = Object.freeze([
  'cache-control',
  'content-length',
  'content-type',
  'etag',
  'last-modified',
  'x-release',
  'x-version'
]);
const EXPECTED_HEADER_NAME_SET = new Set(EXPECTED_HEADER_NAME_LIST);
export const EXPECTED_HEADER_NAMES = new Set(EXPECTED_HEADER_NAME_LIST);

/**
 * @param {string} message
 * @param {string} code
 */
function invalid(message, code) {
  return new AppError(message, EXIT_CODES.invalid, code);
}

/**
 * @param {unknown} value
 * @returns {{name:string,value:string} | null}
 */
export function parseExpectedHeader(value) {
  if (value === undefined) return null;
  if (typeof value !== 'string') {
    throw invalid('Invalid expected response header', 'INVALID_EXPECTED_HEADER');
  }

  const separator = value.indexOf('=');
  if (separator <= 0 || separator === value.length - 1) {
    throw invalid('Invalid expected response header', 'INVALID_EXPECTED_HEADER');
  }

  const name = value.slice(0, separator).toLowerCase();
  const expectedValue = value.slice(separator + 1);
  if (
    !/^[a-z0-9-]+$/u.test(name) ||
    !EXPECTED_HEADER_NAME_SET.has(name) ||
    /[\u0000-\u001f\u007f]/u.test(expectedValue)
  ) {
    throw invalid('Invalid expected response header', 'INVALID_EXPECTED_HEADER');
  }

  return { name, value: expectedValue };
}

/**
 * @param {URL} baseUrl
 * @param {string} manifestPath
 */
export function mapManifestPath(baseUrl, manifestPath) {
  if (!(baseUrl instanceof URL) || baseUrl.protocol !== 'https:' || !baseUrl.pathname.endsWith('/')) {
    throw invalid('Invalid public target URL', 'INVALID_PUBLIC_TARGET');
  }

  const normalized = normalizeManifestPath(manifestPath);
  const segments = normalized.split('/');
  if (segments.at(-1) === 'index.html') segments.pop();
  const encoded = segments.map((segment) => encodeURIComponent(segment)).join('/');
  return new URL(encoded === '' ? './' : `${encoded}${segments.length < normalized.split('/').length ? '/' : ''}`, baseUrl);
}

class DeadlineError extends Error {
  constructor() {
    super('Public verification timed out');
    this.name = 'DeadlineError';
  }
}

/**
 * @param {number} timeoutMs
 * @param {AbortController} controller
 */
function createDeadline(timeoutMs, controller) {
  /** @type {NodeJS.Timeout | undefined} */
  let timer;
  const promise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new DeadlineError());
    }, timeoutMs);
  });
  return {
    /** @template T @param {Promise<T>} operation @returns {Promise<T>} */
    race(operation) {
      return Promise.race([operation, promise]);
    },
    close() {
      if (timer !== undefined) clearTimeout(timer);
    }
  };
}

/** @param {{bytes:number,sha256:string}} entry */
function proof(entry) {
  return { bytes: entry.bytes, sha256: entry.sha256 };
}

/**
 * @param {string} path
 * @param {URL} requestedUrl
 * @param {URL} finalUrl
 * @param {number | null} status
 * @param {{bytes:number,sha256:string}} expected
 * @param {string} errorCode
 */
function unverifiedEntry(path, requestedUrl, finalUrl, status, expected, errorCode) {
  return {
    path,
    requestedUrl: requestedUrl.href,
    finalUrl: finalUrl.href,
    status,
    outcome: 'unverified',
    expected: proof(expected),
    observed: null,
    errorCode
  };
}

/**
 * @param {unknown} value
 * @param {string} name
 * @param {number} fallback
 * @param {number} maximum
 */
function boundedInteger(value, name, fallback, maximum) {
  if (value === undefined) return fallback;
  if (
    !Number.isSafeInteger(value) ||
    /** @type {number} */ (value) < 1 ||
    /** @type {number} */ (value) > maximum
  ) {
    throw invalid(`Invalid ${name}`, 'INVALID_PUBLIC_VERIFY_OPTIONS');
  }
  return /** @type {number} */ (value);
}

/** @param {unknown} value */
function validateObservationTime(value) {
  if (value === undefined || value === null) return null;
  if (
    typeof value !== 'string' ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/u.test(value) ||
    Number.isNaN(Date.parse(value))
  ) {
    throw invalid('Invalid observation time', 'INVALID_PUBLIC_VERIFY_OPTIONS');
  }
  return value;
}

/**
 * @param {URL} currentUrl
 * @param {string} originalOrigin
 * @param {string} location
 */
function nextRedirect(currentUrl, originalOrigin, location) {
  let candidate;
  try {
    candidate = new URL(location, currentUrl);
  } catch {
    return { errorCode: 'unsafe_redirect', url: null };
  }
  if (candidate.origin !== originalOrigin) {
    return { errorCode: 'cross_origin_redirect', url: null };
  }
  try {
    return {
      errorCode: null,
      url: validateSameOriginRedirect(originalOrigin, location, currentUrl)
    };
  } catch {
    return { errorCode: 'unsafe_redirect', url: null };
  }
}

/**
 * @param {Response} response
 * @param {number} maximumBytes
 * @param {{race:<T>(operation:Promise<T>)=>Promise<T>}} deadline
 */
async function readProof(response, maximumBytes, deadline) {
  if (response.body === null) return { errorCode: 'missing_body', proof: null };

  const reader = response.body.getReader();
  const hash = createHash('sha256');
  let bytes = 0;
  try {
    while (true) {
      const result = await deadline.race(reader.read());
      if (result.done) break;
      const chunk = result.value;
      if (!(chunk instanceof Uint8Array)) {
        await reader.cancel();
        return { errorCode: 'body_error', proof: null };
      }
      bytes += chunk.byteLength;
      if (!Number.isSafeInteger(bytes) || bytes > maximumBytes) {
        await reader.cancel();
        return { errorCode: 'response_too_large', proof: null };
      }
      hash.update(chunk);
    }
    return { errorCode: null, proof: { bytes, sha256: hash.digest('hex') } };
  } catch (error) {
    try {
      await reader.cancel();
    } catch {
      // The bounded error code is the receipt contract; cancellation is best effort.
    }
    throw error;
  } finally {
    reader.releaseLock();
  }
}

/**
 * @param {URL} requestedUrl
 * @param {{path:string,bytes:number,sha256:string}} entry
 * @param {{fetchImpl:typeof fetch,lookup?:typeof import('node:dns/promises').lookup,timeoutMs:number,maxResponseBytes:number,expectedHeader:{name:string,value:string}|null}} options
 */
async function verifyEntry(requestedUrl, entry, options) {
  const controller = new AbortController();
  const deadline = createDeadline(options.timeoutMs, controller);
  let currentUrl = requestedUrl;
  let redirects = 0;

  try {
    while (true) {
      try {
        await deadline.race(validatePublicBaseUrl(currentUrl.origin, { lookup: options.lookup }));
      } catch (error) {
        if (error instanceof DeadlineError) throw error;
        return unverifiedEntry(
          entry.path,
          requestedUrl,
          currentUrl,
          null,
          entry,
          redirects === 0 ? 'unsafe_target' : 'unsafe_redirect'
        );
      }

      /** @type {Response} */
      let response;
      try {
        response = await deadline.race(
          options.fetchImpl(currentUrl.href, {
            method: 'GET',
            redirect: 'manual',
            credentials: 'omit',
            headers: new Headers({ 'Accept-Encoding': 'identity' }),
            signal: controller.signal
          })
        );
      } catch (error) {
        if (error instanceof DeadlineError || controller.signal.aborted) throw new DeadlineError();
        return unverifiedEntry(entry.path, requestedUrl, currentUrl, null, entry, 'connection_error');
      }

      if (REDIRECT_STATUSES.has(response.status)) {
        if (redirects >= 5) {
          return unverifiedEntry(
            entry.path,
            requestedUrl,
            currentUrl,
            response.status,
            entry,
            'redirect_limit'
          );
        }
        const location = response.headers.get('location');
        if (location === null) {
          return unverifiedEntry(
            entry.path,
            requestedUrl,
            currentUrl,
            response.status,
            entry,
            'unsafe_redirect'
          );
        }
        const redirect = nextRedirect(currentUrl, requestedUrl.origin, location);
        if (redirect.url === null) {
          return unverifiedEntry(
            entry.path,
            requestedUrl,
            currentUrl,
            response.status,
            entry,
            /** @type {string} */ (redirect.errorCode)
          );
        }
        currentUrl = redirect.url;
        redirects += 1;
        continue;
      }

      const header =
        options.expectedHeader === null
          ? null
          : {
              name: options.expectedHeader.name,
              expected: options.expectedHeader.value,
              observed: response.headers.get(options.expectedHeader.name)
            };

      if (response.status === 404) {
        return {
          path: entry.path,
          requestedUrl: requestedUrl.href,
          finalUrl: currentUrl.href,
          status: response.status,
          ...(header === null ? {} : { header }),
          outcome: 'missing',
          expected: proof(entry),
          observed: null
        };
      }
      if (response.status !== 200) {
        return {
          path: entry.path,
          requestedUrl: requestedUrl.href,
          finalUrl: currentUrl.href,
          status: response.status,
          ...(header === null ? {} : { header }),
          outcome: 'changed',
          expected: proof(entry),
          observed: null,
          errorCode: 'http_status'
        };
      }

      const observed = await readProof(response, options.maxResponseBytes, deadline);
      if (observed.proof === null) {
        return {
          ...unverifiedEntry(
            entry.path,
            requestedUrl,
            currentUrl,
            response.status,
            entry,
            /** @type {string} */ (observed.errorCode)
          ),
          ...(header === null ? {} : { header })
        };
      }

      const matchesBytes = observed.proof.bytes === entry.bytes;
      const matchesHash = observed.proof.sha256 === entry.sha256;
      const matchesHeader = header === null || header.observed === header.expected;
      return {
        path: entry.path,
        requestedUrl: requestedUrl.href,
        finalUrl: currentUrl.href,
        status: response.status,
        ...(header === null ? {} : { header }),
        outcome: matchesBytes && matchesHash && matchesHeader ? 'match' : 'changed',
        expected: proof(entry),
        observed: observed.proof
      };
    }
  } catch (error) {
    if (error instanceof DeadlineError || controller.signal.aborted) {
      return unverifiedEntry(entry.path, requestedUrl, currentUrl, null, entry, 'timeout');
    }
    return unverifiedEntry(entry.path, requestedUrl, currentUrl, null, entry, 'connection_error');
  } finally {
    deadline.close();
  }
}

/**
 * Verify public HTTPS bytes against a deterministic release manifest.
 * DNS is rechecked before requests, but v0.1 does not pin the fetch transport
 * to those answers; callers should supply URLs they control.
 *
 * @param {string} rawBaseUrl
 * @param {unknown} manifest
 * @param {{expectHeader?:string,fetch?:typeof fetch,lookup?:typeof import('node:dns/promises').lookup,timeoutMs?:number,maxResponseBytes?:number,concurrency?:number,observationTime?:string|null}} [options]
 */
export async function verifyPublicRelease(rawBaseUrl, manifest, options = {}) {
  const expectedManifest = validateReleaseManifest(manifest);
  const concurrency = boundedInteger(options.concurrency, 'concurrency', DEFAULT_CONCURRENCY, 8);
  const timeoutMs = boundedInteger(options.timeoutMs, 'timeout', DEFAULT_TIMEOUT_MS, 600_000);
  const maxResponseBytes = boundedInteger(
    options.maxResponseBytes,
    'response byte limit',
    MAX_RESPONSE_BYTES,
    MAX_RESPONSE_BYTES
  );
  const expectedHeader = parseExpectedHeader(options.expectHeader);
  const observationTime = validateObservationTime(options.observationTime);
  const fetchImpl = options.fetch ?? fetch;
  if (typeof fetchImpl !== 'function') {
    throw invalid('Invalid public fetch option', 'INVALID_PUBLIC_VERIFY_OPTIONS');
  }

  const baseUrl = await validatePublicBaseUrl(rawBaseUrl, { lookup: options.lookup });
  /** @type {Array<Record<string, unknown>>} */
  const entries = new Array(expectedManifest.entries.length);
  let nextIndex = 0;

  async function worker() {
    while (nextIndex < expectedManifest.entries.length) {
      const index = nextIndex;
      nextIndex += 1;
      const entry = expectedManifest.entries[index];
      entries[index] = await verifyEntry(mapManifestPath(baseUrl, entry.path), entry, {
        fetchImpl,
        lookup: options.lookup,
        timeoutMs,
        maxResponseBytes,
        expectedHeader
      });
    }
  }

  const workerCount = Math.min(concurrency, expectedManifest.entries.length);
  await Promise.all(Array.from({ length: workerCount }, () => worker()));

  const summary = { match: 0, changed: 0, missing: 0, unexpected: 0, unverified: 0, total: entries.length };
  for (const entry of entries) {
    const outcome = entry.outcome;
    if (outcome === 'match') summary.match += 1;
    else if (outcome === 'changed') summary.changed += 1;
    else if (outcome === 'missing') summary.missing += 1;
    else summary.unverified += 1;
  }
  const outcome = summary.unverified > 0 ? 'unverified' : summary.changed + summary.missing > 0 ? 'mismatch' : 'match';
  return {
    schemaVersion: 1,
    kind: 'public',
    manifestSha256: manifestDigest(expectedManifest),
    verifierVersion: VERSION,
    result: { outcome, entries, summary },
    ...(observationTime === null ? {} : { observation: { observedAt: observationTime } })
  };
}
