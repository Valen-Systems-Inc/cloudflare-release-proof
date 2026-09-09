import { AppError, EXIT_CODES } from './errors.mjs';
import { createReleaseManifest, manifestDigest, validateReleaseManifest } from './manifest.mjs';
import { VERSION } from './version.mjs';

const ISO_INSTANT_PATTERN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-](\d{2}):(\d{2}))$/u;

/** @typedef {{bytes:number, sha256:string}} FileProof */
/** @typedef {'match'|'changed'|'missing'|'unexpected'} LocalEntryOutcome */
/** @typedef {{path:string, outcome:LocalEntryOutcome, expected:FileProof|null, observed:FileProof|null}} LocalReceiptEntry */
/** @typedef {{match:number, changed:number, missing:number, unexpected:number, unverified:0, total:number}} LocalSummary */
/** @typedef {{schemaVersion:1, kind:'local', manifestSha256:string, verifierVersion:string, result:{outcome:'match'|'mismatch', entries:LocalReceiptEntry[], summary:LocalSummary}, observation?:{observedAt:string}}} VerificationReceipt */

/**
 * @param {string} message
 * @param {string} code
 */
function invalid(message, code) {
  return new AppError(message, EXIT_CODES.invalid, code);
}

/**
 * @param {number} year
 */
function isLeapYear(year) {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

/**
 * @param {unknown} value
 * @returns {string | null}
 */
function validateObservationTime(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string') {
    throw invalid('Observation time must be a valid ISO instant', 'INVALID_OBSERVATION_TIME');
  }

  const match = ISO_INSTANT_PATTERN.exec(value);
  if (match === null) {
    throw invalid('Observation time must be a valid ISO instant', 'INVALID_OBSERVATION_TIME');
  }

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const offsetHour = match[7] === undefined ? 0 : Number(match[7]);
  const offsetMinute = match[8] === undefined ? 0 : Number(match[8]);
  const daysByMonth = [31, isLeapYear(year) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  const dayLimit = daysByMonth[month - 1];

  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    dayLimit === undefined ||
    day > dayLimit ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    offsetHour > 23 ||
    offsetMinute > 59 ||
    Number.isNaN(Date.parse(value))
  ) {
    throw invalid('Observation time must be a valid ISO instant', 'INVALID_OBSERVATION_TIME');
  }

  return value;
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
 * @param {{bytes:number, sha256:string}} entry
 * @returns {FileProof}
 */
function fileProof(entry) {
  return { bytes: entry.bytes, sha256: entry.sha256 };
}

/**
 * Compare a folder with a validated release manifest without converting safety
 * failures into partial verification results.
 *
 * @param {string} root
 * @param {unknown} manifest
 * @param {{exclude?: Set<string>, observationTime?: string | null, maxFiles?: number, maxBytes?: number}} [options]
 * @returns {Promise<VerificationReceipt>}
 */
export async function verifyReleaseFolder(root, manifest, options = {}) {
  const expectedManifest = validateReleaseManifest(manifest);
  const observationTime = validateObservationTime(options.observationTime);
  const manifestSha256 = manifestDigest(expectedManifest);
  const observedManifest = await createReleaseManifest(root, {
    exclude: options.exclude,
    maxFiles: options.maxFiles,
    maxBytes: options.maxBytes
  });

  /** @type {LocalReceiptEntry[]} */
  const entries = [];
  /** @type {LocalSummary} */
  const summary = { match: 0, changed: 0, missing: 0, unexpected: 0, unverified: 0, total: 0 };
  let expectedIndex = 0;
  let observedIndex = 0;

  while (
    expectedIndex < expectedManifest.entries.length ||
    observedIndex < observedManifest.entries.length
  ) {
    if (expectedIndex >= expectedManifest.entries.length) {
      const observed = observedManifest.entries[observedIndex];
      entries.push({
        path: observed.path,
        outcome: 'unexpected',
        expected: null,
        observed: fileProof(observed)
      });
      summary.unexpected += 1;
      observedIndex += 1;
      continue;
    }

    if (observedIndex >= observedManifest.entries.length) {
      const expected = expectedManifest.entries[expectedIndex];
      entries.push({
        path: expected.path,
        outcome: 'missing',
        expected: fileProof(expected),
        observed: null
      });
      summary.missing += 1;
      expectedIndex += 1;
      continue;
    }

    const expected = expectedManifest.entries[expectedIndex];
    const observed = observedManifest.entries[observedIndex];
    const pathOrder = compareCodePoints(expected.path, observed.path);

    if (pathOrder < 0) {
      entries.push({
        path: expected.path,
        outcome: 'missing',
        expected: fileProof(expected),
        observed: null
      });
      summary.missing += 1;
      expectedIndex += 1;
      continue;
    }

    if (pathOrder > 0) {
      entries.push({
        path: observed.path,
        outcome: 'unexpected',
        expected: null,
        observed: fileProof(observed)
      });
      summary.unexpected += 1;
      observedIndex += 1;
      continue;
    }

    const matches = expected.bytes === observed.bytes && expected.sha256 === observed.sha256;
    entries.push({
      path: expected.path,
      outcome: matches ? 'match' : 'changed',
      expected: fileProof(expected),
      observed: fileProof(observed)
    });
    if (matches) summary.match += 1;
    else summary.changed += 1;
    expectedIndex += 1;
    observedIndex += 1;
  }

  summary.total = entries.length;
  const outcome = summary.changed + summary.missing + summary.unexpected === 0 ? 'match' : 'mismatch';
  /** @type {VerificationReceipt} */
  const receipt = {
    schemaVersion: 1,
    kind: 'local',
    manifestSha256,
    verifierVersion: VERSION,
    result: { outcome, entries, summary }
  };
  if (observationTime !== null) receipt.observation = { observedAt: observationTime };
  return receipt;
}
