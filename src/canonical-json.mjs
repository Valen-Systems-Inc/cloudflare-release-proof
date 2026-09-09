import { createHash } from 'node:crypto';

/** @typedef {null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue }} JsonValue */

/**
 * @param {string} left
 * @param {string} right
 * @returns {number}
 */
function compareCodePoints(left, right) {
  const leftPoints = Array.from(left, character => character.codePointAt(0));
  const rightPoints = Array.from(right, character => character.codePointAt(0));
  const length = Math.min(leftPoints.length, rightPoints.length);

  for (let index = 0; index < length; index += 1) {
    const difference = /** @type {number} */ (leftPoints[index]) - /** @type {number} */ (rightPoints[index]);
    if (difference !== 0) return difference;
  }

  return leftPoints.length - rightPoints.length;
}

/**
 * @param {unknown} value
 * @param {WeakSet<object>} ancestors
 * @returns {JsonValue}
 */
function copyCanonical(value, ancestors) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('JSON numbers must be finite.');
    return value;
  }

  if (typeof value !== 'object') throw new TypeError(`Unsupported JSON value: ${typeof value}.`);
  if (ancestors.has(value)) throw new TypeError('Unsupported JSON value: cyclic object.');

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const result = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, index)) throw new TypeError('Unsupported JSON value: sparse array.');
        result.push(copyCanonical(value[index], ancestors));
      }
      return result;
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError('Unsupported JSON value: object must be an ordinary object.');
    }

    const source = /** @type {{ [key: string]: unknown }} */ (value);
    /** @type {string[]} */
    const keys = [];
    for (const key of Reflect.ownKeys(source)) {
      if (typeof key === 'symbol') throw new TypeError('Unsupported JSON value: symbol key.');
      keys.push(key);
    }
    /** @type {{ [key: string]: JsonValue }} */
    const result = Object.create(null);
    for (const key of keys.sort(compareCodePoints)) {
      result[key] = copyCanonical(source[key], ancestors);
    }
    return result;
  } finally {
    ancestors.delete(value);
  }
}

/**
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalJson(value) {
  const serialized = JSON.stringify(copyCanonical(value, new WeakSet()), null, 2);
  if (serialized === undefined) throw new TypeError('Unsupported JSON value.');
  return `${serialized}\n`;
}

/**
 * @param {string | Uint8Array} value
 * @returns {string}
 */
export function sha256Bytes(value) {
  return createHash('sha256').update(value).digest('hex');
}
