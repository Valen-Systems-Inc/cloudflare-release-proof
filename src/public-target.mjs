import { lookup as dnsLookup } from 'node:dns/promises';
import { isIP } from 'node:net';

import { AppError, EXIT_CODES } from './errors.mjs';

/** @type {ReadonlyArray<readonly [number, number]>} */
const IPV4_FORBIDDEN_RANGES = Object.freeze([
  [0x00000000, 8],
  [0x0a000000, 8],
  [0x64400000, 10],
  [0x7f000000, 8],
  [0xa9fe0000, 16],
  [0xac100000, 12],
  [0xc0000000, 24],
  [0xc0000200, 24],
  [0xc0586300, 24],
  [0xc0a80000, 16],
  [0xc6120000, 15],
  [0xc6336400, 24],
  [0xcb007100, 24],
  [0xe0000000, 4],
  [0xf0000000, 4]
]);

/** @type {ReadonlyArray<readonly [bigint, number]>} */
const IPV6_FORBIDDEN_RANGES = Object.freeze([
  [0n, 96],
  [0x0100n << 112n, 64],
  [(0x2001n << 112n) | (0x0002n << 96n), 48],
  [(0x2001n << 112n) | (0x0db8n << 96n), 32],
  [0xfc00n << 112n, 7],
  [0xfe80n << 112n, 10],
  [0xfec0n << 112n, 10],
  [0xff00n << 112n, 8]
]);

const IP_LIKE_HOSTNAME = /^(?:[0-9.]+|0x[0-9a-z]+)$/iu;
const ABSOLUTE_HTTPS_URL = /^https:\/\/[^/?#]+(?:[/?#]|$)/iu;

/**
 * @param {string} message
 * @param {string} code
 */
function invalid(message, code) {
  return new AppError(message, EXIT_CODES.invalid, code);
}

/**
 * @param {string} message
 * @param {string} code
 */
function network(message, code) {
  return new AppError(message, EXIT_CODES.network, code);
}

/**
 * @param {string} address
 * @returns {number | null}
 */
function parseIpv4(address) {
  const parts = address.split('.');
  if (parts.length !== 4) return null;

  let value = 0;
  for (const part of parts) {
    if (!/^(?:0|[1-9][0-9]{0,2})$/u.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = value * 256 + octet;
  }
  return value >>> 0;
}

/**
 * @param {number} value
 * @param {number} base
 * @param {number} prefixLength
 */
function matchesIpv4Prefix(value, base, prefixLength) {
  const mask = (0xffffffff << (32 - prefixLength)) >>> 0;
  return ((value & mask) >>> 0) === ((base & mask) >>> 0);
}

/**
 * @param {string} address
 * @returns {bigint | null}
 */
function parseIpv6(address) {
  if (isIP(address) !== 6) return null;

  const zoneIndex = address.indexOf('%');
  let normalized = (zoneIndex === -1 ? address : address.slice(0, zoneIndex)).toLowerCase();
  if (normalized.includes('.')) {
    const separator = normalized.lastIndexOf(':');
    const ipv4 = parseIpv4(normalized.slice(separator + 1));
    if (separator === -1 || ipv4 === null) return null;
    const high = (ipv4 >>> 16).toString(16);
    const low = (ipv4 & 0xffff).toString(16);
    normalized = `${normalized.slice(0, separator)}:${high}:${low}`;
  }

  const halves = normalized.split('::');
  if (halves.length > 2) return null;

  const left = halves[0] === '' ? [] : halves[0].split(':');
  const right = halves.length === 1 || halves[1] === '' ? [] : halves[1].split(':');
  const omitted = halves.length === 2 ? 8 - left.length - right.length : 0;
  if ((halves.length === 1 && left.length !== 8) || (halves.length === 2 && omitted < 1)) {
    return null;
  }

  const groups = [...left, ...Array.from({ length: omitted }, () => '0'), ...right];
  if (groups.length !== 8) return null;

  let value = 0n;
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/u.test(group)) return null;
    value = (value << 16n) | BigInt(`0x${group}`);
  }
  return value;
}

/**
 * @param {bigint} value
 * @param {bigint} base
 * @param {number} prefixLength
 */
function matchesIpv6Prefix(value, base, prefixLength) {
  const shift = BigInt(128 - prefixLength);
  return value >> shift === base >> shift;
}

/**
 * Treat malformed inputs as forbidden so callers fail closed.
 *
 * @param {string} address
 */
export function isForbiddenAddress(address) {
  if (typeof address !== 'string') return true;

  const version = isIP(address);
  if (version === 4) {
    const value = parseIpv4(address);
    if (value === null) return true;
    return IPV4_FORBIDDEN_RANGES.some(([base, prefix]) =>
      matchesIpv4Prefix(value, base, prefix)
    );
  }
  if (version !== 6) return true;

  const value = parseIpv6(address);
  if (value === null) return true;

  // IPv4-mapped IPv6 addresses inherit the embedded IPv4 classification.
  if (value >> 32n === 0xffffn) {
    const ipv4 = Number(value & 0xffffffffn);
    return IPV4_FORBIDDEN_RANGES.some(([base, prefix]) =>
      matchesIpv4Prefix(ipv4, base, prefix)
    );
  }

  return IPV6_FORBIDDEN_RANGES.some(([base, prefix]) =>
    matchesIpv6Prefix(value, base, prefix)
  );
}

/**
 * @param {string} hostname
 */
function invalidDnsResult(hostname) {
  return network(`DNS returned an invalid result for public target host: ${hostname}`, 'PUBLIC_TARGET_DNS_INVALID');
}

/**
 * @param {string} raw
 * @param {{lookup?: typeof dnsLookup}} [options]
 */
export async function validatePublicBaseUrl(raw, options = {}) {
  if (
    typeof raw !== 'string' ||
    raw.trim() !== raw ||
    !ABSOLUTE_HTTPS_URL.test(raw) ||
    raw.includes('?') ||
    raw.includes('#')
  ) {
    throw invalid('Invalid public target URL', 'INVALID_PUBLIC_TARGET');
  }

  let url;
  try {
    url = new URL(raw);
  } catch {
    throw invalid('Invalid public target URL', 'INVALID_PUBLIC_TARGET');
  }

  if (
    url.protocol !== 'https:' ||
    url.hostname === '' ||
    url.username !== '' ||
    url.password !== '' ||
    url.search !== '' ||
    url.hash !== ''
  ) {
    throw invalid('Invalid public target URL', 'INVALID_PUBLIC_TARGET');
  }

  const hostname =
    url.hostname.startsWith('[') && url.hostname.endsWith(']')
      ? url.hostname.slice(1, -1)
      : url.hostname;
  const addressFamily = isIP(hostname);

  if (addressFamily !== 0) {
    if (isForbiddenAddress(hostname)) {
      throw invalid('Public target uses a forbidden address', 'FORBIDDEN_PUBLIC_TARGET');
    }
  } else {
    if (IP_LIKE_HOSTNAME.test(hostname) || hostname.includes(':')) {
      throw invalid('Invalid public target URL', 'INVALID_PUBLIC_TARGET');
    }
    if (options.lookup !== undefined && typeof options.lookup !== 'function') {
      throw invalid('Invalid public target lookup option', 'INVALID_PUBLIC_TARGET');
    }

    const lookup = options.lookup ?? dnsLookup;
    let results;
    try {
      results = await lookup(hostname, { all: true, verbatim: true });
    } catch {
      throw network(
        `DNS lookup failed for public target host: ${hostname}`,
        'PUBLIC_TARGET_DNS_FAILED'
      );
    }

    if (!Array.isArray(results)) throw invalidDnsResult(hostname);
    if (results.length === 0) {
      throw network(
        `DNS returned no addresses for public target host: ${hostname}`,
        'PUBLIC_TARGET_DNS_EMPTY'
      );
    }

    for (const result of results) {
      if (result === null || typeof result !== 'object') throw invalidDnsResult(hostname);
      const version = isIP(result.address);
      if ((version !== 4 && version !== 6) || version !== result.family) {
        throw invalidDnsResult(hostname);
      }
      if (isForbiddenAddress(result.address)) {
        throw invalid(
          `Public target host resolves to a forbidden address: ${hostname}`,
          'FORBIDDEN_PUBLIC_TARGET'
        );
      }
    }
  }

  if (!url.pathname.endsWith('/')) url.pathname = `${url.pathname}/`;
  return url;
}

/**
 * @returns {AppError}
 */
function unsafeRedirect() {
  return invalid('Unsafe public target redirect', 'UNSAFE_PUBLIC_REDIRECT');
}

/**
 * @param {string} originalOrigin
 * @param {string} location
 * @param {URL} currentUrl
 */
export function validateSameOriginRedirect(originalOrigin, location, currentUrl) {
  if (
    typeof originalOrigin !== 'string' ||
    typeof location !== 'string' ||
    location.length === 0 ||
    location.trim() !== location ||
    location.includes('?') ||
    location.includes('#') ||
    !(currentUrl instanceof URL)
  ) {
    throw unsafeRedirect();
  }

  let originUrl;
  try {
    originUrl = new URL(originalOrigin);
  } catch {
    throw unsafeRedirect();
  }

  if (
    originalOrigin !== originUrl.origin ||
    originUrl.protocol !== 'https:' ||
    currentUrl.origin !== originUrl.origin ||
    currentUrl.protocol !== 'https:' ||
    currentUrl.username !== '' ||
    currentUrl.password !== '' ||
    currentUrl.search !== '' ||
    currentUrl.hash !== ''
  ) {
    throw unsafeRedirect();
  }

  let redirected;
  try {
    redirected = new URL(location, currentUrl);
  } catch {
    throw unsafeRedirect();
  }

  if (
    redirected.origin !== originUrl.origin ||
    redirected.username !== '' ||
    redirected.password !== '' ||
    redirected.search !== '' ||
    redirected.hash !== ''
  ) {
    throw unsafeRedirect();
  }

  return redirected;
}
