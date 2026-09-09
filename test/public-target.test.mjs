import assert from 'node:assert/strict';
import test from 'node:test';

import { AppError, EXIT_CODES } from '../src/errors.mjs';
import {
  isForbiddenAddress,
  validatePublicBaseUrl,
  validateSameOriginRedirect
} from '../src/public-target.mjs';

/**
 * @param {unknown} error
 * @param {{exitCode: number, code: string, includes?: string[], excludes?: string[]}} expected
 */
function isExpectedAppError(error, expected) {
  assert.equal(error instanceof AppError, true);
  assert.equal(error.exitCode, expected.exitCode);
  assert.equal(error.code, expected.code);
  for (const text of expected.includes ?? []) assert.match(error.message, new RegExp(text, 'u'));
  for (const text of expected.excludes ?? []) assert.equal(error.message.includes(text), false);
  return true;
}

test('address classification blocks the v0.1 private and special-use ranges', () => {
  const forbidden = [
    '0.0.0.0',
    '0.255.255.255',
    '10.0.0.1',
    '100.64.0.1',
    '100.127.255.254',
    '127.0.0.1',
    '169.254.1.1',
    '172.16.0.1',
    '172.31.255.254',
    '192.168.0.1',
    '192.0.0.1',
    '192.0.2.1',
    '192.88.99.1',
    '198.18.0.1',
    '198.19.255.254',
    '198.51.100.1',
    '203.0.113.1',
    '224.0.0.1',
    '239.255.255.255',
    '240.0.0.1',
    '255.255.255.255',
    '::',
    '::1',
    '::127.0.0.1',
    '::ffff:127.0.0.1',
    '::ffff:7f00:1',
    'fc00::1',
    'fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
    'fe80::1',
    'febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
    'fec0::1',
    'ff00::1',
    'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
    '2001:2::1',
    '2001:db8::1',
    '100::1'
  ];

  for (const address of forbidden) assert.equal(isForbiddenAddress(address), true, address);

  for (const address of ['1.1.1.1', '8.8.8.8', '2606:4700:4700::1111', '::ffff:8.8.8.8']) {
    assert.equal(isForbiddenAddress(address), false, address);
  }

  for (const invalid of ['', '999.1.1.1', '1.2.3', 'gggg::1']) {
    assert.equal(isForbiddenAddress(invalid), true, invalid);
  }
});

test('public base validation normalizes HTTPS URLs and checks every DNS result', async () => {
  const calls = [];
  const lookup = async (hostname, options) => {
    calls.push({ hostname, options });
    return [
      { address: '1.1.1.1', family: 4 },
      { address: '2606:4700:4700::1111', family: 6 }
    ];
  };

  assert.equal((await validatePublicBaseUrl('https://example.com', { lookup })).href, 'https://example.com/');
  assert.equal(
    (await validatePublicBaseUrl('https://example.com/releases', { lookup })).href,
    'https://example.com/releases/'
  );
  assert.deepEqual(calls, [
    { hostname: 'example.com', options: { all: true, verbatim: true } },
    { hostname: 'example.com', options: { all: true, verbatim: true } }
  ]);

  const literalLookup = async () => {
    throw new Error('literal targets must not reach DNS');
  };
  assert.equal(
    (await validatePublicBaseUrl('https://1.1.1.1/base', { lookup: literalLookup })).href,
    'https://1.1.1.1/base/'
  );
  assert.equal(
    (await validatePublicBaseUrl('https://[2606:4700:4700::1111]/', { lookup: literalLookup })).href,
    'https://[2606:4700:4700::1111]/'
  );
});

test('public base validation rejects unsafe URL syntax and literal addresses without DNS', async () => {
  let dnsCalls = 0;
  const lookup = async () => {
    dnsCalls += 1;
    return [{ address: '1.1.1.1', family: 4 }];
  };

  const invalidUrls = [
    'http://example.com/',
    'file:///tmp/release',
    'https:example.com',
    'https:///missing-host',
    'https://user@example.com/',
    'https://user:password@example.com/',
    'https://example.com/?download=1',
    'https://example.com/#release',
    'https://example.com/?',
    'https://example.com/#',
    'https://999.1.1.1/'
  ];

  for (const raw of invalidUrls) {
    await assert.rejects(validatePublicBaseUrl(raw, { lookup }), (error) =>
      isExpectedAppError(error, {
        exitCode: EXIT_CODES.invalid,
        code: 'INVALID_PUBLIC_TARGET'
      })
    );
  }

  const forbiddenLiterals = [
    'https://127.0.0.1/',
    'https://127.1/',
    'https://2130706433/',
    'https://0x7f000001/',
    'https://10.0.0.1/',
    'https://[::1]/',
    'https://[::ffff:127.0.0.1]/'
  ];
  for (const raw of forbiddenLiterals) {
    await assert.rejects(validatePublicBaseUrl(raw, { lookup }), (error) =>
      isExpectedAppError(error, {
        exitCode: EXIT_CODES.invalid,
        code: 'FORBIDDEN_PUBLIC_TARGET',
        excludes: ['127.0.0.1', '10.0.0.1', '::1']
      })
    );
  }

  assert.equal(dnsCalls, 0);
});

test('DNS validation fails closed with stable sanitized invalid and network categories', async () => {
  await assert.rejects(
    validatePublicBaseUrl('https://mixed.example/', {
      lookup: async () => [
        { address: '1.1.1.1', family: 4 },
        { address: '10.0.0.8', family: 4 }
      ]
    }),
    (error) =>
      isExpectedAppError(error, {
        exitCode: EXIT_CODES.invalid,
        code: 'FORBIDDEN_PUBLIC_TARGET',
        includes: ['mixed\\.example'],
        excludes: ['1.1.1.1', '10.0.0.8']
      })
  );

  await assert.rejects(
    validatePublicBaseUrl('https://empty.example/', { lookup: async () => [] }),
    (error) =>
      isExpectedAppError(error, {
        exitCode: EXIT_CODES.network,
        code: 'PUBLIC_TARGET_DNS_EMPTY',
        includes: ['empty\\.example']
      })
  );

  await assert.rejects(
    validatePublicBaseUrl('https://failed.example/', {
      lookup: async () => {
        throw new Error('socket dump /private/config 10.0.0.9');
      }
    }),
    (error) =>
      isExpectedAppError(error, {
        exitCode: EXIT_CODES.network,
        code: 'PUBLIC_TARGET_DNS_FAILED',
        includes: ['failed\\.example'],
        excludes: ['/private/config', '10.0.0.9', 'socket dump']
      })
  );

  await assert.rejects(
    validatePublicBaseUrl('https://invalid-answer.example/', {
      lookup: async () => [{ address: 'not-an-ip', family: 4 }]
    }),
    (error) =>
      isExpectedAppError(error, {
        exitCode: EXIT_CODES.network,
        code: 'PUBLIC_TARGET_DNS_INVALID',
        includes: ['invalid-answer\\.example'],
        excludes: ['not-an-ip']
      })
  );

  await assert.rejects(
    validatePublicBaseUrl('https://wrong-family.example/', {
      lookup: async () => [{ address: '1.1.1.1', family: 6 }]
    }),
    (error) =>
      isExpectedAppError(error, {
        exitCode: EXIT_CODES.network,
        code: 'PUBLIC_TARGET_DNS_INVALID',
        includes: ['wrong-family\\.example'],
        excludes: ['1.1.1.1']
      })
  );
});

test('redirect validation allows only query-free credential-free same-origin locations', () => {
  const currentUrl = new URL('https://example.com/a');
  assert.equal(
    validateSameOriginRedirect('https://example.com', '/b', currentUrl).href,
    'https://example.com/b'
  );
  assert.equal(
    validateSameOriginRedirect('https://example.com', 'nested/file.txt', currentUrl).href,
    'https://example.com/nested/file.txt'
  );

  const rejected = [
    'https://other.example/b',
    'https://example.com:8443/b',
    'https://user@example.com/b',
    '/b?download=1',
    '/b#fragment',
    '/b?',
    '/b#',
    ''
  ];
  for (const location of rejected) {
    assert.throws(
      () => validateSameOriginRedirect('https://example.com', location, currentUrl),
      (error) =>
        isExpectedAppError(error, {
          exitCode: EXIT_CODES.invalid,
          code: 'UNSAFE_PUBLIC_REDIRECT',
          excludes: ['other.example', 'user@example.com', 'download=1', 'fragment']
        }),
      location
    );
  }

  assert.throws(
    () =>
      validateSameOriginRedirect(
        'https://example.com',
        '/b',
        new URL('https://unexpected.example/a')
      ),
    (error) =>
      isExpectedAppError(error, {
        exitCode: EXIT_CODES.invalid,
        code: 'UNSAFE_PUBLIC_REDIRECT'
      })
  );
});
