import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { ReadableStream } from 'node:stream/web';
import test from 'node:test';

import { AppError, EXIT_CODES } from '../src/errors.mjs';
import { manifestDigest } from '../src/manifest.mjs';
import {
  EXPECTED_HEADER_NAMES,
  mapManifestPath,
  parseExpectedHeader,
  verifyPublicRelease
} from '../src/public-verify.mjs';
import { VERSION } from '../src/version.mjs';

const PUBLIC_LOOKUP = async () => [{ address: '1.1.1.1', family: 4 }];

/** @param {Uint8Array | string} value */
function bytes(value) {
  return typeof value === 'string' ? Buffer.from(value) : value;
}

/** @param {Uint8Array | string} value */
function sha256(value) {
  return createHash('sha256').update(bytes(value)).digest('hex');
}

/** @param {Array<[string, Uint8Array | string]>} values */
function manifestFor(values) {
  return {
    schemaVersion: 1,
    algorithm: 'sha256',
    pathEncoding: 'utf8-nfc',
    entries: values.map(([path, value]) => ({
      path,
      bytes: bytes(value).byteLength,
      sha256: sha256(value)
    }))
  };
}

/**
 * @param {Uint8Array[]} chunks
 * @param {{status?:number, headers?:HeadersInit, onCancel?:()=>void}} [options]
 */
function streamedResponse(chunks, options = {}) {
  let index = 0;
  return new Response(
    new ReadableStream({
      pull(controller) {
        if (index === chunks.length) {
          controller.close();
          return;
        }
        controller.enqueue(chunks[index]);
        index += 1;
      },
      cancel() {
        options.onCancel?.();
      }
    }),
    { status: options.status ?? 200, headers: options.headers }
  );
}

/** @param {unknown} error @param {string} code */
function assertInvalid(error, code) {
  assert.ok(error instanceof AppError);
  assert.equal(error.exitCode, EXIT_CODES.invalid);
  assert.equal(error.code, code);
  return true;
}

test('mapManifestPath encodes segments, preserves the base prefix, and maps indexes', () => {
  const base = new URL('https://public.example/releases/current/');
  const cases = [
    ['index.html', 'https://public.example/releases/current/'],
    ['folder/index.html', 'https://public.example/releases/current/folder/'],
    ['assets/app.js', 'https://public.example/releases/current/assets/app.js'],
    ['what?.txt', 'https://public.example/releases/current/what%3F.txt'],
    ['hash#.txt', 'https://public.example/releases/current/hash%23.txt'],
    ['100%.txt', 'https://public.example/releases/current/100%25.txt'],
    ['hello world.txt', 'https://public.example/releases/current/hello%20world.txt'],
    ['café.txt', 'https://public.example/releases/current/caf%C3%A9.txt'],
    ['%2e%2e/kept.txt', 'https://public.example/releases/current/%252e%252e/kept.txt']
  ];

  for (const [path, expected] of cases) {
    assert.equal(mapManifestPath(base, path).href, expected);
  }
  assert.equal(base.href, 'https://public.example/releases/current/');
  assert.throws(() => mapManifestPath(base, '../escape.txt'), (error) =>
    assertInvalid(error, 'UNSAFE_MANIFEST_PATH')
  );
});

test('parseExpectedHeader allows only the documented non-sensitive names', () => {
  assert.equal(parseExpectedHeader(undefined), null);
  assert.deepEqual(parseExpectedHeader('X-Release=v1=blue'), {
    name: 'x-release',
    value: 'v1=blue'
  });

  for (const name of EXPECTED_HEADER_NAMES) {
    assert.deepEqual(parseExpectedHeader(`${name}=value`), { name, value: 'value' });
  }

  for (const value of [
    '',
    'x-release',
    'x-release=',
    'x-release\n=value',
    'x-release=value\rsecret',
    'authorization=secret',
    'cookie=secret',
    'set-cookie=secret',
    'x-api-key=secret',
    'cf-access-client-id=secret',
    'cf-access-client-secret=secret',
    'x-not-allowlisted=value'
  ]) {
    assert.throws(() => parseExpectedHeader(value), (error) =>
      assertInvalid(error, 'INVALID_EXPECTED_HEADER')
    );
  }
});

test('verifyPublicRelease validates all inputs before the first fetch', async () => {
  let fetches = 0;
  let lookups = 0;
  const fetchImpl = async () => {
    fetches += 1;
    return new Response('should not run');
  };
  const lookup = async () => {
    lookups += 1;
    return PUBLIC_LOOKUP();
  };

  await assert.rejects(
    verifyPublicRelease('https://public.example/', { entries: [] }, { fetch: fetchImpl, lookup }),
    (error) => assertInvalid(error, 'INVALID_MANIFEST')
  );
  assert.equal(fetches, 0);
  assert.equal(lookups, 0);

  const emptyManifest = manifestFor([]);
  await assert.rejects(
    verifyPublicRelease('https://127.0.0.1/', emptyManifest, { fetch: fetchImpl, lookup }),
    (error) => assertInvalid(error, 'FORBIDDEN_PUBLIC_TARGET')
  );
  await assert.rejects(
    verifyPublicRelease('https://public.example/', emptyManifest, {
      fetch: fetchImpl,
      lookup,
      concurrency: 0
    }),
    (error) => assertInvalid(error, 'INVALID_PUBLIC_VERIFY_OPTIONS')
  );
  await assert.rejects(
    verifyPublicRelease('https://public.example/', emptyManifest, {
      fetch: fetchImpl,
      lookup,
      expectHeader: 'authorization=secret'
    }),
    (error) => assertInvalid(error, 'INVALID_EXPECTED_HEADER')
  );
  assert.equal(fetches, 0);
});

test('verifyPublicRelease streams bytes, compares hashes, and emits a deterministic receipt', async () => {
  const first = Uint8Array.of(0, 255, 1, 2);
  const expectedSecond = bytes('expected');
  const manifest = manifestFor([
    ['a.bin', first],
    ['b.txt', expectedSecond]
  ]);
  /** @type {Array<{url:string, init:RequestInit}>} */
  const requests = [];

  const makeFetch = () => async (input, init = {}) => {
    requests.push({ url: String(input), init });
    const path = new URL(String(input)).pathname;
    if (path.endsWith('/a.bin')) {
      return streamedResponse([first.subarray(0, 2), first.subarray(2)], {
        headers: { 'x-release': 'v1' }
      });
    }
    return streamedResponse([bytes('changed')], { headers: { 'x-release': 'v1' } });
  };

  const options = {
    fetch: makeFetch(),
    lookup: PUBLIC_LOOKUP,
    expectHeader: 'X-Release=v1',
    concurrency: 2
  };
  const receipt = await verifyPublicRelease('https://public.example/release', manifest, options);
  const again = await verifyPublicRelease('https://public.example/release', manifest, {
    ...options,
    fetch: makeFetch()
  });

  assert.deepEqual(receipt, again);
  assert.deepEqual(receipt, {
    schemaVersion: 1,
    kind: 'public',
    manifestSha256: manifestDigest(manifest),
    verifierVersion: VERSION,
    result: {
      outcome: 'mismatch',
      entries: [
        {
          path: 'a.bin',
          requestedUrl: 'https://public.example/release/a.bin',
          finalUrl: 'https://public.example/release/a.bin',
          status: 200,
          header: { name: 'x-release', expected: 'v1', observed: 'v1' },
          outcome: 'match',
          expected: { bytes: first.byteLength, sha256: sha256(first) },
          observed: { bytes: first.byteLength, sha256: sha256(first) }
        },
        {
          path: 'b.txt',
          requestedUrl: 'https://public.example/release/b.txt',
          finalUrl: 'https://public.example/release/b.txt',
          status: 200,
          header: { name: 'x-release', expected: 'v1', observed: 'v1' },
          outcome: 'changed',
          expected: { bytes: expectedSecond.byteLength, sha256: sha256(expectedSecond) },
          observed: { bytes: 7, sha256: sha256('changed') }
        }
      ],
      summary: { match: 1, changed: 1, missing: 0, unexpected: 0, unverified: 0, total: 2 }
    }
  });

  for (const request of requests) {
    assert.equal(request.init.method, 'GET');
    assert.equal(request.init.redirect, 'manual');
    assert.equal(request.init.credentials, 'omit');
    const headers = new Headers(request.init.headers);
    assert.deepEqual([...headers.entries()], [['accept-encoding', 'identity']]);
    assert.equal(headers.has('authorization'), false);
    assert.equal(headers.has('cookie'), false);
    assert.equal(headers.has('x-release'), false);
  }
});

test('verifyPublicRelease distinguishes missing, HTTP, body, and connection outcomes without leaking errors', async () => {
  const manifest = manifestFor([
    ['connection.txt', 'x'],
    ['missing-body.txt', 'x'],
    ['missing.txt', 'x'],
    ['server.txt', 'x']
  ]);
  const fetchImpl = async (input) => {
    const pathname = new URL(String(input)).pathname;
    if (pathname.endsWith('/connection.txt')) {
      throw new Error('SECRET transport failure at 10.0.0.1');
    }
    if (pathname.endsWith('/missing-body.txt')) return new Response(null, { status: 200 });
    if (pathname.endsWith('/missing.txt')) return new Response('private missing body', { status: 404 });
    return new Response('private server body', { status: 500 });
  };

  const receipt = await verifyPublicRelease('https://public.example/', manifest, {
    fetch: fetchImpl,
    lookup: PUBLIC_LOOKUP
  });
  const byPath = new Map(receipt.result.entries.map((entry) => [entry.path, entry]));

  assert.equal(byPath.get('connection.txt').outcome, 'unverified');
  assert.equal(byPath.get('connection.txt').errorCode, 'connection_error');
  assert.equal(byPath.get('missing-body.txt').outcome, 'unverified');
  assert.equal(byPath.get('missing-body.txt').errorCode, 'missing_body');
  assert.equal(byPath.get('missing.txt').outcome, 'missing');
  assert.equal(byPath.get('server.txt').outcome, 'changed');
  assert.equal(byPath.get('server.txt').errorCode, 'http_status');
  assert.deepEqual(receipt.result.summary, {
    match: 0,
    changed: 1,
    missing: 1,
    unexpected: 0,
    unverified: 2,
    total: 4
  });
  assert.equal(receipt.result.outcome, 'unverified');
  const serialized = JSON.stringify(receipt);
  assert.equal(serialized.includes('SECRET'), false);
  assert.equal(serialized.includes('private server body'), false);
  assert.equal(serialized.includes('10.0.0.1'), false);
});

test('verifyPublicRelease bounds response bodies and covers headers and body with one deadline', async () => {
  const manifest = manifestFor([
    ['body-stall.bin', 'ok'],
    ['headers-stall.bin', 'ok'],
    ['large.bin', 'ok']
  ]);
  let bodyCancelled = 0;
  let largeCancelled = 0;
  const fetchImpl = async (input, init = {}) => {
    const pathname = new URL(String(input)).pathname;
    if (pathname.endsWith('/headers-stall.bin')) {
      return new Promise((resolve, reject) => {
        void resolve;
        const abort = () => reject(new DOMException('aborted', 'AbortError'));
        if (init.signal?.aborted) abort();
        else init.signal?.addEventListener('abort', abort, { once: true });
      });
    }
    if (pathname.endsWith('/body-stall.bin')) {
      let sent = false;
      return new Response(
        new ReadableStream({
          pull(controller) {
            if (!sent) {
              controller.enqueue(Uint8Array.of(1));
              sent = true;
            }
          },
          cancel() {
            bodyCancelled += 1;
          }
        })
      );
    }
    return streamedResponse(
      [Uint8Array.of(1, 2), Uint8Array.of(3, 4), Uint8Array.of(5)],
      {
      onCancel() {
        largeCancelled += 1;
      }
      }
    );
  };

  const receipt = await verifyPublicRelease('https://public.example/', manifest, {
    fetch: fetchImpl,
    lookup: PUBLIC_LOOKUP,
    concurrency: 3,
    timeoutMs: 40,
    maxResponseBytes: 3
  });
  const byPath = new Map(receipt.result.entries.map((entry) => [entry.path, entry]));

  assert.equal(byPath.get('body-stall.bin').errorCode, 'timeout');
  assert.equal(byPath.get('headers-stall.bin').errorCode, 'timeout');
  assert.equal(byPath.get('large.bin').errorCode, 'response_too_large');
  assert.equal(bodyCancelled, 1);
  assert.equal(largeCancelled, 1);
});

test('verifyPublicRelease follows only bounded same-origin public redirects', async () => {
  const manifest = manifestFor([['index.html', 'ok']]);

  async function runRedirects(count) {
    let calls = 0;
    const receipt = await verifyPublicRelease('https://public.example/release', manifest, {
      lookup: PUBLIC_LOOKUP,
      fetch: async () => {
        calls += 1;
        if (calls <= count) {
          return new Response('redirect', {
            status: 302,
            headers: { location: `/release/hop-${calls}` }
          });
        }
        return new Response('ok');
      }
    });
    return { calls, receipt };
  }

  const five = await runRedirects(5);
  assert.equal(five.calls, 6);
  assert.equal(five.receipt.result.outcome, 'match');
  assert.equal(five.receipt.result.entries[0].finalUrl, 'https://public.example/release/hop-5');

  const six = await runRedirects(6);
  assert.equal(six.calls, 6);
  assert.equal(six.receipt.result.outcome, 'unverified');
  assert.equal(six.receipt.result.entries[0].errorCode, 'redirect_limit');

  let crossOriginFetches = 0;
  const crossOrigin = await verifyPublicRelease('https://public.example/', manifest, {
    lookup: PUBLIC_LOOKUP,
    fetch: async () => {
      crossOriginFetches += 1;
      return new Response(null, {
        status: 302,
        headers: { location: 'https://other.example/file' }
      });
    }
  });
  assert.equal(crossOriginFetches, 1);
  assert.equal(crossOrigin.result.entries[0].errorCode, 'cross_origin_redirect');

  let lookupCalls = 0;
  let reboundFetches = 0;
  const reboundLookup = async () => {
    lookupCalls += 1;
    if (lookupCalls < 3) return PUBLIC_LOOKUP();
    return [{ address: '127.0.0.1', family: 4 }];
  };
  const rebound = await verifyPublicRelease('https://public.example/', manifest, {
    lookup: reboundLookup,
    fetch: async () => {
      reboundFetches += 1;
      return new Response(null, { status: 302, headers: { location: '/next' } });
    }
  });
  assert.equal(reboundFetches, 1);
  assert.equal(rebound.result.entries[0].errorCode, 'unsafe_redirect');
});

test('verifyPublicRelease uses a bounded worker pool and continues after one failure', async () => {
  const manifest = manifestFor(
    Array.from({ length: 6 }, (_, index) => [`${index}.txt`, 'x'])
  );
  let active = 0;
  let maximum = 0;
  let calls = 0;
  const fetchImpl = async (input) => {
    calls += 1;
    active += 1;
    maximum = Math.max(maximum, active);
    await new Promise((resolve) => setTimeout(resolve, 5));
    active -= 1;
    if (new URL(String(input)).pathname.endsWith('/2.txt')) throw new Error('one failure');
    return new Response('x');
  };

  const receipt = await verifyPublicRelease('https://public.example/', manifest, {
    fetch: fetchImpl,
    lookup: PUBLIC_LOOKUP,
    concurrency: 2,
    timeoutMs: 500
  });

  assert.equal(calls, 6);
  assert.equal(maximum, 2);
  assert.equal(receipt.result.entries.length, 6);
  assert.equal(receipt.result.summary.unverified, 1);
});
