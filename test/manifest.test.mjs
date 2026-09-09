import assert from 'node:assert/strict';
import { createReadStream } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { Readable } from 'node:stream';
import path from 'node:path';
import test from 'node:test';

import { canonicalJson } from '../src/canonical-json.mjs';
import { AppError } from '../src/errors.mjs';
import {
  createReleaseManifest,
  hashFile,
  manifestDigest,
  parseReleaseManifest,
  validateReleaseManifest
} from '../src/manifest.mjs';
import { LIMITS } from '../src/paths.mjs';
import { makeTempDirectory, writeTree } from './helpers.mjs';

const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const ABC_SHA256 = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';

function validManifest() {
  return {
    schemaVersion: 1,
    algorithm: 'sha256',
    pathEncoding: 'utf8-nfc',
    entries: [{ path: 'asset.txt', bytes: 3, sha256: ABC_SHA256 }]
  };
}

/**
 * @param {unknown} error
 * @param {string | undefined} [code]
 */
function isInvalidAppError(error, code) {
  assert.equal(error instanceof AppError, true);
  assert.equal(error.exitCode, 64);
  if (code !== undefined) assert.equal(error.code, code);
  return true;
}

test('createReleaseManifest hashes every payload stream and produces exact deterministic content', async (t) => {
  const root = await makeTempDirectory(t);
  const binary = Uint8Array.from({ length: 256 }, (_, index) => index);
  await writeTree(root, {
    'empty.txt': '',
    'hello.txt': 'hello cloudflare\n',
    'values.bin': binary,
    'cafe\u0301.txt': 'unicode\n',
    'nested/data.txt': 'nested payload',
    '\ue000.txt': 'bmp-private',
    '\u{10000}.txt': 'astral'
  });

  const streamedPaths = [];
  const streamingSpy = (absolutePath) => {
    streamedPaths.push(absolutePath);
    return createReadStream(absolutePath, { highWaterMark: 7 });
  };

  const manifest = await createReleaseManifest(root, { createReadStream: streamingSpy });
  assert.deepEqual(Object.keys(manifest), ['schemaVersion', 'algorithm', 'pathEncoding', 'entries']);
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.algorithm, 'sha256');
  assert.equal(manifest.pathEncoding, 'utf8-nfc');
  assert.deepEqual(manifest.entries, [
    {
      path: 'caf\u00e9.txt',
      bytes: 8,
      sha256: 'ebc45fabefbabdd06424b3c476b11e93fec784069ff10844e7383d59f491f8cb'
    },
    { path: 'empty.txt', bytes: 0, sha256: EMPTY_SHA256 },
    {
      path: 'hello.txt',
      bytes: 17,
      sha256: 'c72f58b273e9b348a80af94f6a0798186d00b8aeeed01325a74312581fdf6b80'
    },
    {
      path: 'nested/data.txt',
      bytes: 14,
      sha256: '2bd1eacf7b8c15ec38f3d3bbb8e2bd00d0b889926c42abbdd1c8d71dfb88961c'
    },
    {
      path: 'values.bin',
      bytes: 256,
      sha256: '40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880'
    },
    {
      path: '\ue000.txt',
      bytes: 11,
      sha256: '0295992e0826c118b9310c0ece30039d75520c03092c85e9206d170f12361bff'
    },
    {
      path: '\u{10000}.txt',
      bytes: 6,
      sha256: '2e9f768344ff39ac7c1e41218b0a488a0fb666992777f7bfe03d09450df4f5b1'
    }
  ]);
  assert.equal(streamedPaths.length, manifest.entries.length);
  assert.equal(new Set(streamedPaths).size, manifest.entries.length);
  for (const entry of manifest.entries) {
    assert.deepEqual(Object.keys(entry), ['path', 'bytes', 'sha256']);
    assert.match(entry.sha256, /^[0-9a-f]{64}$/u);
  }

  const repeated = await createReleaseManifest(root);
  assert.equal(canonicalJson(manifest), canonicalJson(repeated));
});

test('hashFile reports streamed bytes and SHA-256 without buffering a payload contract', async (t) => {
  const root = await makeTempDirectory(t);
  const absolutePath = path.join(root, 'payload.txt');
  await writeTree(root, { 'payload.txt': 'abc' });

  let calls = 0;
  const result = await hashFile(absolutePath, {
    createReadStream(filePath) {
      calls += 1;
      assert.equal(filePath, absolutePath);
      return createReadStream(filePath, { highWaterMark: 1 });
    }
  });

  assert.deepEqual(result, { bytes: 3, sha256: ABC_SHA256 });
  assert.equal(calls, 1);
});

test('createReleaseManifest consumes payload streams sequentially', async (t) => {
  const root = await makeTempDirectory(t);
  await writeTree(root, { 'a.txt': 'aaa', 'b.txt': 'bbb', 'c.txt': 'ccc' });

  let active = 0;
  let maximumActive = 0;
  let calls = 0;
  const sequentialSpy = (absolutePath) => {
    calls += 1;
    active += 1;
    maximumActive = Math.max(maximumActive, active);
    if (active > 1) throw new Error('payload streams overlapped');
    const source = createReadStream(absolutePath, { highWaterMark: 1 });
    return Readable.from(
      (async function* streamSlowly() {
        try {
          for await (const chunk of source) {
            await new Promise((resolve) => setImmediate(resolve));
            yield chunk;
          }
        } finally {
          active -= 1;
        }
      })()
    );
  };

  const manifest = await createReleaseManifest(root, { createReadStream: sequentialSpy });
  assert.equal(calls, 3);
  assert.equal(maximumActive, 1);
  assert.equal(active, 0);
  assert.deepEqual(manifest.entries.map((entry) => entry.path), ['a.txt', 'b.txt', 'c.txt']);
});

test('createReleaseManifest fails when streamed bytes differ from traversal bytes', async (t) => {
  const root = await makeTempDirectory(t);
  await writeTree(root, { 'payload.txt': 'abc' });

  await assert.rejects(
    createReleaseManifest(root, {
      createReadStream() {
        return Readable.from([Buffer.from('changed')]);
      }
    }),
    (error) => isInvalidAppError(error, 'CONTENT_SIZE_CHANGED')
  );
});

test('hashFile converts native stream failures without leaking paths and preserves AppErrors', async () => {
  const privatePath = '/private/example/release/secret.txt';
  await assert.rejects(
    hashFile(privatePath, {
      createReadStream() {
        return Readable.from(
          (async function* failAfterOneChunk() {
            yield Buffer.from('partial');
            throw new Error(`EIO while reading ${privatePath}: private payload`);
          })()
        );
      }
    }),
    (error) => {
      isInvalidAppError(error, 'CONTENT_STREAM_FAILED');
      assert.equal(error.message, 'Release content stream failed');
      assert.equal(error.message.includes(privatePath), false);
      assert.equal(error.message.includes('private payload'), false);
      return true;
    }
  );

  const classified = new AppError('Already classified', 64, 'ALREADY_CLASSIFIED');
  await assert.rejects(
    hashFile(privatePath, {
      createReadStream() {
        throw classified;
      }
    }),
    (error) => error === classified
  );
});

test('validateReleaseManifest accepts exact ordinary-object shapes and clones them', () => {
  const manifest = Object.assign(Object.create(null), validManifest());
  manifest.entries = [Object.assign(Object.create(null), manifest.entries[0])];

  const validated = validateReleaseManifest(manifest);
  assert.deepEqual(validated, validManifest());
  assert.notEqual(validated, manifest);
  assert.notEqual(validated.entries, manifest.entries);
  assert.notEqual(validated.entries[0], manifest.entries[0]);
});

test('validateReleaseManifest rejects non-ordinary objects and inexact own key sets', () => {
  const topLevelExtra = { ...validManifest(), unexpected: true };
  const topLevelMissing = validManifest();
  delete topLevelMissing.algorithm;
  const topLevelSymbol = validManifest();
  topLevelSymbol[Symbol('private')] = true;
  const entryExtra = validManifest();
  entryExtra.entries[0].unexpected = true;
  const entryMissing = validManifest();
  delete entryMissing.entries[0].bytes;
  const entrySymbol = validManifest();
  entrySymbol.entries[0][Symbol('private')] = true;
  const nonOrdinaryEntry = validManifest();
  nonOrdinaryEntry.entries = [new (class ManifestEntry {
    constructor() {
      this.path = 'asset.txt';
      this.bytes = 3;
      this.sha256 = ABC_SHA256;
    }
  })()];

  for (const value of [
    [],
    new Date(0),
    topLevelExtra,
    topLevelMissing,
    topLevelSymbol,
    entryExtra,
    entryMissing,
    entrySymbol,
    nonOrdinaryEntry
  ]) {
    assert.throws(() => validateReleaseManifest(value), (error) => isInvalidAppError(error));
  }
});

test('validateReleaseManifest enforces exact version, algorithm, and path encoding constants', () => {
  for (const [key, value] of [
    ['schemaVersion', 2],
    ['schemaVersion', '1'],
    ['algorithm', 'SHA-256'],
    ['pathEncoding', 'utf8']
  ]) {
    const manifest = validManifest();
    manifest[key] = value;
    assert.throws(() => validateReleaseManifest(manifest), (error) => isInvalidAppError(error), key);
  }
});

test('validateReleaseManifest rejects unsafe, non-NFC, duplicate, and colliding paths', () => {
  const unsafePaths = [
    '',
    '/abs',
    '../escape',
    'a/../b',
    './a',
    'a//b',
    'a\\b',
    'a\u0000b',
    'a\u001fb',
    'C:/abs',
    'C:relative',
    '//server/share',
    'cafe\u0301.txt'
  ];

  for (const unsafePath of unsafePaths) {
    const manifest = validManifest();
    manifest.entries[0].path = unsafePath;
    assert.throws(() => validateReleaseManifest(manifest), (error) => isInvalidAppError(error), unsafePath);
  }

  const duplicate = validManifest();
  duplicate.entries.push({ ...duplicate.entries[0] });
  assert.throws(() => validateReleaseManifest(duplicate), (error) => isInvalidAppError(error));

  const caseCollision = validManifest();
  caseCollision.entries = [
    { path: 'A.txt', bytes: 0, sha256: EMPTY_SHA256 },
    { path: 'a.txt', bytes: 0, sha256: EMPTY_SHA256 }
  ];
  assert.throws(() => validateReleaseManifest(caseCollision), (error) => isInvalidAppError(error));

  const compatibilityCollision = validManifest();
  compatibilityCollision.entries = [
    { path: '1.txt', bytes: 0, sha256: EMPTY_SHA256 },
    { path: '\u2460.txt', bytes: 0, sha256: EMPTY_SHA256 }
  ];
  assert.throws(() => validateReleaseManifest(compatibilityCollision), (error) => isInvalidAppError(error));
});

test('validateReleaseManifest enforces Unicode code-point ordering', () => {
  const validUnicodeOrder = validManifest();
  validUnicodeOrder.entries = [
    { path: 'a.txt', bytes: 0, sha256: EMPTY_SHA256 },
    { path: '\ue000.txt', bytes: 0, sha256: EMPTY_SHA256 },
    { path: '\u{10000}.txt', bytes: 0, sha256: EMPTY_SHA256 }
  ];
  assert.deepEqual(validateReleaseManifest(validUnicodeOrder), validUnicodeOrder);

  const defaultJavaScriptOrder = validManifest();
  defaultJavaScriptOrder.entries = [
    { path: 'a.txt', bytes: 0, sha256: EMPTY_SHA256 },
    { path: '\u{10000}.txt', bytes: 0, sha256: EMPTY_SHA256 },
    { path: '\ue000.txt', bytes: 0, sha256: EMPTY_SHA256 }
  ];
  assert.throws(() => validateReleaseManifest(defaultJavaScriptOrder), (error) => isInvalidAppError(error));
});

test('validateReleaseManifest enforces integer bytes and lowercase full SHA-256 values', () => {
  for (const bytes of [-1, 1.5, Number.NaN, LIMITS.maxBytes + 1]) {
    const manifest = validManifest();
    manifest.entries[0].bytes = bytes;
    assert.throws(() => validateReleaseManifest(manifest), (error) => isInvalidAppError(error), String(bytes));
  }

  for (const sha256 of [ABC_SHA256.toUpperCase(), ABC_SHA256.slice(0, -1), `${ABC_SHA256.slice(0, -1)}g`]) {
    const manifest = validManifest();
    manifest.entries[0].sha256 = sha256;
    assert.throws(() => validateReleaseManifest(manifest), (error) => isInvalidAppError(error), sha256);
  }
});

test('validateReleaseManifest enforces file-count and aggregate-byte hard limits', () => {
  const tooMany = validManifest();
  tooMany.entries = Array.from({ length: LIMITS.maxFiles + 1 }, (_, index) => ({
    path: `file-${String(index).padStart(5, '0')}.txt`,
    bytes: 0,
    sha256: EMPTY_SHA256
  }));
  assert.throws(() => validateReleaseManifest(tooMany), (error) => isInvalidAppError(error));

  const tooLarge = validManifest();
  tooLarge.entries = [
    { path: 'a.bin', bytes: 34_359_738_369, sha256: EMPTY_SHA256 },
    { path: 'b.bin', bytes: 34_359_738_369, sha256: EMPTY_SHA256 }
  ];
  assert.throws(() => validateReleaseManifest(tooLarge), (error) => isInvalidAppError(error));

  const exactLimit = validManifest();
  exactLimit.entries = [{ path: 'max.bin', bytes: LIMITS.maxBytes, sha256: EMPTY_SHA256 }];
  assert.deepEqual(validateReleaseManifest(exactLimit), exactLimit);
});

test('parseReleaseManifest accepts strings and valid UTF-8 bytes', () => {
  const manifest = validManifest();
  const text = canonicalJson(manifest);
  assert.deepEqual(parseReleaseManifest(text), manifest);
  assert.deepEqual(parseReleaseManifest(new TextEncoder().encode(text)), manifest);
});

test('parseReleaseManifest rejects invalid UTF-8, malformed JSON, invalid manifests, and other inputs path-free', () => {
  const privateBody = '/private/example/release/secret-body.txt';
  const cases = [
    Uint8Array.of(0xc3, 0x28),
    `{"path":"${privateBody}"`,
    canonicalJson({ ...validManifest(), privateBody }),
    42
  ];

  for (const input of cases) {
    assert.throws(
      () => parseReleaseManifest(input),
      (error) => {
        isInvalidAppError(error);
        assert.equal(error.message.includes(privateBody), false);
        assert.equal(error.message.includes('\ufffd'), false);
        return true;
      }
    );
  }
});

test('manifestDigest hashes the validated canonical manifest', () => {
  const manifest = validManifest();
  assert.equal(manifestDigest(manifest), '59bcb1c758d77fe58d08df50e74dc367143f10554ce567a49d6439854711a88b');

  const invalid = { ...manifest, algorithm: 'md5' };
  assert.throws(() => manifestDigest(invalid), (error) => isInvalidAppError(error));
});

test('the strict Ajv schema accepts structural manifests and rejects structural violations', async (t) => {
  const { assertSchemaAccepts, assertSchemaRejects } = await import('./schema-helper.mjs');
  const root = await makeTempDirectory(t);
  await writeTree(root, { 'asset.txt': 'abc' });
  const generated = await createReleaseManifest(root);

  assertSchemaAccepts(generated);
  assertSchemaAccepts(validManifest());

  const extraTopLevel = { ...validManifest(), extra: true };
  const extraEntry = validManifest();
  extraEntry.entries[0].extra = true;
  const wrongVersion = { ...validManifest(), schemaVersion: 2 };
  const wrongAlgorithm = { ...validManifest(), algorithm: 'SHA-256' };
  const wrongEncoding = { ...validManifest(), pathEncoding: 'utf8' };
  const unsafePath = validManifest();
  unsafePath.entries[0].path = '../escape';
  const negativeBytes = validManifest();
  negativeBytes.entries[0].bytes = -1;
  const fractionalBytes = validManifest();
  fractionalBytes.entries[0].bytes = 1.5;
  const uppercaseHash = validManifest();
  uppercaseHash.entries[0].sha256 = ABC_SHA256.toUpperCase();
  const shortHash = validManifest();
  shortHash.entries[0].sha256 = ABC_SHA256.slice(0, -1);
  const tooMany = validManifest();
  tooMany.entries = Array.from({ length: LIMITS.maxFiles + 1 }, () => ({ ...validManifest().entries[0] }));

  for (const fixture of [
    extraTopLevel,
    extraEntry,
    wrongVersion,
    wrongAlgorithm,
    wrongEncoding,
    unsafePath,
    negativeBytes,
    fractionalBytes,
    uppercaseHash,
    shortHash,
    tooMany
  ]) {
    assertSchemaRejects(fixture);
  }
});

test('schema defers NFC, ordering, path collision, and aggregate-byte semantics to code', async () => {
  const { assertSchemaAccepts } = await import('./schema-helper.mjs');

  const decomposed = validManifest();
  decomposed.entries[0].path = 'cafe\u0301.txt';
  assertSchemaAccepts(decomposed);
  assert.throws(() => validateReleaseManifest(decomposed), (error) => isInvalidAppError(error));

  const unsorted = validManifest();
  unsorted.entries = [
    { path: 'b.txt', bytes: 0, sha256: EMPTY_SHA256 },
    { path: 'a.txt', bytes: 0, sha256: EMPTY_SHA256 }
  ];
  assertSchemaAccepts(unsorted);
  assert.throws(() => validateReleaseManifest(unsorted), (error) => isInvalidAppError(error));

  const collision = validManifest();
  collision.entries = [
    { path: 'A.txt', bytes: 0, sha256: EMPTY_SHA256 },
    { path: 'a.txt', bytes: 0, sha256: EMPTY_SHA256 }
  ];
  assertSchemaAccepts(collision);
  assert.throws(() => validateReleaseManifest(collision), (error) => isInvalidAppError(error));

  const aggregateOverflow = validManifest();
  aggregateOverflow.entries = [
    { path: 'a.bin', bytes: 34_359_738_369, sha256: EMPTY_SHA256 },
    { path: 'b.bin', bytes: 34_359_738_369, sha256: EMPTY_SHA256 }
  ];
  assertSchemaAccepts(aggregateOverflow);
  assert.throws(() => validateReleaseManifest(aggregateOverflow), (error) => isInvalidAppError(error));
});

test('manifest semantics reject lone surrogates while schema permits well-formedness checks in code', async () => {
  const { assertSchemaAccepts } = await import('./schema-helper.mjs');

  for (const unsafePath of ['high-\ud800.txt', 'low-\udfff.txt']) {
    const manifest = validManifest();
    manifest.entries[0].path = unsafePath;
    assertSchemaAccepts(manifest);
    assert.throws(
      () => validateReleaseManifest(manifest),
      (error) => isInvalidAppError(error, 'UNSAFE_MANIFEST_PATH')
    );
  }

  const astral = validManifest();
  astral.entries[0].path = 'nested/\u{1f680}.txt';
  assertSchemaAccepts(astral);
  assert.deepEqual(validateReleaseManifest(astral), astral);
});

test('createReleaseManifest excludes only the selected manifest output', async (t) => {
  const root = await makeTempDirectory(t);
  await writeTree(root, {
    'asset.txt': 'abc',
    'notes.json': '{"keep":true}\n'
  });
  await writeFile(path.join(root, 'release-manifest.json'), canonicalJson(validManifest()));

  const manifest = await createReleaseManifest(root, {
    exclude: new Set(['release-manifest.json'])
  });

  assert.deepEqual(manifest.entries.map((entry) => entry.path), ['asset.txt', 'notes.json']);
});
