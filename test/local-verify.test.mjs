import assert from 'node:assert/strict';
import { rm, symlink } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { AppError } from '../src/errors.mjs';
import { createReleaseManifest } from '../src/manifest.mjs';
import { verifyReleaseFolder } from '../src/local-verify.mjs';
import { makeTempDirectory, writeDistinctFiles, writeTree } from './helpers.mjs';

const ABC_SHA256 = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
const OLD_SHA256 = 'cba06b5736faf67e54b07b561eae94395e774c517a7d910a54369e1263ccfbd4';
const GONE_SHA256 = '283bb9deef02e6843abfb538efa1eca70801bd8a701c3f98191e123496339247';
const NEW_SHA256 = '11507a0e2f5e69d5dfa40a62a1bd7b6ee57e6bcd85c67c9b8431b36fff21c437';
const EXTRA_SHA256 = 'c8dee78f8c7b466c881847accc196998bad00e2b96c5ef913dfbe454d3807c96';

function emptyManifest() {
  return { schemaVersion: 1, algorithm: 'sha256', pathEncoding: 'utf8-nfc', entries: [] };
}

/**
 * @param {unknown} error
 * @param {string} code
 */
function isInvalidAppError(error, code) {
  assert.equal(error instanceof AppError, true);
  assert.equal(error.exitCode, 64);
  assert.equal(error.code, code);
  return true;
}

test('verifyReleaseFolder emits an exact deterministic mismatch receipt', async (t) => {
  const root = await makeTempDirectory(t);
  await writeTree(root, {
    'changed.txt': 'old',
    'missing.txt': 'gone',
    'same.txt': 'abc'
  });
  const manifest = await createReleaseManifest(root);

  await writeTree(root, {
    'changed.txt': 'new',
    'unexpected.txt': 'extra'
  });
  await rm(path.join(root, 'missing.txt'));

  const receipt = await verifyReleaseFolder(root, manifest);
  assert.deepEqual(receipt, {
    schemaVersion: 1,
    kind: 'local',
    manifestSha256: '350aed171fe965203ff282b54d187e18d909da92cd033641006920363751573f',
    verifierVersion: '0.1.0',
    result: {
      outcome: 'mismatch',
      entries: [
        {
          path: 'changed.txt',
          outcome: 'changed',
          expected: { bytes: 3, sha256: OLD_SHA256 },
          observed: { bytes: 3, sha256: NEW_SHA256 }
        },
        {
          path: 'missing.txt',
          outcome: 'missing',
          expected: { bytes: 4, sha256: GONE_SHA256 },
          observed: null
        },
        {
          path: 'same.txt',
          outcome: 'match',
          expected: { bytes: 3, sha256: ABC_SHA256 },
          observed: { bytes: 3, sha256: ABC_SHA256 }
        },
        {
          path: 'unexpected.txt',
          outcome: 'unexpected',
          expected: null,
          observed: { bytes: 5, sha256: EXTRA_SHA256 }
        }
      ],
      summary: { match: 1, changed: 1, missing: 1, unexpected: 1, unverified: 0, total: 4 }
    }
  });
  assert.equal(JSON.stringify(receipt).includes(root), false);

  const withObservation = await verifyReleaseFolder(root, manifest, {
    observationTime: '2026-09-09T12:34:56.789Z'
  });
  const { observation, ...withoutObservation } = withObservation;
  assert.deepEqual(withoutObservation, receipt);
  assert.deepEqual(observation, { observedAt: '2026-09-09T12:34:56.789Z' });
});

test('verifyReleaseFolder matches an empty release', async (t) => {
  const root = await makeTempDirectory(t);
  const receipt = await verifyReleaseFolder(root, emptyManifest());

  assert.equal(receipt.result.outcome, 'match');
  assert.deepEqual(receipt.result.entries, []);
  assert.deepEqual(receipt.result.summary, {
    match: 0,
    changed: 0,
    missing: 0,
    unexpected: 0,
    unverified: 0,
    total: 0
  });
});

test('verifyReleaseFolder forwards selected exclusions and traversal limits', async (t) => {
  const root = await makeTempDirectory(t);
  await writeTree(root, {
    'asset.txt': 'abc',
    'manifest.json': '{}\n',
    'receipt.json': '{}\n'
  });
  const exclude = new Set(['manifest.json', 'receipt.json']);
  const manifest = await createReleaseManifest(root, { exclude });

  const receipt = await verifyReleaseFolder(root, manifest, {
    exclude,
    maxFiles: 1,
    maxBytes: 3
  });
  assert.deepEqual(
    receipt.result.entries.map(({ path: relativePath, outcome }) => [relativePath, outcome]),
    [['asset.txt', 'match']]
  );

  await assert.rejects(
    verifyReleaseFolder(root, manifest, { exclude, maxFiles: 0 }),
    (error) => isInvalidAppError(error, 'FILE_LIMIT_EXCEEDED')
  );
  await assert.rejects(
    verifyReleaseFolder(root, manifest, { exclude, maxBytes: 2 }),
    (error) => isInvalidAppError(error, 'BYTE_LIMIT_EXCEEDED')
  );
});

test('verifyReleaseFolder validates manifests and observation instants before returning a receipt', async (t) => {
  const root = await makeTempDirectory(t);
  const nonexistentRoot = path.join(root, 'private-root-that-does-not-exist');

  await assert.rejects(
    verifyReleaseFolder(nonexistentRoot, {}),
    (error) => isInvalidAppError(error, 'INVALID_MANIFEST')
  );

  for (const observationTime of [
    'not-an-instant',
    '2026-09-09T12:00:00',
    '2026-02-30T12:00:00Z',
    42
  ]) {
    await assert.rejects(
      verifyReleaseFolder(root, emptyManifest(), { observationTime }),
      (error) => isInvalidAppError(error, 'INVALID_OBSERVATION_TIME')
    );
  }
});

test('verifyReleaseFolder propagates symlink and path-collision safety errors', async (t) => {
  const symlinkRoot = await makeTempDirectory(t, 'cf-release-proof-symlink-');
  await writeTree(symlinkRoot, { 'target.txt': 'abc' });
  await symlink('target.txt', path.join(symlinkRoot, 'link.txt'));
  await assert.rejects(
    verifyReleaseFolder(symlinkRoot, emptyManifest()),
    (error) => isInvalidAppError(error, 'SYMLINK_NOT_ALLOWED')
  );

  const collisionRoot = await makeTempDirectory(t, 'cf-release-proof-collision-');
  const distinct = await writeDistinctFiles(collisionRoot, ['1.txt', '\u2460.txt']);
  if (!distinct) {
    t.diagnostic('filesystem cannot represent the collision fixture as distinct names');
    return;
  }
  await assert.rejects(
    verifyReleaseFolder(collisionRoot, emptyManifest()),
    (error) => isInvalidAppError(error, 'PATH_COLLISION')
  );
});
