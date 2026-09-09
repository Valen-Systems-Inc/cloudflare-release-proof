import assert from 'node:assert/strict';
import { chmod, lstat, mkdir, opendir, realpath, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { AppError } from '../src/errors.mjs';
import * as pathsModule from '../src/paths.mjs';
import {
  LIMITS,
  isSafeMcpFilePath,
  isSafeMcpFolderPath,
  manifestCollisionKey,
  normalizeManifestPath,
  resolveReadableRoot,
  resolveRootedDirectory,
  resolveRootedFile,
  walkRelease
} from '../src/paths.mjs';
import { makeTempDirectory, writeDistinctFiles, writeTree } from './helpers.mjs';

test('normalizeManifestPath rejects unsafe path spellings', () => {
  const unsafePaths = [
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
    '//server/share'
  ];

  for (const unsafe of unsafePaths) {
    assert.throws(
      () => normalizeManifestPath(unsafe),
      (error) => {
        assert.equal(error instanceof AppError, true);
        assert.equal(error.exitCode, 64);
        assert.equal(error.code, 'UNSAFE_MANIFEST_PATH');
        assert.match(error.message, /unsafe manifest path/i);
        return true;
      },
      unsafe
    );
  }

  assert.throws(() => normalizeManifestPath(''), /unsafe manifest path/i);
  assert.throws(() => normalizeManifestPath('a\u007fb'), /unsafe manifest path/i);
  assert.throws(() => normalizeManifestPath(42), /unsafe manifest path/i);
});

test('normalizeManifestPath stores valid segments in NFC', () => {
  assert.equal(normalizeManifestPath('cafe\u0301.txt'), 'caf\u00e9.txt');
  assert.equal(normalizeManifestPath('nested/asset.bin'), 'nested/asset.bin');
});

test('normalizeManifestPath rejects lone UTF-16 surrogates while preserving astral paths', () => {
  for (const unsafe of ['high-\ud800.txt', 'low-\udfff.txt']) {
    assert.throws(
      () => normalizeManifestPath(unsafe),
      (error) => {
        assert.equal(error instanceof AppError, true);
        assert.equal(error.exitCode, 64);
        assert.equal(error.code, 'UNSAFE_MANIFEST_PATH');
        assert.equal(error.message, 'Unsafe manifest path');
        return true;
      }
    );
  }

  assert.equal(normalizeManifestPath('nested/\u{1f680}.txt'), 'nested/\u{1f680}.txt');
});

test('manifestCollisionKey applies NFKC, upper, lower, and NFC comparison', () => {
  const pairs = [
    ['A.txt', 'a.txt'],
    ['caf\u00e9.txt', 'cafe\u0301.txt'],
    ['stra\u00dfe.txt', 'STRASSE.txt'],
    ['\u03bf\u03c2.txt', '\u03bf\u03c3.txt'],
    ['\u212b.txt', '\u00c5.txt']
  ];

  for (const [left, right] of pairs) {
    assert.equal(manifestCollisionKey(left), manifestCollisionKey(right), `${left} / ${right}`);
  }
});

test('MCP folder paths allow dot while MCP file paths remain strict', () => {
  assert.equal(isSafeMcpFolderPath('.'), true);
  assert.equal(isSafeMcpFolderPath('nested/release'), true);
  assert.equal(isSafeMcpFolderPath('../escape'), false);
  assert.equal(isSafeMcpFilePath('.'), false);
  assert.equal(isSafeMcpFilePath('release-manifest.json'), true);
  assert.equal(isSafeMcpFilePath('/release-manifest.json'), false);
});

test('root resolvers return only real directories and files below the readable root', async (t) => {
  const sandbox = await makeTempDirectory(t);
  const root = path.join(sandbox, 'release');
  await writeTree(root, {
    'nested/data.txt': 'safe',
    'plain.txt': 'plain'
  });

  const resolvedRoot = await resolveReadableRoot(root);
  assert.equal(resolvedRoot, await realpath(root));
  assert.equal(await resolveRootedDirectory(resolvedRoot, '.'), resolvedRoot);
  assert.equal(await resolveRootedDirectory(resolvedRoot, 'nested'), await realpath(path.join(root, 'nested')));
  assert.equal(await resolveRootedFile(resolvedRoot, 'plain.txt'), await realpath(path.join(root, 'plain.txt')));

  await assert.rejects(resolveRootedDirectory(resolvedRoot, 'plain.txt'), /directory/i);
  await assert.rejects(resolveRootedFile(resolvedRoot, 'nested'), /regular file/i);
  await assert.rejects(resolveRootedFile(resolvedRoot, '../escape.txt'), /unsafe manifest path/i);
  await assert.rejects(resolveRootedFile(resolvedRoot, '/escape.txt'), /unsafe manifest path/i);
});

test('root resolvers reject symbolic-link roots, leaves, and intermediate segments', async (t) => {
  const sandbox = await makeTempDirectory(t);
  const root = path.join(sandbox, 'release');
  const outside = path.join(sandbox, 'outside');
  await writeTree(root, { 'nested/data.txt': 'inside' });
  await writeTree(outside, { 'secret.txt': 'outside' });
  await symlink(root, path.join(sandbox, 'root-link'));
  await symlink(path.join(outside, 'secret.txt'), path.join(root, 'file-link'));
  await symlink(path.join(root, 'nested'), path.join(root, 'directory-link'));

  await assert.rejects(resolveReadableRoot(path.join(sandbox, 'root-link')), /symlink/i);

  const resolvedRoot = await resolveReadableRoot(root);
  await assert.rejects(resolveRootedFile(resolvedRoot, 'file-link'), /symlink/i);
  await assert.rejects(resolveRootedDirectory(resolvedRoot, 'directory-link'), /symlink/i);
  await assert.rejects(resolveRootedFile(resolvedRoot, 'directory-link/data.txt'), /symlink/i);
});

test('walkRelease returns nested regular files with NFC paths in code-point order', async (t) => {
  const root = await makeTempDirectory(t);
  const binary = Uint8Array.from({ length: 256 }, (_, index) => index);
  await writeTree(root, {
    'empty.txt': '',
    'nested/app.js': 'export {};\n',
    'cafe\u0301.txt': 'unicode',
    'values.bin': binary,
    '\ue000.txt': 'bmp-private',
    '\u{10000}.txt': 'astral'
  });

  const entries = await walkRelease(root);
  assert.deepEqual(entries.map(({ path: relativePath, bytes }) => [relativePath, bytes]), [
    ['caf\u00e9.txt', 7],
    ['empty.txt', 0],
    ['nested/app.js', 11],
    ['values.bin', 256],
    ['\ue000.txt', 11],
    ['\u{10000}.txt', 6]
  ]);

  for (const entry of entries) {
    assert.equal(path.isAbsolute(entry.absolutePath), true);
    assert.equal((await lstat(entry.absolutePath)).isFile(), true);
  }
});

test('walkRelease normalizes exclusions before traversal results are returned', async (t) => {
  const root = await makeTempDirectory(t);
  await writeTree(root, {
    'cafe\u0301.txt': 'skip',
    'keep.txt': 'keep'
  });

  const entries = await walkRelease(root, { exclude: new Set(['caf\u00e9.txt']) });
  assert.deepEqual(entries.map((entry) => entry.path), ['keep.txt']);
});

test('walkRelease rejects a directory exclusion that could conceal nested files or symlinks', async (t) => {
  const root = await makeTempDirectory(t);
  await writeTree(root, { 'hidden/nested.txt': 'must remain visible' });
  await symlink('nested.txt', path.join(root, 'hidden', 'nested-link.txt'));

  await assert.rejects(walkRelease(root, { exclude: new Set(['hidden']) }), (error) => {
    assert.equal(error instanceof AppError, true);
    assert.equal(error.exitCode, 64);
    assert.equal(error.code, 'EXCLUDED_DIRECTORY');
    assert.match(error.message, /exclusion.*directory/i);
    return true;
  });
});

test('walkRelease rejects a symbolic link to a file', async (t) => {
  const root = await makeTempDirectory(t);
  await writeFile(path.join(root, 'target.txt'), 'target');
  await symlink(path.join(root, 'target.txt'), path.join(root, 'link.txt'));

  await assert.rejects(walkRelease(root), /symlink/i);
});

test('walkRelease rejects a symlinked directory cycle', async (t) => {
  const root = await makeTempDirectory(t);
  await mkdir(path.join(root, 'nested'));
  await writeFile(path.join(root, 'nested', 'data.txt'), 'data');
  await symlink('..', path.join(root, 'nested', 'back'));

  await assert.rejects(walkRelease(root), /symlink/i);
});

test('walkRelease rejects every representable normalization or case-fold collision', async (t) => {
  const pairs = [
    ['A.txt', 'a.txt'],
    ['caf\u00e9.txt', 'cafe\u0301.txt'],
    ['stra\u00dfe.txt', 'STRASSE.txt'],
    ['\u03bf\u03c2.txt', '\u03bf\u03c3.txt']
  ];

  for (const [index, pair] of pairs.entries()) {
    assert.equal(manifestCollisionKey(pair[0]), manifestCollisionKey(pair[1]), pair.join(' / '));
    const root = path.join(await makeTempDirectory(t, `cf-collision-${index}-`), 'release');
    if (await writeDistinctFiles(root, pair)) {
      await assert.rejects(walkRelease(root), /collision/i, pair.join(' / '));
    }
  }
});

test('walkRelease enforces the file-count limit before returning', async (t) => {
  const root = await makeTempDirectory(t);
  await writeTree(root, { 'one.txt': '1', 'two.txt': '2', 'three.txt': '3' });

  await assert.rejects(walkRelease(root, { maxFiles: 2 }), (error) => {
    assert.equal(error.exitCode, 64);
    assert.match(error.message, /file limit/i);
    return true;
  });
});

test('walkRelease enforces the aggregate-byte limit before returning', async (t) => {
  const root = await makeTempDirectory(t);
  await writeFile(path.join(root, 'four.bin'), Uint8Array.of(0, 1, 2, 3));

  await assert.rejects(walkRelease(root, { maxBytes: 3 }), (error) => {
    assert.equal(error.exitCode, 64);
    assert.match(error.message, /byte limit/i);
    return true;
  });
});

test('walkRelease accepts an empty release within the production hard limits', async (t) => {
  const root = await makeTempDirectory(t);

  assert.equal(LIMITS.maxFiles, 10_000);
  assert.equal(LIMITS.maxBytes, 68_719_476_736);
  assert.equal(Object.isFrozen(LIMITS), true);
  assert.deepEqual(await walkRelease(root), []);
});

test('traversal error conversion is stable, path-free, and preserves existing AppErrors', () => {
  assert.equal(typeof pathsModule.toTraversalAppError, 'function');

  const privatePath = '/private/example/release/vanished.txt';
  const nativeError = new Error(`ENOENT: no such file or directory, lstat '${privatePath}'`);
  const converted = pathsModule.toTraversalAppError(nativeError);
  assert.equal(converted instanceof AppError, true);
  assert.equal(converted.exitCode, 64);
  assert.equal(converted.code, 'TRAVERSAL_FAILED');
  assert.equal(converted.message, 'Release traversal failed');
  assert.equal(converted.message.includes(privatePath), false);

  const existing = new AppError('Release contains a path collision', 64, 'PATH_COLLISION');
  assert.equal(pathsModule.toTraversalAppError(existing), existing);
});

test('walkRelease converts a traversal-time permission failure when the platform enforces it', async (t) => {
  const root = await makeTempDirectory(t);
  const blocked = path.join(root, 'blocked');
  await writeTree(blocked, { 'nested.txt': 'unreadable' });
  await chmod(blocked, 0o000);

  try {
    let permissionEnforced = false;
    try {
      const directory = await opendir(blocked);
      await directory.close();
    } catch {
      permissionEnforced = true;
    }

    if (!permissionEnforced) {
      t.skip('host privileges bypass directory permission bits');
      return;
    }

    await assert.rejects(walkRelease(root), (error) => {
      assert.equal(error instanceof AppError, true);
      assert.equal(error.exitCode, 64);
      assert.equal(error.code, 'TRAVERSAL_FAILED');
      assert.equal(error.message, 'Release traversal failed');
      assert.equal(error.message.includes(root), false);
      return true;
    });
  } finally {
    await chmod(blocked, 0o700);
  }
});
