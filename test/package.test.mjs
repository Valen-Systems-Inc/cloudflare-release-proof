import assert from 'node:assert/strict';
import { execFile as execFileCallback } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';

import {
  PORTABLE_ARCHIVE,
  PORTABLE_FILES,
  PORTABLE_ROOT,
  buildPortable
} from '../scripts/build-portable.mjs';
import { validateArchiveEntries, verifyPortablePackage } from '../scripts/verify-package.mjs';
import { makeTempDirectory, writeTree } from './helpers.mjs';

const execFile = promisify(execFileCallback);
const PACKAGE_ROOT = path.resolve(import.meta.dirname, '..');
const EXPECTED_FILES = [
  'cloudflare-release-proof-v0.1.0/LICENSE',
  'cloudflare-release-proof-v0.1.0/README.md',
  'cloudflare-release-proof-v0.1.0/THIRD_PARTY_NOTICES.md',
  'cloudflare-release-proof-v0.1.0/cf-release-proof',
  'cloudflare-release-proof-v0.1.0/cf-release-proof.cmd',
  'cloudflare-release-proof-v0.1.0/cf-release-proof.mjs',
  'cloudflare-release-proof-v0.1.0/examples/release-manifest.json',
  'cloudflare-release-proof-v0.1.0/examples/release/hello.txt',
  'cloudflare-release-proof-v0.1.0/licenses/MCP-LICENSE.txt',
  'cloudflare-release-proof-v0.1.0/licenses/esbuild-LICENSE.txt',
  'cloudflare-release-proof-v0.1.0/licenses/zod-LICENSE.txt',
  'cloudflare-release-proof-v0.1.0/schemas/release-manifest-v1.schema.json'
];

test('portable candidate has the exact allowlist and passes real CLI and MCP smoke checks', async (t) => {
  const outDir = await makeTempDirectory(t, 'release-proof-package-');
  const built = await buildPortable({ packageRoot: PACKAGE_ROOT, outDir });

  assert.deepEqual(PORTABLE_FILES, EXPECTED_FILES);
  assert.equal(path.basename(built.archivePath), PORTABLE_ARCHIVE);
  assert.equal(
    await readFile(built.checksumPath, 'utf8'),
    `${built.sha256}  ${PORTABLE_ARCHIVE}\n`
  );
  const { stdout } = await execFile('/usr/bin/unzip', ['-Z1', built.archivePath]);
  assert.deepEqual(stdout.trimEnd().split('\n'), EXPECTED_FILES);

  const evidencePath = path.join(outDir, 'verification.json');
  const evidence = await verifyPortablePackage({
    packageRoot: PACKAGE_ROOT,
    archivePath: built.archivePath,
    checksumPath: built.checksumPath,
    evidencePath
  });
  assert.equal(evidence.artifact.sha256, built.sha256);
  assert.equal(evidence.artifact.bytes, built.bytes);
  assert.deepEqual(evidence.artifact.entries, EXPECTED_FILES);
  assert.equal(evidence.verification.cliManifestMatch, true);
  assert.deepEqual(evidence.verification.mcpTools, [
    'create_release_manifest',
    'verify_public_release',
    'verify_release_folder'
  ]);
  assert.equal(evidence.verification.mcpManifestMatch, true);
  assert.deepEqual(evidence.state, {
    implemented: true,
    tested: true,
    archiveVerified: true,
    ownerAccepted: false,
    public: false,
    deployed: false,
    toolsPage: false,
    fieldNotes: false,
    observedUse: false,
    revenue: false
  });
  assert.deepEqual(JSON.parse(await readFile(evidencePath, 'utf8')), evidence);
});

test('unsafe names and an extra archive entry are rejected before extraction', async (t) => {
  assert.throws(
    () => validateArchiveEntries([...EXPECTED_FILES, '../escape.txt']),
    /unsafe archive entry/iu
  );

  const outDir = await makeTempDirectory(t, 'release-proof-package-extra-');
  const tamperRoot = await makeTempDirectory(t, 'release-proof-package-tamper-');
  const built = await buildPortable({ packageRoot: PACKAGE_ROOT, outDir });
  await writeTree(tamperRoot, { [`${PORTABLE_ROOT}/extra.txt`]: 'not allowlisted\n' });
  await execFile('/usr/bin/zip', ['-X', '-q', built.archivePath, `${PORTABLE_ROOT}/extra.txt`], {
    cwd: tamperRoot
  });
  const bytes = await readFile(built.archivePath);
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  await writeFile(built.checksumPath, `${sha256}  ${PORTABLE_ARCHIVE}\n`);

  await assert.rejects(
    verifyPortablePackage({
      packageRoot: PACKAGE_ROOT,
      archivePath: built.archivePath,
      checksumPath: built.checksumPath,
      evidencePath: path.join(outDir, 'must-not-exist.json')
    }),
    /archive allowlist mismatch/iu
  );
});

test('private workspace markers are rejected from an otherwise valid archive', async (t) => {
  const outDir = await makeTempDirectory(t, 'release-proof-package-private-');
  const extractRoot = await makeTempDirectory(t, 'release-proof-package-private-extract-');
  const built = await buildPortable({ packageRoot: PACKAGE_ROOT, outDir });
  await execFile('/usr/bin/unzip', ['-q', built.archivePath, '-d', extractRoot]);
  await writeFile(
    path.join(extractRoot, PORTABLE_ROOT, 'README.md'),
    'internal tracker: private-owner/work-control\n'
  );
  await execFile('/usr/bin/zip', ['-X', '-q', built.archivePath, ...EXPECTED_FILES], {
    cwd: extractRoot
  });
  const bytes = await readFile(built.archivePath);
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  await writeFile(built.checksumPath, `${sha256}  ${PORTABLE_ARCHIVE}\n`);

  await assert.rejects(
    verifyPortablePackage({
      packageRoot: PACKAGE_ROOT,
      archivePath: built.archivePath,
      checksumPath: built.checksumPath,
      evidencePath: path.join(outDir, 'must-not-exist.json')
    }),
    /archive privacy scan failed/iu
  );
});
