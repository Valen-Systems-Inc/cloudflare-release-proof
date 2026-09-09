import assert from 'node:assert/strict';
import { lstat, readFile, readdir, readlink, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { InMemoryTransport } from '@modelcontextprotocol/server';

import { canonicalJson } from '../src/canonical-json.mjs';
import { verifyReleaseFolder } from '../src/local-verify.mjs';
import { createReleaseManifest } from '../src/manifest.mjs';
import { createReleaseProofServer } from '../src/mcp.mjs';
import { resolveReadableRoot } from '../src/paths.mjs';
import { verifyPublicRelease } from '../src/public-verify.mjs';
import { makeTempDirectory, writeTree } from './helpers.mjs';

const PUBLIC_LOOKUP = async () => [{ address: '1.1.1.1', family: 4 }];

/** @param {import('node:test').TestContext} t @param {Parameters<typeof createReleaseProofServer>[0]} options */
async function connectInMemory(t, options) {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = createReleaseProofServer(options);
  const client = new Client({ name: 'release-proof-test', version: '1.0.0' });
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  t.after(async () => {
    await client.close().catch(() => {});
    await server.close().catch(() => {});
  });
  return client;
}

/** @param {string} root */
async function snapshotTree(root) {
  const names = (await readdir(root, { recursive: true })).sort();
  const entries = [];
  for (const name of names) {
    const absolutePath = path.join(root, name);
    const stats = await lstat(absolutePath);
    if (stats.isSymbolicLink()) {
      entries.push([name, 'symlink', await readlink(absolutePath)]);
    } else if (stats.isFile()) {
      entries.push([name, 'file', (await readFile(absolutePath)).toString('hex')]);
    } else {
      entries.push([name, 'directory']);
    }
  }
  return entries;
}

/** @param {Client} client @param {string} name @param {Record<string, unknown>} args */
async function assertToolRejected(client, name, args) {
  try {
    const result = await client.callTool({ name, arguments: args });
    assert.equal(result.isError, true, `${name} should return an MCP tool error`);
    return result;
  } catch (error) {
    assert.ok(error instanceof Error);
    return null;
  }
}

/** @param {import('node:test').TestContext} t */
async function makeFixture(t) {
  const root = await makeTempDirectory(t, 'release-proof-mcp-');
  const site = path.join(root, 'site');
  await writeTree(root, {
    'site/app.txt': 'app bytes',
    'site/index.html': '<h1>release</h1>'
  });
  const manifest = await createReleaseManifest(site);
  await writeFile(path.join(site, 'release.json'), canonicalJson(manifest));
  await symlink(path.join(site, 'release.json'), path.join(root, 'linked-manifest.json'));
  return { root, resolvedRoot: await resolveReadableRoot(root), site, manifest };
}

test('MCP lists exactly three tools and each delegates to the existing core without writes', async (t) => {
  const fixture = await makeFixture(t);
  const fetch = async (input) => {
    const pathname = new URL(String(input)).pathname;
    if (pathname.endsWith('/app.txt')) return new Response('app bytes');
    if (pathname.endsWith('/release/')) return new Response('<h1>release</h1>');
    return new Response(null, { status: 404 });
  };
  const client = await connectInMemory(t, {
    resolvedRoot: fixture.resolvedRoot,
    fetch,
    lookup: PUBLIC_LOOKUP
  });
  const before = await snapshotTree(fixture.root);

  const listed = await client.listTools();
  assert.deepEqual(
    listed.tools.map((tool) => tool.name).sort(),
    ['create_release_manifest', 'verify_public_release', 'verify_release_folder']
  );

  const createResult = await client.callTool({
    name: 'create_release_manifest',
    arguments: { folder: 'site' }
  });
  assert.equal(createResult.isError, undefined);
  assert.equal(createResult.content[0].text, 'Release manifest created.');
  assert.deepEqual(createResult.structuredContent, await createReleaseManifest(fixture.site));

  const localResult = await client.callTool({
    name: 'verify_release_folder',
    arguments: { folder: 'site', manifestPath: 'site/release.json' }
  });
  assert.equal(localResult.isError, undefined);
  assert.equal(localResult.content[0].text, 'Local release verification completed.');
  assert.deepEqual(
    localResult.structuredContent,
    await verifyReleaseFolder(fixture.site, fixture.manifest, {
      exclude: new Set(['release.json'])
    })
  );

  const publicResult = await client.callTool({
    name: 'verify_public_release',
    arguments: {
      manifestPath: 'site/release.json',
      baseUrl: 'https://public.example/release/'
    }
  });
  assert.equal(publicResult.isError, undefined);
  assert.equal(publicResult.content[0].text, 'Public release verification completed.');
  assert.deepEqual(
    publicResult.structuredContent,
    await verifyPublicRelease('https://public.example/release/', fixture.manifest, {
      fetch,
      lookup: PUBLIC_LOOKUP
    })
  );

  assert.deepEqual(await snapshotTree(fixture.root), before);
});

test('MCP schemas and rooted resolution reject mutation fields and path escapes before work', async (t) => {
  const fixture = await makeFixture(t);
  let fetches = 0;
  const client = await connectInMemory(t, {
    resolvedRoot: fixture.resolvedRoot,
    lookup: PUBLIC_LOOKUP,
    fetch: async () => {
      fetches += 1;
      return new Response('not reached');
    }
  });
  const before = await snapshotTree(fixture.root);

  const unexpectedInputs = [
    ['create_release_manifest', { folder: '.', token: 'do-not-echo' }],
    [
      'verify_release_folder',
      { folder: 'site', manifestPath: 'site/release.json', token: 'do-not-echo' }
    ],
    [
      'verify_public_release',
      {
        manifestPath: 'site/release.json',
        baseUrl: 'https://public.example/',
        token: 'do-not-echo'
      }
    ]
  ];
  for (const [name, args] of unexpectedInputs) {
    const result = await assertToolRejected(client, name, args);
    if (result !== null) assert.equal(JSON.stringify(result).includes('do-not-echo'), false);
  }

  await assertToolRejected(client, 'create_release_manifest', { folder: '../escape' });
  await assertToolRejected(client, 'create_release_manifest', { folder: 'a'.repeat(1025) });
  await assertToolRejected(client, 'verify_release_folder', {
    folder: 'site',
    manifestPath: path.join(fixture.root, 'site/release.json')
  });
  await assertToolRejected(client, 'verify_release_folder', {
    folder: 'site',
    manifestPath: 'linked-manifest.json'
  });
  await assertToolRejected(client, 'verify_public_release', {
    manifestPath: 'site/release.json',
    baseUrl: 'x'.repeat(2049)
  });
  const unsafeUrl = await assertToolRejected(client, 'verify_public_release', {
    manifestPath: 'site/release.json',
    baseUrl: 'http://127.0.0.1/'
  });
  assert.equal(fetches, 0);
  assert.equal(JSON.stringify(unsafeUrl).includes(fixture.root), false);
  assert.deepEqual(await snapshotTree(fixture.root), before);
});

test('the CLI serves clean MCP stdio and logs readiness only to stderr', async (t) => {
  const fixture = await makeFixture(t);
  const packageRoot = path.resolve(import.meta.dirname, '..');
  const cliLink = path.join(fixture.root, 'cf-release-proof');
  await symlink(path.join(packageRoot, 'src/cli.mjs'), cliLink);
  const transport = new StdioClientTransport({
    command: cliLink,
    args: ['mcp', '--root', fixture.root],
    cwd: packageRoot,
    stderr: 'pipe'
  });
  let stderr = '';
  transport.stderr?.on('data', (chunk) => {
    stderr += chunk.toString();
  });
  const client = new Client({ name: 'release-proof-stdio-test', version: '1.0.0' });
  t.after(async () => {
    await client.close().catch(() => {});
  });

  await client.connect(transport);
  const listed = await client.listTools();
  assert.deepEqual(
    listed.tools.map((tool) => tool.name).sort(),
    ['create_release_manifest', 'verify_public_release', 'verify_release_folder']
  );
  const result = await client.callTool({
    name: 'create_release_manifest',
    arguments: { folder: 'site' }
  });
  assert.equal(result.isError, undefined);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(stderr, 'cloudflare-release-proof MCP ready\n');
  await client.close();
});
