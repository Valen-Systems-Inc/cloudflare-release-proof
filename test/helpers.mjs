import { mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

/**
 * @param {import('node:test').TestContext} t
 * @param {string} [label]
 */
export async function makeTempDirectory(t, label = 'cf-release-proof-') {
  const root = await mkdtemp(path.join(tmpdir(), label));
  t.after(async () => {
    await rm(root, { recursive: true, force: true });
  });
  return root;
}

/**
 * @param {string} root
 * @param {Record<string, string | Uint8Array>} entries
 */
export async function writeTree(root, entries) {
  for (const [relativePath, contents] of Object.entries(entries)) {
    const absolutePath = path.join(root, ...relativePath.split('/'));
    await mkdir(path.dirname(absolutePath), { recursive: true });
    await writeFile(absolutePath, contents);
  }
}

/**
 * Some filesystems compare names case-insensitively or normalize Unicode names.
 * Return whether every requested spelling exists as a distinct directory entry.
 *
 * @param {string} root
 * @param {string[]} names
 */
export async function writeDistinctFiles(root, names) {
  await mkdir(root, { recursive: true });
  for (const [index, name] of names.entries()) {
    await writeFile(path.join(root, name), `fixture-${index}`);
  }

  const actualNames = await readdir(root);
  return names.every((name) => actualNames.includes(name)) && new Set(actualNames).size === names.length;
}
