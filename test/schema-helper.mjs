import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import Ajv from 'ajv';

const schema = JSON.parse(
  readFileSync(new URL('../schemas/release-manifest-v1.schema.json', import.meta.url), 'utf8')
);
const ajv = new Ajv({ allErrors: true, strict: true });
export const validateReleaseManifestSchema = ajv.compile(schema);

/** @param {unknown} value */
export function assertSchemaAccepts(value) {
  assert.equal(
    validateReleaseManifestSchema(value),
    true,
    ajv.errorsText(validateReleaseManifestSchema.errors, { separator: '\n' })
  );
}

/** @param {unknown} value */
export function assertSchemaRejects(value) {
  assert.equal(validateReleaseManifestSchema(value), false, 'schema unexpectedly accepted fixture');
}
