import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJson, sha256Bytes } from '../src/canonical-json.mjs';

test('canonical JSON sorts object keys recursively and ends with one newline', () => {
  assert.equal(canonicalJson({ z: 1, a: { y: 2, x: 3 } }), '{\n  "a": {\n    "x": 3,\n    "y": 2\n  },\n  "z": 1\n}\n');
});

test('canonical JSON rejects unsupported and non-finite values', () => {
  assert.throws(() => canonicalJson({ bad: undefined }), /unsupported JSON value/i);
  assert.throws(() => canonicalJson({ bad: Number.POSITIVE_INFINITY }), /finite/i);
});

test('SHA-256 accepts text and bytes', () => {
  assert.equal(sha256Bytes('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(sha256Bytes(new Uint8Array([97, 98, 99])), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

test('canonical JSON rejects functions', () => {
  assert.throws(() => canonicalJson({ bad: () => {} }), /unsupported JSON value: function/i);
});

test('canonical JSON rejects symbols', () => {
  assert.throws(() => canonicalJson({ bad: Symbol('fixture') }), /unsupported JSON value: symbol/i);
});

test('canonical JSON rejects own symbol keys', () => {
  const value = { visible: true };
  Object.defineProperty(value, Symbol('hidden'), { value: 'fixture', enumerable: true });
  assert.throws(() => canonicalJson(value), /symbol key/i);
});

test('canonical JSON rejects bigint values', () => {
  assert.throws(() => canonicalJson({ bad: 1n }), /unsupported JSON value: bigint/i);
});

test('canonical JSON rejects sparse arrays', () => {
  const sparse = [];
  sparse.length = 1;
  assert.throws(() => canonicalJson(sparse), /sparse array/i);
});

test('canonical JSON rejects cyclic objects', () => {
  const cyclic = {};
  cyclic.self = cyclic;
  assert.throws(() => canonicalJson(cyclic), /cyclic object/i);
});

test('canonical JSON rejects non-ordinary objects', () => {
  assert.throws(() => canonicalJson(new Date(0)), /ordinary object/i);
});

test('canonical JSON preserves an own __proto__ data property', () => {
  const value = JSON.parse('{"__proto__":{"x":1}}');
  assert.equal(Object.hasOwn(value, '__proto__'), true);
  assert.equal(canonicalJson(value), '{\n  "__proto__": {\n    "x": 1\n  }\n}\n');
});

test('canonical JSON orders keys by Unicode code point', () => {
  const basicMultilingualPlane = '\uE000';
  const supplementaryPlane = '\u{10000}';
  assert.equal(
    canonicalJson({ [supplementaryPlane]: 1, [basicMultilingualPlane]: 2 }),
    `{\n  "${basicMultilingualPlane}": 2,\n  "${supplementaryPlane}": 1\n}\n`
  );
});

test('canonical JSON allows repeated non-cyclic object references', () => {
  const shared = { z: 1, a: 2 };
  assert.equal(
    canonicalJson({ right: shared, left: shared }),
    '{\n  "left": {\n    "a": 2,\n    "z": 1\n  },\n  "right": {\n    "a": 2,\n    "z": 1\n  }\n}\n'
  );
});
