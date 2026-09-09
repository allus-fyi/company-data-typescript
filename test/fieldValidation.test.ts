/**
 * Field-type registry parity — every case in the shared
 * `contract-field-validation-vector.json` vector must pass; that vector is the contract
 * `FieldTypeRegistry` is held to. Its `registry` member is the row set every case is
 * resolved against.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { FieldTypeRegistry, type FieldTypeRow, type ResolvedFieldType } from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const VECTOR_PATH = join(here, '..', 'testdata', 'contract-field-validation-vector.json');

interface Case {
  name: string;
  type: string;
  value: string;
  /** The caller's own option list, present only on a choice case. */
  options?: string[];
  valid: boolean;
}

interface Vector {
  registry: FieldTypeRow[];
  cases: Case[];
  resolve_cases: Array<{ name: string; type: string; resolved: ResolvedFieldType }>;
  accepts_cases: Array<{ name: string; requested: string; actual: string; accepts: boolean }>;
  ordered_cases: Array<{ name: string; types: string[]; ordered: string[] }>;
  effective_type_cases: Array<{ name: string; type: string; effective_type: string }>;
  derived_sets: { requestable_types: string[]; flow_types: string[]; claimable_types: string[] };
}

const vector = JSON.parse(readFileSync(VECTOR_PATH, 'utf8')) as Vector;
const registry = new FieldTypeRegistry(vector.registry);

for (const c of vector.cases) {
  test(`field validation vector: ${c.name}`, () => {
    assert.equal(registry.isFieldValueValid(c.type, c.value, c.options ?? null), c.valid);
  });
}

test('field validation vector has all 177 cases', () => {
  assert.equal(vector.cases.length, 177);
});

for (const c of vector.resolve_cases) {
  test(`resolve vector: ${c.name}`, () => {
    assert.deepEqual(registry.resolve(c.type), c.resolved);
  });
}

for (const c of vector.accepts_cases) {
  test(`accepts vector: ${c.name}`, () => {
    assert.equal(registry.accepts(c.requested, c.actual), c.accepts);
  });
}

for (const c of vector.ordered_cases) {
  test(`ordered vector: ${c.name}`, () => {
    assert.deepEqual(registry.ordered(c.types), c.ordered);
  });
}

for (const c of vector.effective_type_cases) {
  test(`effectiveType vector: ${c.name}`, () => {
    assert.equal(registry.effectiveType(c.type), c.effective_type);
  });
}

test('derived sets', () => {
  assert.deepEqual(registry.requestableTypes(), vector.derived_sets.requestable_types);
  assert.deepEqual(registry.flowTypes(), vector.derived_sets.flow_types);
  assert.deepEqual(registry.claimableTypes(), vector.derived_sets.claimable_types);
});

test('fieldValueError returns the failing rule name', () => {
  assert.equal(registry.fieldValueError('email', 'a@b.co'), null);
  assert.equal(registry.fieldValueError('email', 'nope'), 'validation');
  assert.equal(registry.fieldValueError('text', 'anything'), null);
});
