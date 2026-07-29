/**
 * Field-type value validation parity — every case in the shared
 * `contract-field-validation-vector.json` vector must pass, keeping this port
 * byte-aligned with every other implementation of the same contract.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { isFieldValueValid, fieldValueError } from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const VECTOR_PATH = join(here, '..', 'testdata', 'contract-field-validation-vector.json');

interface Case {
  name: string;
  type: string;
  value: string;
  valid: boolean;
}

const cases = (JSON.parse(readFileSync(VECTOR_PATH, 'utf8')) as { cases: Case[] }).cases;

for (const c of cases) {
  test(`field validation vector: ${c.name}`, () => {
    assert.equal(isFieldValueValid(c.type, c.value), c.valid);
  });
}

test('field validation vector has all 115 cases', () => {
  assert.equal(cases.length, 115);
});

test('fieldValueError returns the type tag on failure', () => {
  assert.equal(fieldValueError('email', 'a@b.co'), null);
  assert.equal(fieldValueError('email', 'nope'), 'email');
  assert.equal(fieldValueError('text', 'anything'), null);
});
