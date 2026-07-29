/**
 * FlowConditionEvaluator parity — every case in the shared vector must pass, keeping
 * this port aligned with every other implementation of the same contract.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { evaluateCondition } from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const VECTOR_PATH = join(here, '..', 'testdata', 'contract-flow-condition-vector.json');

interface Case {
  name: string;
  condition: unknown;
  answers: Record<string, unknown>;
  expect: boolean;
}

const cases = (JSON.parse(readFileSync(VECTOR_PATH, 'utf8')) as { cases: Case[] }).cases;

for (const c of cases) {
  test(`flow condition vector: ${c.name}`, () => {
    assert.equal(evaluateCondition(c.condition, c.answers), c.expect);
  });
}

test('flow condition vector has all 35 cases', () => {
  assert.equal(cases.length, 35);
});
