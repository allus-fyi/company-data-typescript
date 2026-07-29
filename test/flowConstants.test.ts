/**
 * Flow constants (computed variables) parity — every case in the shared
 * contract-flow-constants-vector.json must pass, keeping this port aligned with every
 * other implementation of the same contract. Sibling of the frozen condition vector
 * in test/flowCondition.test.ts.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  resolveConstants,
  computeConstants,
  evaluateFlowCondition,
  evaluateCondition,
} from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const VECTOR_PATH = join(here, '..', 'testdata', 'contract-flow-constants-vector.json');
const CONDITION_VECTOR_PATH = join(here, '..', 'testdata', 'contract-flow-condition-vector.json');

interface Case {
  name: string;
  constants: unknown[];
  answers: Record<string, unknown>;
  reference_date: string;
  expect: Record<string, unknown>;
}

interface ConditionCase {
  name: string;
  condition: unknown;
  answers: Record<string, unknown>;
  expect: boolean;
}

const cases = (JSON.parse(readFileSync(VECTOR_PATH, 'utf8')) as { cases: Case[] }).cases;
const conditionCases = (
  JSON.parse(readFileSync(CONDITION_VECTOR_PATH, 'utf8')) as { cases: ConditionCase[] }
).cases;

for (const c of cases) {
  test(`flow constants vector: ${c.name}`, () => {
    assert.deepStrictEqual(resolveConstants(c.constants, c.answers, c.reference_date), c.expect);
  });
}

test('computeConstants merges answers and constants', () => {
  const merged = computeConstants(
    [{ key: 'c', label: 'C', result_type: 'number', expr: { type: 'ref', key: 'employees' } }],
    { employees: 11 },
    '2026-07-01',
  );
  assert.equal(merged.employees, 11);
  assert.equal(merged.c, 11);
});

test('evaluateFlowCondition resolves a constant leaf then evaluates', () => {
  const cond = { field: 'headcount', op: 'gt', value: 10 };
  const constants = [
    { key: 'headcount', label: 'H', result_type: 'number', expr: { type: 'ref', key: 'employees' } },
  ];
  assert.equal(evaluateFlowCondition(cond, { employees: 20 }, constants, '2026-07-01'), true);
  assert.equal(evaluateFlowCondition(cond, { employees: 5 }, constants, '2026-07-01'), false);
});

for (const c of conditionCases) {
  test(`evaluateFlowCondition preserves the condition vector: ${c.name}`, () => {
    assert.equal(evaluateFlowCondition(c.condition, c.answers, [], null), c.expect);
    assert.equal(evaluateCondition(c.condition, c.answers), c.expect);
  });
}

test('flow constants vector has all 51 cases', () => {
  assert.equal(cases.length, 51);
});
