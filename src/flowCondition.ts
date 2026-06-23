/**
 * Pure port of the platform `FlowConditionEvaluator` (A-spec §4) — pinned to the
 * shared `contract-flow-condition-vector.json`.
 *
 * A condition is one of:
 *   - `null` / a non-object → always `true` (the "no condition" short-circuit).
 *   - a boolean node `{op:"and"|"or"|"not", children:[...]}` (`not` = one child).
 *   - a comparison leaf `{field, op, value}` with op in
 *     `eq ne lt le gt ge in nin answered empty`.
 *
 * `answers` is the decrypted `{slug: value}` map.
 *
 * Frozen semantics (see the vector):
 *   - A blank/missing answer is "unanswered": never matches eq/ne/an ordered
 *     comparison (→ false); `empty` true, `answered` false; `nin` true on missing.
 *   - eq/ne: booleans by truth, numbers (with numeric-string coercion) by value,
 *     else strings exactly. in/nin: membership in the array `value`.
 *   - Ordered (lt/le/gt/ge): BOTH numeric → numeric compare; BOTH non-numeric →
 *     string compare (so YYYY-MM-DD dates sort chronologically); MIXED → false.
 *   - and over [] → true; or over [] → false.
 */

type Json = Record<string, unknown>;

const BOOL_OPS = new Set(['and', 'or', 'not']);

export function evaluateCondition(condition: unknown, answers: Record<string, unknown>): boolean {
  if (condition === null || condition === undefined) return true;
  if (typeof condition !== 'object' || Array.isArray(condition)) return true;
  const cond = condition as Json;
  const op = typeof cond['op'] === 'string' ? (cond['op'] as string) : '';

  if (BOOL_OPS.has(op)) {
    const kids = Array.isArray(cond['children']) ? (cond['children'] as unknown[]) : [];
    if (op === 'and') return kids.every((c) => evaluateCondition(c, answers));
    if (op === 'or') return kids.some((c) => evaluateCondition(c, answers));
    return !evaluateCondition(kids.length > 0 ? kids[0] : null, answers); // not
  }

  const slug = typeof cond['field'] === 'string' ? (cond['field'] as string) : '';
  const target = cond['value'];
  const val = Object.prototype.hasOwnProperty.call(answers, slug) ? answers[slug] : undefined;

  if (op === 'answered') return isAnswered(val);
  if (op === 'empty') return !isAnswered(val);
  if (op === 'in') return Array.isArray(target) && target.some((x) => looseEq(x, val));
  if (op === 'nin') return !(Array.isArray(target) && target.some((x) => looseEq(x, val)));

  if (!isAnswered(val)) return false;
  if (op === 'eq') return looseEq(target, val);
  if (op === 'ne') return !looseEq(target, val);
  if (op === 'lt' || op === 'gt' || op === 'le' || op === 'ge') {
    const a = toNum(val);
    const b = toNum(target);
    if (a !== null && b !== null) {
      return op === 'lt' ? a < b : op === 'gt' ? a > b : op === 'le' ? a <= b : a >= b;
    }
    // Mixed (one numeric, one not) → false; both non-numeric → string compare.
    if (a !== null || b !== null) return false;
    const sa = str(val);
    const sb = str(target);
    return op === 'lt' ? sa < sb : op === 'gt' ? sa > sb : op === 'le' ? sa <= sb : sa >= sb;
  }
  return false;
}

function isAnswered(v: unknown): boolean {
  return v !== undefined && v !== null && !(typeof v === 'string' && v === '');
}

function toNum(v: unknown): number | null {
  if (typeof v === 'boolean') return null;
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  if (typeof v === 'string' && v.trim() !== '') {
    const n = Number(v);
    return Number.isNaN(n) ? null : n;
  }
  return null;
}

function looseEq(a: unknown, b: unknown): boolean {
  if (typeof a === 'boolean' || typeof b === 'boolean') return Boolean(a) === Boolean(b);
  const na = toNum(a);
  const nb = toNum(b);
  if (na !== null && nb !== null) return na === nb;
  return str(a) === str(b);
}

function str(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') return Number.isInteger(v) ? String(v) : String(v);
  return String(v);
}
