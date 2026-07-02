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

// ── Flow constants (computed variables) — issue #79. Pure; extends the evaluator above. ──
// Reuses the file's existing module-local helpers toNum / str / evaluateCondition WITHOUT
// modifying them, so the 27-case condition vector stays byte-identical. A "constant" is
// { key, label, result_type, expr }; computeConstants materialises each into a NEW slug->value
// map (answers + {key:value}) in dependency order. null propagates. Pinned by
// testdata/contract-flow-constants-vector.json (51 cases).

interface FlowDate {
  y: number;
  m: number;
  d: number;
  utc: number;
}

function litValue(expr: Json): unknown {
  return expr['value'] === undefined ? null : expr['value'];
}

// Parse a value as a UTC-midnight calendar date. Non-ISO-date -> null (rejects 2026-02-30 etc.).
function parseFlowDate(v: unknown): FlowDate | null {
  if (typeof v !== 'string') return null;
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(v.trim());
  if (!m) return null;
  const y = Number(m[1]);
  const mo = Number(m[2]);
  const d = Number(m[3]);
  if (mo < 1 || mo > 12 || d < 1 || d > 31) return null;
  const utc = Date.UTC(y, mo - 1, d);
  const dt = new Date(utc);
  if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== mo - 1 || dt.getUTCDate() !== d) return null;
  return { y, m: mo, d, utc };
}

function diffDays(from: FlowDate, to: FlowDate): number {
  return Math.round((to.utc - from.utc) / 86400000);
}
function diffMonths(from: FlowDate, to: FlowDate): number {
  let n = (to.y - from.y) * 12 + (to.m - from.m);
  if (to.d < from.d) n -= 1;
  return n;
}
function diffYears(from: FlowDate, to: FlowDate): number {
  let n = to.y - from.y;
  if (to.m < from.m || (to.m === from.m && to.d < from.d)) n -= 1;
  return n;
}
function roundHalfAway(n: number): number {
  return n < 0 ? -Math.round(-n) : Math.round(n);
}

// Pinned non-finite policy: math never yields Infinity/NaN — overflow -> null.
function fin(r: number): number | null {
  return Number.isFinite(r) ? r : null;
}

// evalExpr(expr, answers, referenceDate) -> value | null. Covers every AST node type.
function evalExpr(expr: unknown, answers: Record<string, unknown>, referenceDate: unknown): unknown {
  if (!expr || typeof expr !== 'object' || Array.isArray(expr)) return null;
  const e = expr as Json;
  switch (e['type']) {
    case 'lit':
      return litValue(e);
    case 'ref': {
      const key = typeof e['key'] === 'string' ? (e['key'] as string) : '';
      if (Object.prototype.hasOwnProperty.call(answers, key)) {
        const v = answers[key];
        return v === undefined ? null : v; // operand present -> its value (a stored null stays null)
      }
      return null; // operand not in the map -> null
    }
    case 'today':
      return typeof referenceDate === 'string' && referenceDate !== '' ? referenceDate : null;
    case 'if': {
      const cases = Array.isArray(e['cases']) ? (e['cases'] as unknown[]) : [];
      for (const csRaw of cases) {
        const cs = csRaw && typeof csRaw === 'object' ? (csRaw as Json) : {};
        if (evaluateCondition(cs['when'] ?? null, answers)) return evalExpr(cs['then'], answers, referenceDate);
      }
      return evalExpr(e['else'], answers, referenceDate); // else is required (total function)
    }
    case 'concat': {
      const sep = typeof e['sep'] === 'string' ? (e['sep'] as string) : '';
      const parts = Array.isArray(e['parts']) ? (e['parts'] as unknown[]) : [];
      return parts
        .map((p) => {
          const v = evalExpr(p, answers, referenceDate);
          return v === null || v === undefined ? '' : str(v); // null part -> ""
        })
        .join(sep);
    }
    case 'datediff': {
      const from = parseFlowDate(evalExpr(e['from'], answers, referenceDate));
      const to = parseFlowDate(evalExpr(e['to'], answers, referenceDate));
      if (from === null || to === null) return null; // non-date operand -> null
      switch (e['unit']) {
        case 'days':
          return diffDays(from, to);
        case 'weeks':
          return Math.trunc(diffDays(from, to) / 7); // toward zero
        case 'months':
          return diffMonths(from, to);
        case 'years':
          return diffYears(from, to);
        default:
          return null;
      }
    }
    case 'math': {
      const args = Array.isArray(e['args']) ? (e['args'] as unknown[]) : [];
      const nums = args.map((a) => toNum(evalExpr(a, answers, referenceDate)));
      // Any null / non-numeric (incl. boolean) arg -> null; a non-finite arg (a
      // string like "1e309" coercing to Infinity) -> null (pinned non-finite policy).
      if (nums.some((n) => n === null || !Number.isFinite(n))) return null;
      const ns = nums as number[];
      switch (e['op']) {
        case 'add':
          return fin(ns.reduce((a, b) => a + b, 0));
        case 'mul':
          return fin(ns.reduce((a, b) => a * b, 1));
        case 'sub':
          return ns.length >= 2 ? fin(ns[0] - ns[1]) : null;
        case 'div':
          return ns.length >= 2 && ns[1] !== 0 ? fin(ns[0] / ns[1]) : null; // /0 -> null
        case 'mod':
          return ns.length >= 2 && ns[1] !== 0 ? fin(ns[0] % ns[1]) : null; // %0 -> null; truncated remainder
        case 'neg':
          return ns.length >= 1 ? fin(-ns[0]) : null;
        case 'abs':
          return ns.length >= 1 ? fin(Math.abs(ns[0])) : null;
        case 'round':
          return ns.length >= 1 ? fin(roundHalfAway(ns[0])) : null; // half away from zero
        case 'floor':
          return ns.length >= 1 ? fin(Math.floor(ns[0])) : null;
        case 'ceil':
          return ns.length >= 1 ? fin(Math.ceil(ns[0])) : null;
        default:
          return null;
      }
    }
    default:
      return null;
  }
}

// Collect the constant KEYS an expression directly references (topological-ordering only).
function collectExprConstRefs(expr: unknown, constKeys: Set<string>, acc: Set<string>): void {
  if (!expr || typeof expr !== 'object' || Array.isArray(expr)) return;
  const e = expr as Json;
  switch (e['type']) {
    case 'ref': {
      const key = typeof e['key'] === 'string' ? (e['key'] as string) : '';
      if (constKeys.has(key)) acc.add(key);
      return;
    }
    case 'lit':
    case 'today':
      return;
    case 'if': {
      const cases = Array.isArray(e['cases']) ? (e['cases'] as unknown[]) : [];
      for (const csRaw of cases) {
        const cs = csRaw && typeof csRaw === 'object' ? (csRaw as Json) : {};
        collectCondConstRefs(cs['when'], constKeys, acc); // a when-leaf may name a constant
        collectExprConstRefs(cs['then'], constKeys, acc);
      }
      collectExprConstRefs(e['else'], constKeys, acc);
      return;
    }
    case 'concat': {
      const parts = Array.isArray(e['parts']) ? (e['parts'] as unknown[]) : [];
      for (const p of parts) collectExprConstRefs(p, constKeys, acc);
      return;
    }
    case 'datediff':
      collectExprConstRefs(e['from'], constKeys, acc);
      collectExprConstRefs(e['to'], constKeys, acc);
      return;
    case 'math': {
      const args = Array.isArray(e['args']) ? (e['args'] as unknown[]) : [];
      for (const a of args) collectExprConstRefs(a, constKeys, acc);
      return;
    }
  }
}

function collectCondConstRefs(cond: unknown, constKeys: Set<string>, acc: Set<string>): void {
  if (!cond || typeof cond !== 'object' || Array.isArray(cond)) return;
  const c = cond as Json;
  const op = typeof c['op'] === 'string' ? (c['op'] as string) : '';
  if (op === 'and' || op === 'or' || op === 'not') {
    const kids = Array.isArray(c['children']) ? (c['children'] as unknown[]) : [];
    for (const ch of kids) collectCondConstRefs(ch, constKeys, acc);
    return;
  }
  if (typeof c['field'] === 'string' && constKeys.has(c['field'] as string)) acc.add(c['field'] as string);
}

// computeConstants(constants, answers, referenceDate) -> NEW map = answers + {key:value} for
// every constant, evaluated in topological (dependency) order. A ref to an operand not yet in
// the map resolves to null; null propagates. Cycles (rejected by the validator) are broken
// defensively via 3-colour DFS -> the back-edge operand reads null. Declared array order is
// irrelevant — the DFS post-order guarantees each constant is computed after its dependencies.
// Dependency iteration is insertion-ordered (JS Set) so every port breaks the same back-edge.
export function computeConstants(
  constants: unknown,
  answers: Record<string, unknown>,
  referenceDate: unknown,
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...(answers || {}) };
  const list = Array.isArray(constants) ? (constants as unknown[]) : [];
  const byKey = new Map<string, Json>();
  for (const cRaw of list) {
    if (cRaw && typeof cRaw === 'object' && !Array.isArray(cRaw)) {
      const c = cRaw as Json;
      if (typeof c['key'] === 'string') byKey.set(c['key'] as string, c);
    }
  }
  const constKeys = new Set(byKey.keys());

  const order: string[] = [];
  const state = new Map<string, number>(); // key -> 0 visiting (grey), 1 done (black)
  const visit = (key: string): void => {
    const st = state.get(key);
    if (st === 1 || st === 0) return; // done, or grey => cycle back-edge: break it
    state.set(key, 0);
    const deps = new Set<string>();
    const c = byKey.get(key);
    if (c) collectExprConstRefs(c['expr'], constKeys, deps);
    for (const dep of deps) if (byKey.has(dep)) visit(dep);
    state.set(key, 1);
    order.push(key); // post-order => dependencies precede dependents
  };
  for (const cRaw of list) {
    if (cRaw && typeof cRaw === 'object' && !Array.isArray(cRaw)) {
      const c = cRaw as Json;
      if (typeof c['key'] === 'string') visit(c['key'] as string);
    }
  }

  for (const key of order) {
    const c = byKey.get(key);
    out[key] = c ? evalExpr(c['expr'], out, referenceDate) : null;
  }
  return out;
}

// Convenience: the resolved constant values ONLY (key -> value), without the source answers.
// Mirrors the vector's `expect` shape (declared constant keys only). Same computation.
export function resolveConstants(
  constants: unknown,
  answers: Record<string, unknown>,
  referenceDate: unknown,
): Record<string, unknown> {
  const full = computeConstants(constants, answers, referenceDate);
  const out: Record<string, unknown> = {};
  const list = Array.isArray(constants) ? (constants as unknown[]) : [];
  for (const cRaw of list) {
    if (cRaw && typeof cRaw === 'object' && !Array.isArray(cRaw)) {
      const c = cRaw as Json;
      if (typeof c['key'] === 'string') {
        const key = c['key'] as string;
        out[key] = Object.prototype.hasOwnProperty.call(full, key) ? full[key] : null;
      }
    }
  }
  return out;
}

// Per-call-site wrapper: materialise constants, then evaluate the condition unchanged.
export function evaluateFlowCondition(
  condition: unknown,
  answers: Record<string, unknown>,
  constants: unknown,
  referenceDate: unknown,
): boolean {
  return evaluateCondition(condition, computeConstants(constants, answers, referenceDate));
}
