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
  // Substring ops (text): contains needs an answer (like in); not_contains is true when
  // unanswered (like nin). Case-sensitive; empty needle counts as contained.
  if (op === 'contains') return isAnswered(val) && str(val).includes(str(target));
  if (op === 'not_contains') return !(isAnswered(val) && str(val).includes(str(target)));

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

// ── Flow constants (computed variables). Pure; extends the evaluator above. ──────────────
// Reuses the file's existing module-local helpers toNum / str / evaluateCondition WITHOUT
// modifying them, so the 27-case condition vector stays byte-identical. A "constant" is
// { key, label, result_type, expr }; computeConstants materialises each into a NEW slug->value
// map (answers + {key:value}) in dependency order. null propagates. Pinned by
// testdata/contract-flow-constants-vector.json (62 cases).

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
      // max/min are variadic and skip what is not a number: only the args that coerce to a
      // FINITE number take part, so a null or text arg never nulls the whole result. They run
      // before the null guard below for exactly that reason; no numeric arg at all -> null.
      if (e['op'] === 'max' || e['op'] === 'min') {
        const found: number[] = [];
        for (const a of args) {
          const n = toNum(evalExpr(a, answers, referenceDate));
          if (n !== null && Number.isFinite(n)) found.push(n);
        }
        if (found.length === 0) return null;
        return e['op'] === 'max' ? Math.max(...found) : Math.min(...found);
      }
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
// Same computation. `pluginSlugs` — the definition's plugin element slugs — expands every plugin
// answer first (expandPluginAnswers), so a constant can read `slug`, `slug.<block>` and
// `slug.<output>`; omit it when the flow has no plugin element.
export function resolveConstants(
  constants: unknown,
  answers: Record<string, unknown>,
  referenceDate: unknown,
  pluginSlugs?: readonly string[] | null,
): Record<string, unknown> {
  const source = pluginSlugs != null ? expandPluginAnswers(answers, pluginSlugs) : answers;
  const full = computeConstants(constants, source, referenceDate);
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

// ── Plugin answers. Pure; pinned by the shared constants vector. ──────────────────────────────
// A plugin answer's plaintext is a self-describing JSON object:
//   {"plugin","type","blocks":[{key,kind,label,id?,value}],"outputs":[{key,type,label,value}]}
// An answer without an `outputs` array is unfinished.

const PLUGIN_KEY = /^[a-z][a-z0-9_]{0,39}$/;

function isPlainObject(v: unknown): v is Json {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

// The plaintext parsed as a JSON object, or null when it is not a string holding one.
function parsePluginObject(plaintext: unknown): Json | null {
  if (typeof plaintext !== 'string') return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(plaintext);
  } catch {
    return null;
  }
  return isPlainObject(parsed) ? parsed : null;
}

// The blocks' values in stored order, each stringified, joined by " / ".
function pluginSummary(answer: Json): string {
  const blocks = Array.isArray(answer['blocks']) ? (answer['blocks'] as unknown[]) : [];
  return blocks.map((b) => str(isPlainObject(b) ? b['value'] : null)).join(' / ');
}

/**
 * Expand every plugin answer of `answers` into the keys a condition, a constant or a bound reads.
 *
 * Returns a NEW map; the input is not changed. For each slug of `pluginSlugs` whose answer is a
 * string: a value that is not a JSON object is left as it is; a JSON object without an `outputs`
 * array is an unfinished answer and its entry is REMOVED; a finished one is replaced by its
 * summary (the blocks' values joined by " / ") and adds `slug.<block>` (the block's stored value),
 * `slug.<block>.id` (a `search_select` block's picked id, as a string) and `slug.<output>` (the
 * output's typed value). A block or output key that is `id` or does not match
 * `^[a-z][a-z0-9_]{0,39}$`, and a null value, add nothing. A slug not in `pluginSlugs` is never
 * touched.
 */
export function expandPluginAnswers(
  answers: Record<string, unknown>,
  pluginSlugs: readonly string[] | null | undefined,
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...(answers || {}) };
  for (const slug of Array.isArray(pluginSlugs) ? pluginSlugs : []) {
    if (typeof slug !== 'string' || !Object.prototype.hasOwnProperty.call(out, slug)) continue;
    const answer = parsePluginObject(out[slug]);
    if (answer === null) continue;
    if (!Array.isArray(answer['outputs'])) {
      delete out[slug];
      continue;
    }
    out[slug] = pluginSummary(answer);
    const blocks = Array.isArray(answer['blocks']) ? (answer['blocks'] as unknown[]) : [];
    for (const b of blocks) {
      if (!isPlainObject(b)) continue;
      const key = b['key'];
      if (typeof key !== 'string' || key === 'id' || !PLUGIN_KEY.test(key)) continue;
      const value = b['value'] === undefined ? null : b['value'];
      if (value !== null) out[`${slug}.${key}`] = value;
      if (b['kind'] === 'search_select' && b['id'] !== undefined && b['id'] !== null) {
        out[`${slug}.${key}.id`] = str(b['id']);
      }
    }
    for (const o of answer['outputs'] as unknown[]) {
      if (!isPlainObject(o)) continue;
      const key = o['key'];
      if (typeof key !== 'string' || key === 'id' || !PLUGIN_KEY.test(key)) continue;
      const value = o['value'] === undefined ? null : o['value'];
      if (value !== null) out[`${slug}.${key}`] = value;
    }
  }
  return out;
}

/** A plugin answer's summary (its blocks' values joined by " / "), or null when it is unfinished or not one. */
export function pluginAnswerSummary(plaintext: unknown): string | null {
  const answer = parsePluginObject(plaintext);
  if (answer === null || !Array.isArray(answer['outputs'])) return null;
  return pluginSummary(answer);
}

/** A stored plugin answer in display form: the blocks, then the outputs, in stored order. */
export interface PluginAnswerView {
  blocks: { label: unknown; value: unknown }[];
  outputs: { label: unknown; type: unknown; value: unknown }[];
}

/**
 * A plugin answer for display — `{blocks: [{label, value}], outputs: [{label, type, value}]}` in
 * stored order (a `search_select` block's value is its option label) — or null when the plaintext
 * is not a JSON object with an `outputs` array.
 */
export function pluginAnswerView(plaintext: unknown): PluginAnswerView | null {
  const answer = parsePluginObject(plaintext);
  if (answer === null || !Array.isArray(answer['outputs'])) return null;
  const blocks = Array.isArray(answer['blocks']) ? (answer['blocks'] as unknown[]) : [];
  const member = (o: unknown, name: string): unknown => {
    const v = isPlainObject(o) ? o[name] : undefined;
    return v === undefined ? null : v;
  };
  return {
    blocks: blocks.map((b) => ({ label: member(b, 'label'), value: member(b, 'value') })),
    outputs: (answer['outputs'] as unknown[]).map((o) => ({
      label: member(o, 'label'),
      type: member(o, 'type'),
      value: member(o, 'value'),
    })),
  };
}

// ── Helpers the SDK's own flow code reads (not part of the package's public surface). ───────

/** Evaluate one constants-language expression over an answer map (a default, a min or a max). */
export function evaluateFlowExpression(
  expr: unknown,
  answers: Record<string, unknown>,
  referenceDate: unknown,
): unknown {
  return evalExpr(expr, answers, referenceDate);
}

/** The evaluator's own number coercion: a finite number, a numeric string, else null. */
export function flowNumber(v: unknown): number | null {
  const n = toNum(v);
  return n !== null && Number.isFinite(n) ? n : null;
}

/** The evaluator's strict YYYY-MM-DD reading as a UTC-midnight epoch, or null. */
export function flowDateUtc(v: unknown): number | null {
  const d = parseFlowDate(v);
  return d === null ? null : d.utc;
}

/** The evaluator's own stringification. */
export function flowString(v: unknown): string {
  return str(v);
}

/** Every key an expression reads: its `ref` keys and the fields of its `if` conditions. */
export function flowExprRefs(expr: unknown): string[] {
  const acc = new Set<string>();
  const walkCond = (cond: unknown): void => {
    if (!isPlainObject(cond)) return;
    const op = typeof cond['op'] === 'string' ? (cond['op'] as string) : '';
    if (op === 'and' || op === 'or' || op === 'not') {
      for (const ch of Array.isArray(cond['children']) ? (cond['children'] as unknown[]) : []) walkCond(ch);
      return;
    }
    if (typeof cond['field'] === 'string') acc.add(cond['field'] as string);
  };
  const walk = (node: unknown): void => {
    if (!isPlainObject(node)) return;
    switch (node['type']) {
      case 'ref':
        if (typeof node['key'] === 'string') acc.add(node['key'] as string);
        return;
      case 'if':
        for (const cs of Array.isArray(node['cases']) ? (node['cases'] as unknown[]) : []) {
          if (!isPlainObject(cs)) continue;
          walkCond(cs['when']);
          walk(cs['then']);
        }
        walk(node['else']);
        return;
      case 'concat':
        for (const p of Array.isArray(node['parts']) ? (node['parts'] as unknown[]) : []) walk(p);
        return;
      case 'datediff':
        walk(node['from']);
        walk(node['to']);
        return;
      case 'math':
        for (const a of Array.isArray(node['args']) ? (node['args'] as unknown[]) : []) walk(a);
        return;
    }
  };
  walk(expr);
  return [...acc];
}
