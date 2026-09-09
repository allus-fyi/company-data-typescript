/**
 * The field-type registry — the whole of what a contact-field TYPE means.
 *
 * A type is a ROW, not a literal: the row says what its parent is, which primitive draws it,
 * which named check verifies it, which additive regexes it must match, which sub-fields it
 * carries and on which storage lane its value lives. The rows are served by
 * `GET /api/contact-field-types`; this module interprets them, so adding a type that reuses
 * existing primitives and checks is a row and nothing else.
 *
 * TWO FIXED VOCABULARIES, and only these two are code. `INPUTS` names the editor a value is drawn
 * with and `CHECKS` what is verified beyond a regex; a row may only name a member of each, so a
 * new member is code here rather than data.
 *
 * INHERITANCE. A child inherits any column it leaves null from its nearest ancestor that sets
 * it — `input`, `lane`, `check`, `options`, `fields`. `validation` is the exception and is
 * ADDITIVE: a value must match the regex of every ancestor that has one, root first, plus the
 * type's own. `resolve()` answers the row with every inherited column filled in and the
 * validations in that order, and every consumer works on that resolved definition rather than on
 * a raw row.
 *
 * Pinned case-for-case by `testdata/contract-field-validation-vector.json`.
 */

import { COUNTRY_CODES, US_STATE_CODES } from './countryData.js';

/** The storage lanes a value can live on. `inline` is the value itself; the other two are files. */
export const LANES = ['inline', 'photo', 'document'] as const;

/** The drawing primitives a row may name. A new member is code here, not a row. */
export const INPUTS = [
  'line',
  'date',
  'list',
  'multilist',
  'country',
  'nationality',
  'state',
  'phone',
  'composite',
  'file',
  'pages',
] as const;

/** The named checks a row may name — verification beyond a regex. A new member is code here, not a row. */
export const CHECKS = ['url', 'card', 'number', 'integer', 'decimal', 'float'] as const;

/**
 * The lanes each primitive can store on. `file` is the only primitive with a choice, which is
 * why a root with that input is the only row whose lane an operator picks.
 */
// A null prototype, because the keys are registry identifiers: `^[a-z0-9_]{1,40}$` admits
// `constructor` and `tostring`, and an inherited member must never answer a lookup here.
export const INPUT_LANES: Record<string, readonly string[]> = Object.assign(Object.create(null), {
  line: ['inline'],
  date: ['inline'],
  list: ['inline'],
  multilist: ['inline'],
  country: ['inline'],
  nationality: ['inline'],
  state: ['inline'],
  phone: ['inline'],
  composite: ['inline'],
  file: ['photo', 'document'],
  pages: ['document'],
});

/** The primitives a sub-field entry may name: no composite nesting and no binary. */
export const ENTRY_INPUTS = ['line', 'date', 'list', 'country', 'nationality', 'state', 'phone'] as const;

/**
 * The members a `file`/`pages` envelope carries itself. They belong to the primitive, so a
 * `fields` entry may never claim one — the entries are the extra metadata beside them.
 */
export const ENVELOPE_MEMBERS = [
  'file',
  'pages',
  'original_name',
  'mime_type',
  'size',
  'name',
  'full',
  'thumb',
] as const;

/** The members ONE page of a `pages` envelope may carry. */
export const PAGE_MEMBERS = ['label', 'file', 'original_name', 'mime_type', 'size'] as const;

/** The page slots the multi-page upload draws: a front, an optional back, repeatable extras. */
export const PAGE_LABELS = ['front', 'back', 'additional'] as const;

/** The longest a stored `validation` regex may be. */
export const MAX_VALIDATION_LENGTH = 200;

/** One raw registry row, exactly as `GET /api/contact-field-types` serves it. */
export interface FieldTypeRow {
  type: string;
  parent?: string | null;
  label?: string | null;
  input?: string | null;
  lane?: string | null;
  check?: string | null;
  options?: string[] | null;
  fields?: SubFieldEntry[] | null;
  validation?: string | null;
  is_system?: boolean | null;
}

/** One sub-field entry of a `composite`, `file` or `pages` type. */
export interface SubFieldEntry {
  key: string;
  input?: string | null;
  required?: boolean | null;
  check?: string | null;
  validation?: string | null;
  options?: string[] | null;
}

/** A row with every inherited column filled in, plus the validations root-first. */
export interface ResolvedFieldType {
  type: string;
  parent: string | null;
  label: string;
  is_system: boolean;
  known: boolean;
  input: string | null;
  lane: string | null;
  check: string | null;
  options: string[] | null;
  fields: SubFieldEntry[] | null;
  validations: string[];
}

const COUNTRY_CODE_SET = new Set<string>(COUNTRY_CODES as readonly string[]);
const US_STATE_CODE_SET = new Set<string>(US_STATE_CODES as readonly string[]);

const URL_RE = /^https?:\/\/[^\s/$.?#][^\s]*\.[^\s]{2,}$/i;
const URL_SCHEME_RE = /^https?:\/\//i;
const MIME_RE = /^[\w.+-]+\/[\w.+-]+$/;
const PHONE_RE = /^\+?\d{4,15}$/;
const PHONE_STRIP_RE = /[ \-().]/g;
const CARD_RE = /^\d{12,19}$/;
const CARD_STRIP_RE = /[ -]/g;
// Numeric grammars accept ASCII digits only, so a hex literal, an Infinity/NaN spelling or a
// Unicode digit is refused rather than accepted by the language's own numeric reader.
const INTEGER_RE = /^-?[0-9]+$/;
// decimal(10,2) is a FIXED shape: up to 8 integer digits + up to 2 decimal digits.
const DECIMAL_RE = /^-?[0-9]{1,8}(\.[0-9]{1,2})?$/;
// Float accepts decimal or scientific notation.
const FLOAT_RE = /^-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

// Compiled stored regexes, keyed by the raw pattern. `null` records a pattern this engine cannot
// compile, so it is attempted once rather than per value.
const COMPILED = new Map<string, RegExp | null>();

function daysInMonth(year: number, month: number): number {
  if (month === 2) {
    const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
    return leap ? 29 : 28;
  }
  return DAYS_IN_MONTH[month - 1]!;
}

/** A real calendar date in `YYYY-MM-DD`. */
export function isCalendarDate(value: string): boolean {
  if (!DATE_RE.test(value)) return false;
  const year = Number(value.slice(0, 4));
  const month = Number(value.slice(5, 7));
  const day = Number(value.slice(8, 10));
  if (month < 1 || month > 12) return false;
  return day >= 1 && day <= daysInMonth(year, month);
}

function luhnOk(digits: string): boolean {
  let total = 0;
  let dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    total += d;
    dbl = !dbl;
  }
  return total % 10 === 0;
}

function finiteNumber(value: string): boolean {
  if (value === '') return false;
  const n = Number(value);
  return Number.isFinite(n);
}

/**
 * The CANONICAL FORM a named check verifies.
 *
 * It is also the form a regex below that check is tested against, since the check is what states
 * it. A check with nothing to normalise, and a name that is not a check at all, answer the value
 * unchanged.
 */
export function normaliseForCheck(check: string, value: string): string {
  switch (check) {
    case 'url':
      return URL_SCHEME_RE.test(value) ? value : `https://${value}`;
    case 'card':
      return value.replace(CARD_STRIP_RE, '');
    case 'number':
    case 'integer':
    case 'decimal':
    case 'float':
      return value.trim();
    default:
      return value;
  }
}

/** One named check, applied to the whole value in its canonical form; null when it passes. */
export function applyCheck(check: string, value: string): string | null {
  const normalised = normaliseForCheck(check, value);
  let ok: boolean;
  switch (check) {
    case 'url':
      ok = URL_RE.test(normalised);
      break;
    case 'card':
      ok = CARD_RE.test(normalised) && luhnOk(normalised);
      break;
    case 'number':
      ok = finiteNumber(normalised);
      break;
    case 'integer':
      ok = INTEGER_RE.test(normalised);
      break;
    case 'decimal':
      ok = DECIMAL_RE.test(normalised);
      break;
    case 'float':
      ok = FLOAT_RE.test(normalised);
      break;
    default:
      ok = true;
  }
  return ok ? null : check;
}

/** A stored regex anchored to the WHOLE value, or null when it cannot compile. */
export function compileRegex(regex: string): RegExp | null {
  if (COMPILED.has(regex)) return COMPILED.get(regex)!;
  let compiled: RegExp | null;
  try {
    compiled = new RegExp(`^(?:${regex})$`);
  } catch {
    compiled = null;
  }
  COMPILED.set(regex, compiled);
  return compiled;
}

/**
 * Whether a value matches a stored regex, which is anchored to the whole value.
 *
 * A pattern that cannot be compiled is refused at write, so reaching this with one means the
 * stored row predates the rule it is now held to: no verdict can be stated, and refusing the
 * value would refuse every value of that type.
 */
export function matchesRegex(regex: string, value: string): boolean {
  const compiled = compileRegex(regex);
  return compiled === null || compiled.test(value);
}

function isOptionArray(value: string, options: readonly string[]): boolean {
  let decoded: unknown;
  try {
    decoded = JSON.parse(value);
  } catch {
    return false;
  }
  if (!Array.isArray(decoded)) return false;
  return decoded.every((e) => typeof e === 'string' && options.includes(e));
}

function compareLabels(a: string, b: string): number {
  const la = a.toLowerCase();
  const lb = b.toLowerCase();
  if (la < lb) return -1;
  if (la > lb) return 1;
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

/**
 * The served rows, interpreted.
 *
 * Built from the raw `GET /api/contact-field-types` array and held for the life of the client
 * that fetched it. An instance with no rows knows no type, which is the honest answer for a
 * client that has not loaded the registry: every type resolves as unknown and validates as
 * "accept anything".
 */
export class FieldTypeRegistry {
  private readonly byType = new Map<string, FieldTypeRow>();
  private readonly resolved = new Map<string, ResolvedFieldType>();

  constructor(rows: readonly FieldTypeRow[] = []) {
    for (const row of rows ?? []) {
      if (row && typeof row.type === 'string' && row.type !== '') this.byType.set(row.type, row);
    }
  }

  // ── the tree ─────────────────────────────────────────────────────────────

  /** The raw rows keyed by type. */
  rows(): Map<string, FieldTypeRow> {
    return this.byType;
  }

  /** Every type the registry carries. */
  types(): string[] {
    return [...this.byType.keys()];
  }

  /** Whether the registry carries this type at all. */
  knows(type: string | null | undefined): boolean {
    return this.byType.has(type ?? '');
  }

  /**
   * The resolved definition: every inherited column filled in, validations root-first.
   *
   * A type the registry does not carry resolves to the UNKNOWN definition — every column null,
   * no validations, `known` false. That is a distinct answer from a known type with nothing set,
   * and callers must read it as "this client cannot draw or store this", never as a default.
   */
  resolve(type: string | null | undefined): ResolvedFieldType {
    const key = type ?? '';
    let cached = this.resolved.get(key);
    if (cached === undefined) {
      cached = this.resolveIn(key);
      this.resolved.set(key, cached);
    }
    return cached;
  }

  private resolveIn(type: string): ResolvedFieldType {
    const row = this.byType.get(type);
    if (row === undefined) {
      return {
        type,
        parent: null,
        label: type,
        is_system: false,
        known: false,
        input: null,
        lane: null,
        check: null,
        options: null,
        fields: null,
        validations: [],
      };
    }

    // Walk to the root collecting the chain, then fill downward: the nearest ancestor that sets
    // an inherited column wins, and the validations come out root-first.
    const chain: FieldTypeRow[] = [];
    const seen = new Set<string>();
    let cursor: string | null | undefined = type;
    while (cursor !== null && cursor !== undefined && this.byType.has(cursor) && !seen.has(cursor)) {
      seen.add(cursor);
      chain.push(this.byType.get(cursor)!);
      cursor = this.byType.get(cursor)!.parent;
    }
    chain.reverse();

    const definition: ResolvedFieldType = {
      type,
      parent: row.parent ?? null,
      label: row.label ?? type,
      is_system: Boolean(row.is_system),
      known: true,
      input: null,
      lane: null,
      check: null,
      options: null,
      fields: null,
      validations: [],
    };
    for (const ancestor of chain) {
      if (ancestor.input !== null && ancestor.input !== undefined) definition.input = ancestor.input;
      if (ancestor.lane !== null && ancestor.lane !== undefined) definition.lane = ancestor.lane;
      if (ancestor.check !== null && ancestor.check !== undefined) definition.check = ancestor.check;
      if (ancestor.options !== null && ancestor.options !== undefined) definition.options = ancestor.options;
      if (ancestor.fields !== null && ancestor.fields !== undefined) definition.fields = ancestor.fields;
      if (ancestor.validation) definition.validations.push(ancestor.validation);
    }
    return definition;
  }

  /**
   * The type and every descendant of it. An unknown type answers itself alone, so a lookup keyed
   * on a type the registry does not carry still addresses that type rather than nothing.
   */
  descendants(type: string): string[] {
    const out = [type];
    let frontier = new Set<string>([type]);
    // Bounded by the number of rows: each pass adds only types not already collected.
    for (let guard = this.byType.size; guard > 0 && frontier.size > 0; guard--) {
      const next = new Set<string>();
      for (const [candidate, row] of this.byType) {
        const parent = row.parent ?? null;
        if (parent !== null && frontier.has(parent) && !out.includes(candidate)) {
          out.push(candidate);
          next.add(candidate);
        }
      }
      frontier = next;
    }
    return out;
  }

  /** Whether a request for `requested` is answered by a field of `actual`. */
  accepts(requested: string, actual: string): boolean {
    return actual === requested || this.descendants(requested).includes(actual);
  }

  // ── storage lane ─────────────────────────────────────────────────────────

  /** Whether this type's value is a file rather than an inline value. */
  isBinary(type: string | null | undefined): boolean {
    const lane = this.resolve(type).lane;
    return lane !== null && lane !== 'inline';
  }

  /** Whether this type uses the document upload/storage lane. */
  isDocumentLike(type: string | null | undefined): boolean {
    return this.resolve(type).lane === 'document';
  }

  /** Whether this type carries the multi-page ID-document envelope. */
  isIdDocument(type: string | null | undefined): boolean {
    return this.resolve(type).input === 'pages';
  }

  /** Every type on a lane other than `inline`. */
  binaryTypes(): string[] {
    return this.types().filter((t) => this.isBinary(t));
  }

  /** Every type on the `document` lane. */
  documentLikeTypes(): string[] {
    return this.types().filter((t) => this.isDocumentLike(t));
  }

  /** Every type drawn by the multi-page upload. */
  idDocumentTypes(): string[] {
    return this.types().filter((t) => this.isIdDocument(t));
  }

  // ── derived sets ─────────────────────────────────────────────────────────

  /**
   * A choice type whose options are supplied elsewhere. It is usable only where something else
   * carries them — a flow element — so it is offered for no contact field, no request row and no
   * claim.
   */
  isOptionLessChoice(type: string): boolean {
    const definition = this.resolve(type);
    const isChoice = definition.input === 'list' || definition.input === 'multilist';
    return isChoice && (definition.options === null || definition.options.length === 0);
  }

  /**
   * The option domain a choice value is held to: the ROW's own resolved options when it carries
   * any, else the ones the caller supplies, and NEVER a merge of the two — a row that states its
   * domain owns it, and a row that states none borrows the caller's whole.
   *
   * `null` means neither source has a domain: an option-less row asked about with nothing
   * supplied. A value cannot be measured against that, so `validate` refuses rather than testing
   * membership of an empty list, which would refuse every value including a legitimate one.
   *
   * Public so a caller can RENDER exactly the domain the validator will enforce.
   */
  optionsFor(type: string | null | undefined, suppliedOptions: readonly string[] | null = null): string[] | null {
    const rowOptions = this.resolve(type).options;
    if (rowOptions !== null && rowOptions.length > 0) return [...rowOptions];
    if (suppliedOptions !== null && suppliedOptions.length > 0) return [...suppliedOptions];
    return null;
  }

  /** The types a contact field, a service request row or an admin field may declare. */
  requestableTypes(): string[] {
    return this.types().filter((t) => !this.isOptionLessChoice(t));
  }

  /** The requestable set plus the option-less choice types a flow element supplies options for. */
  flowTypes(): string[] {
    return [...this.requestableTypes(), ...this.types().filter((t) => this.isOptionLessChoice(t))];
  }

  /**
   * The types an OAuth claim may declare: the requestable set on the `inline` lane. A file can
   * never be sealed to a relying party's app key, so no claim can name a binary type.
   */
  claimableTypes(): string[] {
    return this.requestableTypes().filter((t) => this.resolve(t).lane === 'inline');
  }

  // ── display ──────────────────────────────────────────────────────────────

  /**
   * The label to render. A seeded row's `label` is the `fieldtype_*` translation key and a
   * data-added row's is the literal an operator typed; `is_system` is the discriminator, and a
   * literal is rendered verbatim rather than looked up.
   */
  labelFor(type: string): string {
    return this.resolve(type).label;
  }

  /**
   * The requested types in display order: roots A→Z, each followed by its own children A→Z,
   * recursively, by the stored `label`. A requested type the registry does not carry sorts after
   * the tree, so a picker built from a stale set still shows every entry it was given.
   */
  ordered(types: readonly string[]): string[] {
    const wanted = new Set(types);
    const out: string[] = [];

    const childrenOf = (parent: string | null): string[] => {
      const found: Array<[string, string]> = [];
      for (const [name, row] of this.byType) {
        if ((row.parent ?? null) === parent) found.push([row.label ?? name, name]);
      }
      found.sort((a, b) => compareLabels(a[0], b[0]));
      return found.map(([, name]) => name);
    };

    const walk = (parent: string | null): void => {
      for (const name of childrenOf(parent)) {
        if (wanted.has(name)) out.push(name);
        walk(name);
      }
    };
    walk(null);

    const unknown = types.filter((t) => !out.includes(t)).slice().sort(compareLabels);
    return [...out, ...unknown];
  }

  /**
   * The nearest ancestor, self included, that is `date` or `number`; otherwise the type itself.
   * It collapses a type to the domain its comparison operators are chosen from; nothing in
   * `validate` consults it, and no value's shape follows it.
   */
  effectiveType(type: string): string {
    const seen = new Set<string>();
    let cursor: string | null | undefined = type;
    while (cursor !== null && cursor !== undefined && this.byType.has(cursor) && !seen.has(cursor)) {
      seen.add(cursor);
      if (cursor === 'date' || cursor === 'number') return cursor;
      cursor = this.byType.get(cursor)!.parent;
    }
    return type;
  }

  // ── validation ───────────────────────────────────────────────────────────

  /**
   * Validate a plaintext value against a type, in the one fixed order: the
   * primitive's own rule, then the resolved check, then every regex root-first, then the
   * sub-field entries. The CHECK's normalised value is what those regexes see; the primitive's is
   * not.
   *
   * An EMPTY value is valid — required is the caller's job — and a type the registry does not
   * carry accepts anything, which is the pinned answer for a client older than a type.
   *
   * Returns null when valid, else the name of the first failing rule.
   */
  validate(
    type: string | null | undefined,
    value: unknown,
    suppliedOptions: readonly string[] | null = null,
  ): string | null {
    const text = value === null || value === undefined ? '' : String(value);
    if (text === '') return null;
    const definition = this.resolve(type);
    if (!definition.known) return null;

    const failure = this.applyPrimitive(definition, text, this.optionsFor(type, suppliedOptions));
    if (failure !== null) return failure;

    // A CHECK'S NORMALISATION CARRIES; A PRIMITIVE'S DOES NOT, and the asymmetry is the rule
    // rather than an oversight. A check states the canonical form of the value it verifies — a
    // URL with its scheme, a card number without its separators — so a regex a child adds below
    // it describes that form and is tested against it. A primitive draws a value it does not
    // rewrite, so nothing it does reaches the regex step.
    let matched = text;
    if (definition.check) {
      const checkFailure = applyCheck(definition.check, text);
      if (checkFailure !== null) return checkFailure;
      matched = normaliseForCheck(definition.check, text);
    }
    for (const regex of definition.validations) {
      if (!matchesRegex(regex, matched)) return 'validation';
    }
    return null;
  }

  /** True when `value` is an acceptable plaintext for `type`. */
  isFieldValueValid(
    type: string | null | undefined,
    value: unknown,
    suppliedOptions: readonly string[] | null = null,
  ): boolean {
    return this.validate(type, value, suppliedOptions) === null;
  }

  /** Null when valid, else the name of the first failing rule. */
  fieldValueError(
    type: string | null | undefined,
    value: unknown,
    suppliedOptions: readonly string[] | null = null,
  ): string | null {
    return this.validate(type, value, suppliedOptions);
  }

  /**
   * The primitive's own rule, plus the sub-field entries for the three that carry them.
   *
   * `options` is the domain a choice value is held to, already resolved by `optionsFor`; `null`
   * is "there is no domain", which is refused rather than tested.
   */
  private applyPrimitive(
    definition: ResolvedFieldType,
    value: string,
    options: readonly string[] | null,
  ): string | null {
    const primitive = definition.input;
    switch (primitive) {
      case null:
      case 'line':
        return null;
      case 'date':
        return isCalendarDate(value) ? null : 'date';
      case 'list':
        if (options === null) return 'options_unavailable';
        return options.includes(value) ? null : 'list';
      case 'multilist':
        if (options === null) return 'options_unavailable';
        return isOptionArray(value, options) ? null : 'multilist';
      case 'country':
      case 'nationality':
        return COUNTRY_CODE_SET.has(value) ? null : primitive;
      case 'state':
        return US_STATE_CODE_SET.has(value) ? null : 'state';
      case 'phone':
        return PHONE_RE.test(value.replace(PHONE_STRIP_RE, '')) ? null : 'phone';
      case 'composite':
        return validateObject(value, definition.fields ?? [], []);
      case 'file':
      case 'pages':
        return validateObject(value, definition.fields ?? [], ENVELOPE_MEMBERS as readonly string[]);
      default:
        return null;
    }
  }
}

/**
 * A JSON object value: no unknown key, every required entry present, and each non-empty entry
 * valid for its own primitive, check and regex.
 *
 * `envelopeMembers` are the primitive's own members, accepted beside the entries and validated by
 * `validateEnvelopeMember` — the one home for what each of them looks like.
 */
function validateObject(
  value: string,
  fields: readonly SubFieldEntry[],
  envelopeMembers: readonly string[],
): string | null {
  let obj: unknown;
  try {
    obj = JSON.parse(value);
  } catch {
    return 'object';
  }
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return 'object';

  const entries = new Map<string, SubFieldEntry>();
  for (const entry of fields) {
    if (entry && typeof entry.key === 'string') entries.set(entry.key, entry);
  }

  const record = obj as Record<string, unknown>;
  for (const [key, raw] of Object.entries(record)) {
    const entry = entries.get(key);
    if (entry !== undefined) {
      if (typeof raw !== 'string') return key;
      if (raw !== '' && validateEntry(entry, raw) !== null) return key;
      continue;
    }
    if (!envelopeMembers.includes(key)) return 'unknown_key';
    const memberFailure = validateEnvelopeMember(key, raw);
    if (memberFailure !== null) return memberFailure;
  }

  for (const [key, entry] of entries) {
    // OWN properties only. A sub-field key is a registry identifier and `^[a-z0-9_]{1,40}$`
    // admits `constructor` and `tostring`; `in` would find those on the prototype and read a
    // required entry as present on an object that never carried it.
    const present = Object.prototype.hasOwnProperty.call(record, key);
    if (entry.required && (!present || record[key] === '')) return key;
  }
  return null;
}

/**
 * ONE member of a `file`/`pages` envelope, by its own shape — the single home for what each
 * member looks like, so a member added to the envelope is one branch here and nothing else.
 *
 * `size` is a JSON integer, `pages` the multi-page list below, `mime_type` a MIME string when it
 * carries anything, and every other member a string.
 */
function validateEnvelopeMember(key: string, raw: unknown): string | null {
  if (key === 'pages') return validatePages(raw);
  if (key === 'size') return typeof raw === 'number' && Number.isInteger(raw) ? null : 'size';
  if (typeof raw !== 'string') return key;
  if (key === 'mime_type' && raw !== '' && !MIME_RE.test(raw)) return 'mime_type';
  return null;
}

/**
 * The `pages` member of an ID-document envelope: a LIST of page objects, never a scalar.
 *
 * Each page names one uploaded file plus that file's own metadata. `file` is the reference and is
 * required; `label` says which slot the page fills, and the slots are exactly the ones the
 * multi-page editor draws — a front, an optional back, and repeatable extras. An empty list is a
 * document whose pages have not been uploaded yet, which is a valid envelope.
 */
function validatePages(raw: unknown): string | null {
  if (!Array.isArray(raw)) return 'pages';
  for (const page of raw) {
    if (page === null || typeof page !== 'object' || Array.isArray(page)) return 'pages';
    const record = page as Record<string, unknown>;
    for (const [key, member] of Object.entries(record)) {
      if (!PAGE_MEMBERS.includes(key as (typeof PAGE_MEMBERS)[number])) return 'pages';
      if (key === 'label') {
        if (typeof member !== 'string') return 'pages';
        if (!PAGE_LABELS.includes(member as (typeof PAGE_LABELS)[number])) return 'pages';
        continue;
      }
      if (key === 'file') {
        if (typeof member !== 'string' || member === '') return 'pages';
        continue;
      }
      if (validateEnvelopeMember(key, member) !== null) return 'pages';
    }
    if (!Object.prototype.hasOwnProperty.call(record, 'file')) return 'pages';
  }
  return null;
}

/** One sub-field entry: its primitive rule, then its check, then its regex. */
function validateEntry(entry: SubFieldEntry, value: string): string | null {
  const primitive = entry.input ?? 'line';
  const options = entry.options ?? [];
  let failure: string | null = null;
  switch (primitive) {
    case 'date':
      failure = isCalendarDate(value) ? null : 'date';
      break;
    case 'list':
      failure = options.includes(value) ? null : 'list';
      break;
    case 'country':
    case 'nationality':
      failure = COUNTRY_CODE_SET.has(value) ? null : primitive;
      break;
    case 'state':
      failure = US_STATE_CODE_SET.has(value) ? null : 'state';
      break;
    case 'phone':
      failure = PHONE_RE.test(value.replace(PHONE_STRIP_RE, '')) ? null : 'phone';
      break;
    default:
      failure = null;
  }
  if (failure !== null) return failure;

  // The entry runs the same primitive → check → regex order a top-level value does, and the
  // check's normalisation carries into its regex for the same reason it does there — so a
  // composite's entry can never disagree with a value of the same shape.
  let matched = value;
  if (entry.check) {
    if (applyCheck(entry.check, value) !== null) return entry.check;
    matched = normaliseForCheck(entry.check, value);
  }
  if (entry.validation && !matchesRegex(entry.validation, matched)) return 'validation';
  return null;
}
