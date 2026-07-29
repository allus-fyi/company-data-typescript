/**
 * Shared field-type value validation.
 *
 * Pure + i18n-free port of the canonical field-validation reference, kept byte-aligned
 * with every other implementation of the same contract by
 * `testdata/contract-field-validation-vector.json`. Spec:
 * `docs/superpowers/specs/2026-07-15-field-type-validation-design.html`.
 *
 * Contract: `isFieldValueValid(type, value) -> boolean`. Empty value = valid
 * (required is the caller's job). Only present, non-empty sub-fields of a
 * structured type are checked. An unknown / `text` type accepts anything.
 *
 * The SDK validates the PLAINTEXT before it is encrypted, at the value-submit
 * surfaces only (never on share / propagate).
 */

import { COUNTRY_CODES, DIAL_CODES, US_STATE_CODES } from './countryData';

// Country/nationality store an ISO 3166-1 alpha-2 code; address state = USPS 2-letter code.
// The code lists come from the generated country data (do NOT inline them — they would rot).
const COUNTRY_CODE_SET = new Set(COUNTRY_CODES);
const US_STATE_CODE_SET = new Set(US_STATE_CODES);

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const URL_RE = /^https?:\/\/[^\s/$.?#][^\s]*\.[^\s]{2,}$/i;
const MIME_RE = /^[\w.+-]+\/[\w.+-]+$/;
const PHONE_RE = /^\+?\d{4,15}$/;
const CARD_RE = /^\d{12,19}$/;
const GENDER = ['Male', 'Female', 'Non-binary', 'Prefer not to say'];

type SubRule = { re?: RegExp; int?: boolean; kind?: string };

// structured types: each allowed key -> sub-rule. {} = any string; {int:true} =
// JSON integer; {re} = string matching a regex; {kind} = reuse a kind handler.
const OBJ: Record<string, Record<string, SubRule>> = {
  address: {
    postal_code: { re: /^[A-Za-z0-9][A-Za-z0-9 -]{1,9}$/ },
    country: { kind: 'countryCode' }, state: { kind: 'usState' },
    street: {}, building_number: {}, affix: {}, city: {},
  },
  creditcard: {
    number: { kind: 'card' },
    expiry: { re: /^(0[1-9]|1[0-2])\/\d{2}(\d{2})?$/ },
    cvc: { re: /^\d{3,4}$/ },
    name: {},
  },
  bank: {
    swift: { re: /^[A-Za-z]{6}[A-Za-z0-9]{2}([A-Za-z0-9]{3})?$/ },
    routing_number: { re: /^\d{9}$/ },
    account_number: { re: /^[A-Za-z0-9 ]{4,34}$/ },
    account_holder: {}, bank_name: {},
  },
  document: {
    size: { int: true }, mime_type: { re: MIME_RE }, name: {}, file: {}, original_name: {},
  },
  legal_document: {
    size: { int: true }, expiry_date: { kind: 'date' }, mime_type: { re: MIME_RE },
    document_number: {}, file: {}, original_name: {},
  },
};

type Rule =
  | { kind: 'regex'; re: RegExp }
  | { kind: 'enum'; values: string[] }
  | { kind: 'object' }
  | { kind: 'phone' | 'url' | 'date' | 'number' | 'boolean' | 'countryCode' };

const RULES: Record<string, Rule> = {
  email: { kind: 'regex', re: EMAIL_RE },
  phone: { kind: 'phone' },
  url: { kind: 'url' },
  date: { kind: 'date' }, date_of_birth: { kind: 'date' },
  gender: { kind: 'enum', values: GENDER },
  address: { kind: 'object' }, creditcard: { kind: 'object' }, bank: { kind: 'object' },
  document: { kind: 'object' }, legal_document: { kind: 'object' },
  number: { kind: 'number' }, boolean: { kind: 'boolean' },
  country: { kind: 'countryCode' }, nationality: { kind: 'countryCode' },
  // text + unknown => no rule => accept anything
};

function luhnOk(digits: string): boolean {
  let sum = 0;
  let dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

function daysInMonth(y: number, m: number): number {
  const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  return [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1];
}

function validDate(s: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const y = Number(s.slice(0, 4));
  const m = Number(s.slice(5, 7));
  const d = Number(s.slice(8, 10));
  if (m < 1 || m > 12) return false;
  if (d < 1 || d > daysInMonth(y, m)) return false;
  return true;
}

// kind handlers for the "content" checks (top-level rules AND structured sub-rules).
function applyKind(kind: string, value: string): boolean {
  switch (kind) {
    case 'phone':
      return PHONE_RE.test(value.replace(/[ \-().]/g, ''));
    case 'url': {
      const u = /^https?:\/\//i.test(value) ? value : `https://${value}`;
      return URL_RE.test(u);
    }
    case 'date':
      return validDate(value);
    case 'card': {
      const s = value.replace(/[ -]/g, '');
      return CARD_RE.test(s) && luhnOk(s);
    }
    case 'number':
      return value.trim() !== '' && Number.isFinite(Number(value));
    case 'boolean':
      return value === 'true' || value === 'false';
    case 'countryCode':
      return COUNTRY_CODE_SET.has(value);
    case 'usState':
      return US_STATE_CODE_SET.has(value);
    default:
      return true;
  }
}

function validObject(type: string, raw: string): boolean {
  let o: unknown;
  try {
    o = JSON.parse(raw);
  } catch {
    return false;
  }
  if (!o || typeof o !== 'object' || Array.isArray(o)) return false;
  const spec = OBJ[type];
  for (const k of Object.keys(o as Record<string, unknown>)) {
    const sub = spec[k];
    if (sub === undefined) return false; // unknown key
    const v = (o as Record<string, unknown>)[k];
    if (sub.int) {
      if (!Number.isInteger(v)) return false;
      continue;
    }
    if (typeof v !== 'string') return false;
    if (v === '') continue; // empty sub-field ok (partial fill)
    if (sub.re && !sub.re.test(v)) return false;
    if (sub.kind && !applyKind(sub.kind, v)) return false;
  }
  return true;
}

/** True if `value` is an acceptable plaintext for `type`. Empty value is valid. */
export function isFieldValueValid(type: string | null | undefined, value: unknown): boolean {
  const s = value == null ? '' : String(value);
  if (s === '') return true;
  const rule = RULES[type ?? ''];
  if (!rule) return true;
  switch (rule.kind) {
    case 'regex':
      return rule.re.test(s);
    case 'enum':
      return rule.values.includes(s);
    case 'object':
      return validObject(type as string, s);
    default:
      return applyKind(rule.kind, s);
  }
}

/** `null` when valid, else the `type` tag (callers map to `field_invalid_<type>`). */
export function fieldValueError(type: string | null | undefined, value: unknown): string | null {
  return isFieldValueValid(type, value) ? null : type ?? '';
}

/** True if `code` is an assigned ISO 3166-1 alpha-2 country code. */
export function isValidCountryCode(code: string | null | undefined): boolean {
  return code != null && COUNTRY_CODE_SET.has(code);
}

/** The ITU E.164 dial code (digits only, no `+`) for a country code, or `null`. */
export function dialCodeFor(code: string | null | undefined): string | null {
  return (code != null && DIAL_CODES[code]) || null;
}
