/**
 * Output model — the conclusions.
 *
 * The consumer works with these and nothing else. They are produced by factories
 * that turn a *hardened* API JSON object (slug-keyed `values`; NO person source
 * field) into typed objects, decrypting ciphertext via the injected crypto closures.
 *
 *     RequestField { slug, label, type, oneTime, mandatory }   // YOUR request config
 *     Connection   { id, personId, displayName, connectedAt, values: {<slug>: Value} }
 *     Value        { value, live, updatedAt }
 *     Change       { id, event, personId, shareCode?, slug?, value?, live?, at }   // id = stable dedup key
 *     LogEntry     { type, message, metadata, at }
 *
 * Typed values:
 *   - `email`/`phone`/`url`/`text` → string
 *   - `address`/`bank`/`creditcard`  → a parsed object (the decrypted plaintext is a
 *     JSON object string → parsed)
 *   - `date`/`date_of_birth`         → a JS `Date` (UTC midnight; falls back to the
 *     raw string if it can't be parsed)
 *   - `photo`/`document`/`legal_document` → a lazy {@link BinaryHandle}
 *     (`.bytes()` fetches the slot file endpoint, decrypts, parses the envelope,
 *     base64-decodes the `full`/`file` data URI)
 *
 * Every model carries `.raw` — the underlying (hardened) API object — for debugging
 * or an edge case the SDK didn't model. It never contains the person's source field.
 *
 * Decryption is config-driven: the factory takes a `decryptValue`
 * callable (a closure over the loaded service private key) and, for binaries, a
 * `binaryFetch` callable — never a key/secret argument.
 */

import { BinaryHandle, DecryptError, type BinaryFetch, type DecryptWrapper, type EncWrapper } from './crypto.js';

/** Field types whose decrypted plaintext is a JSON object → a parsed object. */
export const STRUCTURED_TYPES = ['address', 'bank', 'creditcard'] as const;
/** Field types whose value is a lazy binary handle (served as a value_url). */
export const BINARY_TYPES = ['photo', 'document', 'legal_document'] as const;
/** Field types whose decrypted plaintext is an ISO date. */
export const DATE_TYPES = ['date', 'date_of_birth'] as const;

/** A type resolver: slug -> the request field's type (e.g. "email", "photo"). */
export type TypeForSlug = (slug: string) => string | null | undefined;

type Json = Record<string, unknown>;

function parseIsoDate(value: unknown): Date | null {
  if (value === null || value === undefined || value === '') return null;
  const raw = String(value);
  const ms = Date.parse(raw);
  if (Number.isNaN(ms)) return null;
  return new Date(ms);
}

function coerceBool(value: unknown): boolean | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    const low = value.trim().toLowerCase();
    if (low === 'true' || low === '1') return true;
    if (low === 'false' || low === '0' || low === '') return false;
  }
  return Boolean(value);
}

function parseDateOnly(value: string): Date | null {
  const head = value.trim().slice(0, 10);
  // Strict YYYY-MM-DD; build a UTC date so there's no timezone drift.
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(head);
  if (!m) return null;
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const d = new Date(Date.UTC(year, month - 1, day));
  // Round-trip guard (rejects e.g. 1990-13-40).
  if (d.getUTCFullYear() !== year || d.getUTCMonth() !== month - 1 || d.getUTCDate() !== day) {
    return null;
  }
  return d;
}

// ── definitions ──────────────────────────────────────────────────────────────

/**
 * A request-field DEFINITION — YOUR config, never the person's.
 *
 * `mandatory` folds the API's two flags: it is true when the field is mandatory to
 * provide OR mandatory to stay connected.
 */
export class RequestField {
  constructor(
    readonly slug: string,
    readonly label: string,
    readonly type: string,
    readonly oneTime: boolean,
    readonly mandatory: boolean,
    readonly raw: Json,
  ) {}

  static fromApi(obj: Json): RequestField {
    return new RequestField(
      String(obj['slug'] ?? ''),
      obj['label'] != null ? String(obj['label']) : '',
      obj['type'] != null ? String(obj['type']) : '',
      Boolean(coerceBool(obj['one_time'])),
      Boolean(coerceBool(obj['mandatory_provide']) || coerceBool(obj['mandatory_connected'])),
      obj,
    );
  }

  /** Parse the `/request-fields` response → a list of definitions. */
  static listFromApi(body: unknown): RequestField[] {
    const items = listOf(body, 'request_fields');
    return items.map((o) => RequestField.fromApi(o));
  }
}

// ── values ───────────────────────────────────────────────────────────────────

/**
 * A single answer for one of YOUR request slots.
 *
 * `value` is the typed plaintext (string / object / Date / lazy BinaryHandle);
 * `live` = the person chose "keep connected" (auto-updates) vs a one-time snapshot;
 * `updatedAt` = when this answer last changed. Both ride on the Value (per-answer),
 * not the definition.
 */
export class Value {
  constructor(
    readonly value: unknown,
    readonly live: boolean,
    readonly updatedAt: Date | null,
    readonly raw: Json,
  ) {}

  /** Build a typed Value from one hardened `{value|value_url, live, updatedAt}` entry. */
  static fromApi(
    obj: Json,
    opts: { fieldType: string | null | undefined; decryptValue: DecryptWrapper; binaryFetch?: BinaryFetch | null },
  ): Value {
    const live = Boolean(coerceBool(obj['live']));
    const updatedAt = parseIsoDate(obj['updatedAt'] ?? obj['updated_at']);
    const typed = typedValue(obj, opts);
    return new Value(typed, live, updatedAt, obj);
  }
}

function typedValue(
  obj: Json,
  opts: { fieldType: string | null | undefined; decryptValue: DecryptWrapper; binaryFetch?: BinaryFetch | null },
): unknown {
  const ftype = (opts.fieldType ?? '').toLowerCase();

  // Binary → a lazy handle over the slot value_url (no eager fetch/decrypt).
  if ((BINARY_TYPES as readonly string[]).includes(ftype) || 'value_url' in obj) {
    const valueUrl = obj['value_url'];
    if (valueUrl === undefined || valueUrl === null) {
      // Binary type but no url (e.g. unanswered) → an empty handle.
      return new BinaryHandle({});
    }
    return new BinaryHandle({
      valueUrl: String(valueUrl),
      fetch: opts.binaryFetch ?? null,
      decrypt: opts.decryptValue,
    });
  }

  // Non-binary → decrypt the ciphertext wrapper to plaintext.
  const ciphertext = obj['value'];
  if (ciphertext === undefined || ciphertext === null) {
    return null;
  }
  const plaintext = opts.decryptValue(ciphertext as EncWrapper | string);

  if ((STRUCTURED_TYPES as readonly string[]).includes(ftype)) {
    try {
      return JSON.parse(plaintext);
    } catch {
      throw new DecryptError(`structured value for type '${ftype}' is not valid JSON`);
    }
  }

  if ((DATE_TYPES as readonly string[]).includes(ftype)) {
    const d = parseDateOnly(plaintext);
    return d !== null ? d : plaintext;
  }

  // text/email/phone/url and anything unknown → the plaintext string.
  return plaintext;
}

// ── connection ─────────────────────────────────────────────────────────────

/**
 * A connected person — identity + the slug-keyed value map.
 *
 * NO source field anywhere: `values` is keyed by YOUR request slug.
 */
export class Connection {
  constructor(
    readonly id: string,
    readonly personId: string,
    readonly displayName: string | null,
    readonly connectedAt: Date | null,
    readonly values: Record<string, Value>,
    readonly raw: Json,
  ) {}

  /**
   * Build a Connection from a hardened `connectionDetail` (or list) object.
   *
   * `connectionDetail` returns `{connection_id, user_id, values}` and no
   * displayName/connectedAt, so those can be supplied via `identity` (the matching
   * row from the list endpoint, which carries them).
   */
  static fromApi(
    obj: Json,
    opts: {
      typeForSlug: TypeForSlug;
      decryptValue: DecryptWrapper;
      binaryFetch?: BinaryFetch | null;
      identity?: Json;
    },
  ): Connection {
    const identity = opts.identity ?? {};
    const connId = String(
      obj['connection_id'] ?? obj['id'] ?? identity['connection_id'] ?? '',
    );
    const personId = String(
      obj['user_id'] ?? obj['person_id'] ?? obj['person_user_id'] ?? identity['user_id'] ?? '',
    );
    const displayNameRaw = obj['display_name'] ?? identity['display_name'];
    const displayName = displayNameRaw != null ? String(displayNameRaw) : null;
    const connectedAt = parseIsoDate(obj['connected_at'] ?? identity['connected_at']);

    const values: Record<string, Value> = {};
    const valuesObj = obj['values'];
    if (valuesObj !== null && typeof valuesObj === 'object' && !Array.isArray(valuesObj)) {
      for (const [slug, entry] of Object.entries(valuesObj as Record<string, unknown>)) {
        if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) continue;
        values[slug] = Value.fromApi(entry as Json, {
          fieldType: opts.typeForSlug(slug),
          decryptValue: opts.decryptValue,
          binaryFetch: opts.binaryFetch,
        });
      }
    }

    return new Connection(connId, personId, displayName, connectedAt, values, obj);
  }
}

// ── change ───────────────────────────────────────────────────────────────────

/**
 * A change feed / webhook event.
 *
 * `id` is the stable server change-row id (the pump dedupes on it after a
 * crash/replay); `at` is the change time (there is NO separate
 * `updatedAt` on a change). `slug`/`value`/`live` are present only on
 * `field_updated` (connection/consent events carry no slot/value).
 */
export class Change {
  constructor(
    readonly id: string,
    readonly event: string,
    readonly personId: string | null,
    /** The person's profile share code (present on every event; may be null). */
    readonly shareCode: string | null,
    readonly slug: string | null,
    readonly value: unknown,
    readonly live: boolean | null,
    readonly at: Date | null,
    readonly raw: Json,
  ) {}

  /** Build a Change from one hardened changes-feed / webhook event object. */
  static fromApi(
    obj: Json,
    opts: { typeForSlug: TypeForSlug; decryptValue: DecryptWrapper; binaryFetch?: BinaryFetch | null },
  ): Change {
    const slug = obj['slug'] != null ? String(obj['slug']) : null;
    const event = obj['event'] != null ? String(obj['event']) : '';
    const live = 'live' in obj ? coerceBool(obj['live']) : null;

    let value: unknown = null;
    if (event === 'field_updated' && slug !== null) {
      // Reuse the Value typing path so feed + connection produce identical typed
      // values (incl. the same lazy BinaryHandle for binaries).
      if ('value' in obj || 'value_url' in obj) {
        value = typedValue(obj, {
          fieldType: opts.typeForSlug(slug),
          decryptValue: opts.decryptValue,
          binaryFetch: opts.binaryFetch,
        });
      }
    }

    const personIdRaw = obj['person_user_id'] ?? obj['person_id'];
    const shareCodeRaw = obj['share_code'];
    return new Change(
      String(obj['id'] ?? ''),
      event,
      personIdRaw != null ? String(personIdRaw) : null,
      shareCodeRaw != null ? String(shareCodeRaw) : null,
      slug,
      value,
      live,
      parseIsoDate(obj['at']),
      obj,
    );
  }

  /** Parse the `/changes` response → a list of typed Change events. */
  static listFromApi(
    body: unknown,
    opts: { typeForSlug: TypeForSlug; decryptValue: DecryptWrapper; binaryFetch?: BinaryFetch | null },
  ): Change[] {
    const items = listOf(body, 'changes');
    return items.map((o) => Change.fromApi(o, opts));
  }
}

// ── log ────────────────────────────────────────────────────────────────────

/** A service activity-log entry — ops events only, never person data. */
export class LogEntry {
  constructor(
    readonly type: string,
    readonly message: string | null,
    readonly metadata: unknown,
    readonly at: Date | null,
    readonly raw: Json,
  ) {}

  static fromApi(obj: Json): LogEntry {
    return new LogEntry(
      obj['type'] != null ? String(obj['type']) : '',
      obj['message'] != null ? String(obj['message']) : null,
      obj['metadata'] ?? null,
      parseIsoDate(obj['at'] ?? obj['created_at']),
      obj,
    );
  }

  /** Parse the `/logs` response → a list of log entries. */
  static listFromApi(body: unknown): LogEntry[] {
    const items = listOf(body, 'items');
    return items.map((o) => LogEntry.fromApi(o));
  }
}

// ── shared list extraction ───────────────────────────────────────────────────

/**
 * Pull the named array out of a `{<key>: [...]}` response, or accept a bare array.
 * Mirrors the Python `body.get(key, []) if dict else (body or [])`.
 */
function listOf(body: unknown, key: string): Json[] {
  let items: unknown;
  if (body !== null && typeof body === 'object' && !Array.isArray(body)) {
    items = (body as Record<string, unknown>)[key] ?? [];
  } else {
    items = body ?? [];
  }
  if (!Array.isArray(items)) return [];
  return items.filter((o): o is Json => o !== null && typeof o === 'object' && !Array.isArray(o));
}
