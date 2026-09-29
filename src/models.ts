/**
 * Output model — the conclusions.
 *
 * The consumer works with these and nothing else. They are produced by factories
 * that turn a *hardened* API JSON object (slug-keyed `values`; NO person source
 * field) into typed objects, decrypting ciphertext via the injected crypto closures.
 *
 *     RequestField { slug, label, type, oneTime, mandatory, verified, verifiedMaxAgeDays, plugin }
 *     Connection   { id, personId, displayName, connectedAt, values: {<slug>: Value} }
 *     Value        { value, live, updatedAt, verified, verifiedAt, verifiedExpiresAt,
 *                    verifiedMethod, verifiedProvider, verificationId }
 *     Change       { id, event, personId, shareCode?, slug?, value?, live?, at }   // id = stable dedup key
 *     LogEntry     { type, message, metadata, at }
 *
 * A value's shape follows the RESOLVED DEFINITION of its field type
 * ({@link FieldTypeRegistry}), never a list of type names:
 *   - storage lane `photo`/`document` → a lazy {@link BinaryHandle} (`.bytes()` fetches
 *     the slot file endpoint, decrypts, parses the envelope, base64-decodes the
 *     `full`/`file` data URI)
 *   - primitive `composite` → a parsed object (the decrypted plaintext is a JSON object
 *     string → parsed)
 *   - primitive `date` → a JS `Date` (UTC midnight; falls back to the raw string if it
 *     can't be parsed)
 *   - primitive `multilist` → a parsed array
 *   - everything else → the plaintext string, whose grammar the registry's `validate()`
 *     states
 *   - the reserved type key `plugin` is typed first, before the registry: a {@link PluginValue}
 *
 * Every model carries `.raw` — the underlying (hardened) API object — for debugging
 * or an edge case the SDK didn't model. It never contains the person's source field.
 *
 * Decryption is config-driven: the factory takes a `decryptValue`
 * callable (a closure over the loaded service private key) and, for binaries, a
 * `binaryFetch` callable — never a key/secret argument.
 */

import { BinaryHandle, DecryptError, type BinaryFetch, type DecryptWrapper, type EncWrapper, hashMatches } from './crypto.js';
import { ValidationError } from './errors.js';
import { FieldTypeRegistry } from './fieldTypes.js';

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

/**
 * Whether a verification expiry stamp has already passed.
 *
 * Absent → `false`: a verification with no expiry never lapses. Present but unparseable →
 * `true`: an expiry that cannot be evaluated cannot be used to claim the value is still
 * verified today.
 */
export function expiryPassed(value: unknown): boolean {
  if (value === null || value === undefined || value === '') return false;
  const ms = Date.parse(String(value));
  if (Number.isNaN(ms)) return true;
  return ms <= Date.now();
}

/** Coerce a JSON number or an XML numeric string into an integer, or null. */
function coerceInt(value: unknown): number | null {
  if (value === null || value === undefined || value === '') return null;
  const n = Number(String(value).trim());
  return Number.isFinite(n) ? Math.trunc(n) : null;
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

/**
 * Coerce the one schema-defined boolean inside a signature map entry. The
 * entries stay untyped (matching every existing signature field), but
 * signerNameVerified is a boolean in the schema — XML carries it as the
 * string "false"/"true", and a caller testing that raw string for truthiness
 * reads a false verification as verified. Coerce it the same way every other
 * boolean field on this transport is coerced.
 */
function normalizeSignatures(signatures: unknown): Json[] {
  if (!Array.isArray(signatures)) return [];
  return signatures.map((entry) => {
    if (entry !== null && typeof entry === 'object' && !Array.isArray(entry) && 'signer_name_verified' in (entry as Record<string, unknown>)) {
      return { ...(entry as Record<string, unknown>), signer_name_verified: coerceBool((entry as Record<string, unknown>)['signer_name_verified']) } as Json;
    }
    return entry as Json;
  });
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
    /** Which customer TYPE this row applies to: "person" | "company" | "both" (B2B); null on older API. */
    readonly audience: string | null,
    /**
     * This row DEMANDS a verified answer: only a value the person verified satisfies it, and an
     * unverified candidate is refused at the accepting act rather than downgraded.
     */
    readonly verified: boolean,
    /**
     * The oldest verification the demand accepts, in days; null = no age limit. Enforced at the
     * accepting act only — a standing live link is not re-enforced afterwards, so apply your own
     * policy from each {@link Value.verifiedAt}.
     */
    readonly verifiedMaxAgeDays: number | null,
    readonly raw: Json,
    /**
     * The plugin behind a plugin row (`type === 'plugin'`): `{pluginName, fieldType, snapshot}`,
     * where `snapshot` is the field type's frozen description (blocks, inputs, outputs). Null on
     * every other row, and on an API that does not send it.
     */
    readonly plugin: RequestFieldPlugin | null = null,
  ) {}

  static fromApi(obj: Json): RequestField {
    return new RequestField(
      String(obj['slug'] ?? ''),
      obj['label'] != null ? String(obj['label']) : '',
      obj['type'] != null ? String(obj['type']) : '',
      Boolean(coerceBool(obj['one_time'])),
      Boolean(coerceBool(obj['mandatory_provide']) || coerceBool(obj['mandatory_connected'])),
      obj['audience'] != null ? String(obj['audience']) : null,
      Boolean(coerceBool(obj['verified'])),
      coerceInt(obj['verified_max_age_days']),
      obj,
      RequestFieldPlugin.fromApi(obj['plugin']),
    );
  }

  /** Parse the `/request-fields` response → a list of definitions. */
  static listFromApi(body: unknown): RequestField[] {
    const items = listOf(body, 'request_fields');
    return items.map((o) => RequestField.fromApi(o));
  }
}

/** The plugin a plugin request row or flow row asks through. */
export class RequestFieldPlugin {
  constructor(
    readonly pluginName: string | null,
    readonly fieldType: string | null,
    /** The field type's frozen description: `{plugin_name, host, label, blocks, inputs, outputs}`. */
    readonly snapshot: Json | null,
    readonly raw: Json,
  ) {}

  /** Parse-permissive: anything but an object is "no plugin". */
  static fromApi(value: unknown): RequestFieldPlugin | null {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
    const o = value as Json;
    const snapshot = o['snapshot'];
    return new RequestFieldPlugin(
      o['plugin_name'] != null ? String(o['plugin_name']) : null,
      o['field_type'] != null ? String(o['field_type']) : null,
      snapshot !== null && typeof snapshot === 'object' && !Array.isArray(snapshot) ? (snapshot as Json) : null,
      o,
    );
  }
}

// ── plugin values ────────────────────────────────────────────────────────────

/** One block of a plugin answer: a pick (`id` + its option label as `value`) or a typed value. */
export interface PluginBlock {
  key: string | null;
  kind: string | null;
  label: string | null;
  /** The picked option's id on a `search_select` block; null on a typed block. */
  id: string | null;
  value: unknown;
}

/** One output of a plugin answer, typed as the plugin declared it. */
export interface PluginOutput {
  key: string | null;
  type: string | null;
  label: string | null;
  value: unknown;
}

/**
 * A plugin answer — the value of a row whose type key is `plugin`, and of a plugin claim.
 *
 * The answer describes itself: the plugin's name, the field type, the blocks in declared order
 * (labels, picked ids and option labels, typed values) and the outputs, so reading it never needs
 * the plugin. It is what the answering client submitted — sealed but not signed; a company that
 * must rely on an output checks it with the plugin itself.
 */
export class PluginValue {
  constructor(
    readonly plugin: string | null,
    readonly type: string | null,
    readonly blocks: PluginBlock[],
    readonly outputs: PluginOutput[],
    readonly raw: Json,
  ) {}

  /**
   * Parse a plugin answer's plaintext.
   *
   * @throws ValidationError when the plaintext is not a JSON object with an `outputs` array.
   */
  static parse(plaintext: string): PluginValue {
    let parsed: unknown;
    try {
      parsed = JSON.parse(plaintext);
    } catch {
      parsed = null;
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new ValidationError(null, 'plugin');
    }
    const o = parsed as Json;
    if (!Array.isArray(o['outputs'])) throw new ValidationError(null, 'plugin');
    const text = (v: unknown): string | null => (v === undefined || v === null ? null : String(v));
    const objects = (v: unknown): Json[] =>
      Array.isArray(v) ? (v.filter((x) => x !== null && typeof x === 'object' && !Array.isArray(x)) as Json[]) : [];
    return new PluginValue(
      text(o['plugin']),
      text(o['type']),
      objects(o['blocks']).map((b) => ({
        key: text(b['key']),
        kind: text(b['kind']),
        label: text(b['label']),
        id: text(b['id']),
        value: b['value'] === undefined ? null : b['value'],
      })),
      objects(o['outputs']).map((out) => ({
        key: text(out['key']),
        type: text(out['type']),
        label: text(out['label']),
        value: out['value'] === undefined ? null : out['value'],
      })),
      o,
    );
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
/**
 * Recompute the verified flag from the just-decrypted plaintext (text values only).
 *
 * Two conditions, both required: the hash recomputes over the exact plaintext, AND the
 * verification has not lapsed (`verified_expires_at` absent or still in the future). A
 * document-backed verification lapses when the document itself expires, so a stale binding reads
 * false here without any lookup.
 */
function verifiedFrom(obj: Json, plaintext: unknown): boolean {
  if (typeof plaintext !== 'string') return false;
  const vhash = obj['verified_hash'];
  const vsalt = obj['verified_salt'];
  if (typeof vhash !== 'string' || typeof vsalt !== 'string' || !vhash || !vsalt) return false;
  if (expiryPassed(obj['verified_expires_at'])) return false;
  return hashMatches(vsalt, vhash, plaintext);
}

export class Value {
  constructor(
    readonly value: unknown,
    readonly live: boolean,
    readonly updatedAt: Date | null,
    /** True iff the hash recomputes over the plaintext AND the verification has not lapsed. */
    readonly verified: boolean,
    /**
     * When the person's answering field was verified; null when the value carries no verification.
     * It is a stamp, not a promise about today — read it with {@link verified}.
     */
    readonly verifiedAt: Date | null,
    /**
     * When that verification lapses (a document-backed verification dies with the document);
     * null = it does not lapse. Past → {@link verified} reads false.
     */
    readonly verifiedExpiresAt: Date | null,
    /**
     * HOW allme bound this value: `email_code` | `sms_code` | `sumsub_id` | `sumsub_address`.
     * Null when the value was bound before the proof log existed — the three proof fields
     * arrive together or not at all. Readable whatever {@link verified} says; that boolean
     * stays the only trust decision.
     */
    readonly verifiedMethod: string | null,
    /** WHO established the proof: `allme` | `sumsub`. Same all-or-none set. */
    readonly verifiedProvider: string | null,
    /** The id to quote back to allme in a dispute. Same all-or-none set. */
    readonly verificationId: string | null,
    readonly raw: Json,
  ) {}

  /** Build a typed Value from one hardened `{value|value_url, live, updatedAt}` entry. */
  static fromApi(
    obj: Json,
    opts: {
      fieldType: string | null | undefined;
      fieldTypes: FieldTypeRegistry;
      decryptValue: DecryptWrapper;
      binaryFetch?: BinaryFetch | null;
    },
  ): Value {
    const live = Boolean(coerceBool(obj['live']));
    const updatedAt = parseIsoDate(obj['updatedAt'] ?? obj['updated_at']);
    const typed = typedValue(obj, opts);
    return new Value(
      typed,
      live,
      updatedAt,
      verifiedFrom(obj, typed),
      parseIsoDate(obj['verified_at']),
      parseIsoDate(obj['verified_expires_at']),
      obj['verified_method'] != null ? String(obj['verified_method']) : null,
      obj['verified_provider'] != null ? String(obj['verified_provider']) : null,
      obj['verification_id'] != null ? String(obj['verification_id']) : null,
      obj,
    );
  }
}

function typedValue(
  obj: Json,
  opts: {
    fieldType: string | null | undefined;
    fieldTypes: FieldTypeRegistry;
    decryptValue: DecryptWrapper;
    binaryFetch?: BinaryFetch | null;
  },
): unknown {
  const ftype = (opts.fieldType ?? '').toLowerCase();

  // The type key `plugin` is reserved and never a registry row: a plugin answer is a
  // self-describing JSON object, typed here before the registry is consulted.
  if (ftype === 'plugin') {
    const cipher = obj['value'];
    if (cipher === undefined || cipher === null) return null;
    return PluginValue.parse(opts.decryptValue(cipher as EncWrapper | string));
  }

  const definition = opts.fieldTypes.resolve(ftype);

  // Binary → a lazy handle over the slot value_url (no eager fetch/decrypt).
  if (opts.fieldTypes.isBinary(ftype) || 'value_url' in obj) {
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

  if (definition.input === 'composite' || definition.input === 'multilist') {
    try {
      return JSON.parse(plaintext);
    } catch {
      throw new DecryptError(`structured value for type '${ftype}' is not valid JSON`);
    }
  }

  if (definition.input === 'date') {
    const d = parseDateOnly(plaintext);
    return d !== null ? d : plaintext;
  }

  // Every other primitive, and a type the registry does not carry, is the plaintext string.
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
    /** The connected customer's TYPE: "person" | "company" (B2B); null on older API. */
    readonly customerType: string | null,
    /** The customer's profile share code (previously only via `raw`); null when absent. */
    readonly shareCode: string | null,
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
      fieldTypes: FieldTypeRegistry;
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
          fieldTypes: opts.fieldTypes,
          decryptValue: opts.decryptValue,
          binaryFetch: opts.binaryFetch,
        });
      }
    }

    const customerTypeRaw = obj['customer_type'] ?? identity['customer_type'];
    const shareCodeRaw = obj['share_code'] ?? identity['share_code'];
    return new Connection(
      connId,
      personId,
      displayName,
      connectedAt,
      values,
      customerTypeRaw != null ? String(customerTypeRaw) : null,
      shareCodeRaw != null ? String(shareCodeRaw) : null,
      obj,
    );
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
    /** Set on `document_status_changed` — the affected document's id. */
    readonly documentId: string | null,
    /** Set on `document_status_changed` — the document's new lifecycle status. */
    readonly status: string | null,
    /** Set on `document_status_changed` for a contract — signed | accepted | cancelled (else null). */
    readonly action: string | null,
    /** Set on `document_status_changed` — the person's optional cancellation note (else null). */
    readonly note: string | null,
    /** Set on a signature — sign method: biometric | twofa | email | custodian (else null). */
    readonly method: string | null,
    /** Set on a signature — SHA-256 of the signed content (else null). */
    readonly contentSha256: string | null,
    /** Set on a signature — ISO timestamp the signature was recorded (else null). */
    readonly signedAt: string | null,
    /** Set on a cancelled `document_status_changed` — ISO date the cancellation takes effect (else null). */
    readonly cancelEffectiveDate: string | null,
    /** Set on `document_status_changed` — when the platform seal was applied (else null until sealed). */
    readonly sealedAt: string | null,
    /** Set on `document_status_changed` — SHA-256 of the document's unencrypted PDF bytes (else null on a JSON contract). */
    readonly plainSha256: string | null,
    /** Set on `document_status_changed` — the signature's own signer evidence (else null). */
    readonly signerFirstName: string | null,
    readonly signerLastName: string | null,
    /** True iff the submitted name matched the signer's verified ID name; null when unset. */
    readonly signerNameVerified: boolean | null,
    /** Set on `connection_request_accepted` / `connection_request_rejected` — the request_id (else null). */
    readonly requestId: string | null,
    /** The customer's TYPE: "person" | "company" (B2B); null on older API. */
    readonly customerType: string | null,
    /** Set on `key_rotated` — SHA-256 fingerprint of the person's NEW public key (else null). */
    readonly publicKeySha256: string | null,
    /** Set on `message_received` — the connection to reply / acknowledge on (else null). */
    readonly connectionId: string | null,
    /** Set on `message_received` — the ack boundary (`upToMessageId`) (else null). */
    readonly messageId: string | null,
    /** Set on `message_received` — base64 SPKI to encrypt the reply to (else null). */
    readonly personPublicKey: string | null,
    /** Set on `message_received` — the DECRYPTED message text (else null). */
    readonly messageBody: string | null,
    /** True iff a field_updated value's hash matches AND the verification has not lapsed. */
    readonly verified: boolean,
    /** When the answering field was verified; null when the value carries no verification. */
    readonly verifiedAt: Date | null,
    /** When that verification lapses; null = it does not. Past → {@link verified} reads false. */
    readonly verifiedExpiresAt: Date | null,
    /**
     * HOW allme bound this value: `email_code` | `sms_code` | `sumsub_id` | `sumsub_address`.
     * Null when the value was bound before the proof log existed — the three proof fields
     * arrive together or not at all. Readable whatever {@link verified} says; that boolean
     * stays the only trust decision.
     */
    readonly verifiedMethod: string | null,
    /** WHO established the proof: `allme` | `sumsub`. Same all-or-none set. */
    readonly verifiedProvider: string | null,
    /** The id to quote back to allme in a dispute. Same all-or-none set. */
    readonly verificationId: string | null,
    readonly at: Date | null,
    readonly raw: Json,
  ) {}

  /** Build a Change from one hardened changes-feed / webhook event object. */
  static fromApi(
    obj: Json,
    opts: {
      typeForSlug: TypeForSlug;
      fieldTypes: FieldTypeRegistry;
      decryptValue: DecryptWrapper;
      binaryFetch?: BinaryFetch | null;
    },
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
          fieldTypes: opts.fieldTypes,
          decryptValue: opts.decryptValue,
          binaryFetch: opts.binaryFetch,
        });
      }
    }

    const isMessage = event === 'message_received';
    let messageBody: string | null = null;
    if (isMessage) {
      // The message ciphertext is carried under `body`, never `value`: on every other
      // event `value` means field ciphertext, which a message body is not. It is
      // encrypted for the SERVICE key, so the ordinary decrypt opens it.
      const cipher = obj['body'];
      if (cipher !== undefined && cipher !== null) {
        messageBody = opts.decryptValue(cipher as EncWrapper | string);
      }
    }

    const personIdRaw = obj['person_user_id'] ?? obj['person_id'];
    const shareCodeRaw = obj['share_code'];
    const documentIdRaw = obj['document_id'];
    // `2fa_challenge_completed` carries the outcome in `status` (approved | denied | revoked);
    // its `challenge_id` and `completed_at` stay available on `raw`. The poll is the record (spec §3).
    const statusRaw =
      event === 'document_status_changed' || event === '2fa_challenge_completed' ? obj['status'] : null;
    const actionRaw = event === 'document_status_changed' ? obj['action'] : null;
    const noteRaw = event === 'document_status_changed' ? obj['note'] : null;
    const methodRaw = event === 'document_status_changed' ? obj['method'] : null;
    const contentSha256Raw = event === 'document_status_changed' ? obj['content_sha256'] : null;
    const signedAtRaw = event === 'document_status_changed' ? obj['signed_at'] : null;
    const cancelEffectiveDateRaw = event === 'document_status_changed' ? obj['cancel_effective_date'] : null;
    const sealedAtRaw = event === 'document_status_changed' ? obj['sealed_at'] : null;
    const plainSha256Raw = event === 'document_status_changed' ? obj['plain_sha256'] : null;
    const signerFirstNameRaw = event === 'document_status_changed' ? obj['signer_first_name'] : null;
    const signerLastNameRaw = event === 'document_status_changed' ? obj['signer_last_name'] : null;
    const signerNameVerifiedRaw = event === 'document_status_changed' ? obj['signer_name_verified'] : null;
    const requestIdRaw =
      event === 'connection_request_accepted' || event === 'connection_request_rejected'
        ? obj['request_id']
        : null;
    return new Change(
      String(obj['id'] ?? ''),
      event,
      personIdRaw != null ? String(personIdRaw) : null,
      shareCodeRaw != null ? String(shareCodeRaw) : null,
      slug,
      value,
      live,
      documentIdRaw != null ? String(documentIdRaw) : null,
      statusRaw != null ? String(statusRaw) : null,
      actionRaw != null ? String(actionRaw) : null,
      noteRaw != null ? String(noteRaw) : null,
      methodRaw != null ? String(methodRaw) : null,
      contentSha256Raw != null ? String(contentSha256Raw) : null,
      signedAtRaw != null ? String(signedAtRaw) : null,
      cancelEffectiveDateRaw != null ? String(cancelEffectiveDateRaw) : null,
      sealedAtRaw != null ? String(sealedAtRaw) : null,
      plainSha256Raw != null ? String(plainSha256Raw) : null,
      signerFirstNameRaw != null ? String(signerFirstNameRaw) : null,
      signerLastNameRaw != null ? String(signerLastNameRaw) : null,
      signerNameVerifiedRaw != null ? coerceBool(signerNameVerifiedRaw) : null,
      requestIdRaw != null ? String(requestIdRaw) : null,
      obj['customer_type'] != null ? String(obj['customer_type']) : null,
      event === 'key_rotated' && obj['public_key_sha256'] != null
        ? String(obj['public_key_sha256'])
        : null,
      isMessage && obj['connection_id'] != null ? String(obj['connection_id']) : null,
      isMessage && obj['message_id'] != null ? String(obj['message_id']) : null,
      isMessage && obj['person_public_key'] != null ? String(obj['person_public_key']) : null,
      messageBody,
      verifiedFrom(obj, value),
      parseIsoDate(obj['verified_at']),
      parseIsoDate(obj['verified_expires_at']),
      obj['verified_method'] != null ? String(obj['verified_method']) : null,
      obj['verified_provider'] != null ? String(obj['verified_provider']) : null,
      obj['verification_id'] != null ? String(obj['verification_id']) : null,
      parseIsoDate(obj['at']),
      obj,
    );
  }

  /** Parse the `/changes` response → a list of typed Change events. */
  static listFromApi(
    body: unknown,
    opts: {
      typeForSlug: TypeForSlug;
      fieldTypes: FieldTypeRegistry;
      decryptValue: DecryptWrapper;
      binaryFetch?: BinaryFetch | null;
    },
  ): Change[] {
    const items = listOf(body, 'changes');
    return items.map((o) => Change.fromApi(o, opts));
  }
}

// ── document ─────────────────────────────────────────────────────────────────

/**
 * A company document the SDK created/queried (company-data side).
 *
 * value semantics mirror the connection-payload contract — keyed on
 * BROADCAST(plaintext) vs PER-PERSON(always encrypted), NOT on is_private:
 *   broadcast file   -> {file, original_name, mime_type, size}   (plaintext)
 *   per-person file  -> {"_enc_file": "enc_…json"}   (ciphertext blob, ANY is_private)
 *   broadcast json   -> the JSON object   (plaintext)
 *   per-person json  -> {"_enc":1,k,iv,d}   (ciphertext wrapper, ANY is_private;
 *                                            decrypt on demand via .json())
 * is_private is device-display-only (lock vs decrypt-on-load), not the value shape.
 */
export class Document {
  constructor(
    readonly id: string,
    readonly kind: string,
    readonly name: string,
    readonly description: string | null,
    readonly status: string,
    /** 'file' | 'json'. */
    readonly payloadKind: string,
    readonly isPrivate: boolean,
    readonly value: unknown,
    readonly metadata: Json | null,
    readonly createdAt: Date | null,
    readonly updatedAt: Date | null,
    /** Contract: the person must sign. */
    readonly requiresSignature: boolean,
    /** Contract: the person must accept. */
    readonly requiresAcceptance: boolean,
    /** SHA-256 of the unencrypted PDF bytes, lowercase hex. Null on a JSON contract. */
    readonly plainSha256: string | null,
    /** When the platform seal was applied. Null until sealed. */
    readonly sealedAt: Date | null,
    /**
     * Contract sign/accept audit trail (company-side reads only), one entry per signature:
     * action, method, content_sha256, plain_sha256, signer_first_name, signer_last_name,
     * signer_name_verified, ip, user_agent, created_at.
     */
    readonly signatures: Json[],
    /**
     * Present only on a contract-flow run-participant document: the WHOLE run's signing line,
     * one entry per (output document, participant) in line order — each
     * `{output_key, name, party_key, document_id, position, status, action, acted_at}`. Every
     * document of the run carries the same summary. Null on any other document.
     */
    readonly runSignatures: Json[] | null,
    private readonly decryptValue: DecryptWrapper | null,
    readonly raw: Json,
  ) {}

  /**
   * For a json document, return the plaintext object.
   *
   * Decryption is keyed on the value shape (per-person → encrypted wrapper), NOT on
   * is_private: a per-person json doc (ANY is_private) is an {"_enc":1,…} wrapper and
   * is decrypted with the SDK's own private key; a broadcast json doc is already
   * plaintext and returned as-is.
   */
  json(): unknown {
    if (this.payloadKind !== 'json') {
      throw new DecryptError("json() is only valid for payloadKind='json' documents");
    }
    if (
      this.value !== null &&
      typeof this.value === 'object' &&
      !Array.isArray(this.value) &&
      (this.value as Record<string, unknown>)['_enc'] === 1
    ) {
      if (this.decryptValue === null) {
        throw new DecryptError('no decrypt wiring for an encrypted (per-person) document');
      }
      return JSON.parse(this.decryptValue(this.value as EncWrapper));
    }
    return this.value;
  }

  static fromApi(obj: Json, opts: { decryptValue?: DecryptWrapper | null } = {}): Document {
    const metadata = obj['metadata'];
    return new Document(
      String(obj['id'] ?? ''),
      obj['kind'] != null ? String(obj['kind']) : '',
      obj['name'] != null ? String(obj['name']) : '',
      obj['description'] != null ? String(obj['description']) : null,
      obj['status'] != null ? String(obj['status']) : '',
      obj['payload_kind'] != null ? String(obj['payload_kind']) : '',
      Boolean(coerceBool(obj['is_private'])),
      obj['value'] ?? null,
      metadata !== null && typeof metadata === 'object' && !Array.isArray(metadata) ? (metadata as Json) : null,
      parseIsoDate(obj['created_at']),
      parseIsoDate(obj['updated_at']),
      Boolean(coerceBool(obj['requires_signature'])),
      Boolean(coerceBool(obj['requires_acceptance'])),
      obj['plain_sha256'] != null ? String(obj['plain_sha256']) : null,
      parseIsoDate(obj['sealed_at']),
      normalizeSignatures(obj['signatures']),
      Array.isArray(obj['run_signatures']) ? (obj['run_signatures'] as Json[]) : null,
      opts.decryptValue ?? null,
      obj,
    );
  }

  /** Parse a `{total, items}` list response → a list of documents. */
  static listFromApi(body: unknown, opts: { decryptValue?: DecryptWrapper | null } = {}): Document[] {
    const items = listOf(body, 'items');
    return items.map((o) => Document.fromApi(o, opts));
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

// ── flow run ─────────────────────────────────────────────────────────────────

/**
 * A contract-flow run (company-data side).
 *
 * The company is one of the two bound parties. `bindings` maps each party key to
 * the bound `user_id` (the company's own is `companyUserId`); `answers` are the
 * per-party encrypted answer copies (the company reads the rows whose
 * `for_user_id === companyUserId`, decryptable with the service private key);
 * `definition` is the pinned flow-version graph (`nodes`, `edges`, `parties`,
 * `output_mode`).
 */

/**
 * One of a participant's own documents on a run — one per output document the leaf produced for
 * that participant. `position` is the step's 1-based place in the run's ONE signing line; null
 * for a party the output's signer list does not name (its copy is `active` from the start, owing
 * nothing).
 */
export class FlowRunParticipantDocument {
  constructor(
    readonly outputKey: string | null,
    readonly name: string | null,
    readonly documentId: string | null,
    readonly documentStatus: string | null,
    readonly requiresSignature: boolean,
    readonly requiresAcceptance: boolean,
    readonly position: number | null,
    /** 'signed' | 'accepted' | null — null until this document has been acted on. */
    readonly action: string | null,
    readonly actedAt: string | null,
  ) {}

  static fromApi(o: Json): FlowRunParticipantDocument {
    return new FlowRunParticipantDocument(
      o['output_key'] != null ? String(o['output_key']) : null,
      o['name'] != null ? String(o['name']) : null,
      o['document_id'] != null ? String(o['document_id']) : null,
      o['document_status'] != null ? String(o['document_status']) : null,
      Boolean(coerceBool(o['requires_signature'])),
      Boolean(coerceBool(o['requires_acceptance'])),
      o['position'] != null ? Number(o['position']) : null,
      o['action'] != null ? String(o['action']) : null,
      o['acted_at'] != null ? String(o['acted_at']) : null,
    );
  }
}

/**
 * One participant's row on a run's `participants[]` — the durable participant set. `documents`
 * holds the participant's own copy of every output document the run produced, ordered by
 * signing-line position (unlisted last); empty before generation. One account may hold TWO of
 * these (two owner parties, or one customer bound to two party keys) — never collapse this to a
 * single row by user id.
 */
export class FlowRunParticipant {
  constructor(
    readonly partyKey: string | null,
    readonly personUserId: string | null,
    readonly connectionId: string | null,
    readonly documents: FlowRunParticipantDocument[],
  ) {}

  static fromApi(o: Json): FlowRunParticipant {
    const docsRaw = o['documents'];
    return new FlowRunParticipant(
      o['party_key'] != null ? String(o['party_key']) : null,
      o['person_user_id'] != null ? String(o['person_user_id']) : null,
      o['connection_id'] != null ? String(o['connection_id']) : null,
      Array.isArray(docsRaw)
        ? docsRaw
            .filter((d): d is Json => d !== null && typeof d === 'object' && !Array.isArray(d))
            .map((d) => FlowRunParticipantDocument.fromApi(d))
        : [],
    );
  }
}

export class FlowRun {
  constructor(
    readonly id: string,
    readonly flowId: string | null,
    readonly flowVersion: unknown,
    readonly serviceId: string | null,
    readonly connectionId: string | null,
    readonly companyUserId: string | null,
    readonly bindings: Record<string, string>,
    readonly status: string | null,
    readonly currentNode: string | null,
    readonly outputMode: string | null,
    readonly definition: Json,
    readonly answers: Json[],
    /** Immutable run "today" (raw `YYYY-MM-DD` string), or null when absent. */
    readonly referenceDate: string | null,
    readonly createdAt: Date | null,
    readonly updatedAt: Date | null,
    /**
     * Every bound party, including the owning company.
     * The top-level connection id is the customer caller's own connection on customer reads;
     * service-owner reads carry the primary counterparty's connection.
     */
    readonly participants: FlowRunParticipant[],
    readonly raw: Json,
    /**
     * The slugs whose answers came from a private source (a party's private field, a plugin called
     * with a private input, a default filled from one). Metadata, never a value. Null when the API
     * did not send the list — unknown, which the SDK treats as private for every other party.
     */
    readonly privateSlugs: string[] | null = null,
  ) {}

  /** The party key the company is bound to (`bindings[key] === companyUserId`). */
  get companyPartyKey(): string | null {
    for (const [key, uid] of Object.entries(this.bindings)) {
      if (uid === this.companyUserId) return key;
    }
    return null;
  }

  /** The company's bound user_id — its answer copies use this `for_user_id`. */
  get serviceUserId(): string | null {
    return this.companyUserId;
  }

  static fromApi(obj: Json): FlowRun {
    const o = obj ?? {};
    let definition: Json;
    const rawDef = o['definition'];
    if (rawDef !== null && typeof rawDef === 'object' && !Array.isArray(rawDef)) {
      definition = rawDef as Json;
    } else {
      definition = {
        nodes: o['nodes'] ?? [],
        edges: o['edges'] ?? [],
        parties: o['parties'] ?? [],
        output_mode: o['output_mode'] ?? null,
      };
    }
    const bindingsRaw = o['bindings'];
    const bindings: Record<string, string> = {};
    if (bindingsRaw !== null && typeof bindingsRaw === 'object' && !Array.isArray(bindingsRaw)) {
      for (const [k, v] of Object.entries(bindingsRaw as Record<string, unknown>)) {
        bindings[k] = v == null ? '' : String(v);
      }
    }
    const answersRaw = o['answers'];
    const answers = Array.isArray(answersRaw)
      ? (answersRaw.filter((a) => a !== null && typeof a === 'object' && !Array.isArray(a)) as Json[])
      : [];
    const outputMode =
      o['output_mode'] != null
        ? String(o['output_mode'])
        : definition['output_mode'] != null
          ? String(definition['output_mode'])
          : null;
    const participantsRaw = o['participants'];
    const participants = Array.isArray(participantsRaw)
      ? participantsRaw
          .filter((p): p is Json => p !== null && typeof p === 'object' && !Array.isArray(p))
          .map((p) => FlowRunParticipant.fromApi(p))
      : [];
    return new FlowRun(
      o['id'] != null ? String(o['id']) : '',
      o['flow_id'] != null ? String(o['flow_id']) : null,
      o['flow_version'] ?? null,
      o['service_id'] != null ? String(o['service_id']) : null,
      o['connection_id'] != null ? String(o['connection_id']) : null,
      o['company_user_id'] != null ? String(o['company_user_id']) : null,
      bindings,
      o['status'] != null ? String(o['status']) : null,
      o['current_node'] != null ? String(o['current_node']) : null,
      outputMode,
      definition,
      answers,
      o['reference_date'] != null ? String(o['reference_date']) : null,
      parseIsoDate(o['created_at']),
      parseIsoDate(o['updated_at']),
      participants,
      o,
      Array.isArray(o['private_slugs'])
        ? (o['private_slugs'] as unknown[]).filter((x) => x !== null && x !== undefined).map((x) => String(x))
        : null,
    );
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
