/**
 * Output model — the conclusions.
 *
 * The consumer works with these and nothing else. They are produced by factories
 * that turn a *hardened* API JSON object (slug-keyed `values`; NO person source
 * field) into typed objects, decrypting ciphertext via the injected crypto closures.
 *
 *     RequestField { slug, label, type, oneTime, mandatory, verified, verifiedMaxAgeDays }
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
 *
 * Every model carries `.raw` — the underlying (hardened) API object — for debugging
 * or an edge case the SDK didn't model. It never contains the person's source field.
 *
 * Decryption is config-driven: the factory takes a `decryptValue`
 * callable (a closure over the loaded service private key) and, for binaries, a
 * `binaryFetch` callable — never a key/secret argument.
 */

import { BinaryHandle, DecryptError, type BinaryFetch, type DecryptWrapper, type EncWrapper, hashMatches } from './crypto.js';
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
    /** Contract sign/accept audit trail (company-side reads only). */
    readonly signatures: Json[],
    /**
     * Present only on a contract-flow run-participant document: the run's ordered signature
     * summary, one entry per participant owing an act — each
     * `{party_key, document_id, position, status, action, acted_at}`. Null on any other document.
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
      Array.isArray(obj['signatures']) ? (obj['signatures'] as Json[]) : [],
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
 * One participant's row on a run's `participants[]` (flows.html §5a/§9 item 12) — the durable
 * participant set, additively carrying its place in the leaf PDF rule's ordered signing plan.
 * One account may hold TWO of these (two owner parties, or one customer bound to two party
 * keys) — never collapse this to a single row by user id.
 */
export class FlowRunParticipant {
  constructor(
    readonly partyKey: string | null,
    readonly personUserId: string | null,
    readonly connectionId: string | null,
    readonly documentId: string | null,
    readonly documentStatus: string | null,
    readonly requiresSignature: boolean,
    readonly requiresAcceptance: boolean,
    /** 1-based place in the signing plan; null for a party the plan does not name. */
    readonly position: number | null,
    /** 'signed' | 'accepted' | null — null until this participant's document has acted. */
    readonly action: string | null,
    readonly actedAt: string | null,
  ) {}

  static fromApi(o: Json): FlowRunParticipant {
    return new FlowRunParticipant(
      o['party_key'] != null ? String(o['party_key']) : null,
      o['person_user_id'] != null ? String(o['person_user_id']) : null,
      o['connection_id'] != null ? String(o['connection_id']) : null,
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
    readonly documentId: string | null,
    readonly outputMode: string | null,
    readonly definition: Json,
    readonly answers: Json[],
    /** Immutable run "today" (raw `YYYY-MM-DD` string), or null when absent. */
    readonly referenceDate: string | null,
    readonly createdAt: Date | null,
    readonly updatedAt: Date | null,
    /**
     * Every party the run binds, the owning company included (flows.html §5a/§9 item 12).
     * `connectionId` above names only the PRIMARY counterparty, so a multi-actor run's other
     * counterparties are reachable only here.
     */
    readonly participants: FlowRunParticipant[],
    readonly raw: Json,
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
      o['document_id'] != null ? String(o['document_id']) : null,
      outputMode,
      definition,
      answers,
      o['reference_date'] != null ? String(o['reference_date']) : null,
      parseIsoDate(o['created_at']),
      parseIsoDate(o['updated_at']),
      participants,
      o,
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
