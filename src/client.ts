/**
 * Client facade.
 *
 * The one object an integrating company touches. Build it from config (the keys
 * live there and nowhere else), then call:
 *
 *     client.requestFields()              -> Promise<RequestField[]>  (slug -> meta, cached)
 *     client.connections(limit, offset)   -> AsyncIterable<Connection> (auto-paged, lazy)
 *     client.connection(id)               -> Promise<Connection>
 *     client.logs(limit, offset)          -> Promise<LogEntry[]>
 *     client.processChanges(handler, opts) -> Promise<void>  (the crash-safe pump)
 *     client.drainBatch(max)              -> Promise<Change[]>  (raw unbuffered drain — advanced)
 *     client.deadLetters() / client.retryDeadLetters(handler)
 *
 * Plus the webhook receiver helpers, exposed as methods that delegate to the
 * `webhooks` module (all config-driven, no key/secret args):
 *
 *     client.verifyWebhook(rawBody, headers) -> bool
 *     client.parseWebhook(rawBody, headers)  -> Change
 *     client.handleWebhook(rawBody, headers) -> Change
 *
 * How it is wired (everything else the SDK hides):
 *   - **Auth + transport** — an {@link HttpClient} owns the `client_credentials`
 *     token, the JSON/XML accept+parse, and the error mapping (incl. 429 backoff).
 *   - **Decryption** — the service private key is loaded **once** at construction
 *     from the configured encrypted PEM + passphrase into an in-memory key; a
 *     `decryptValue` closure over it is handed to every model factory and the pump
 *     (config-only key handling — the key never appears in a method signature).
 *   - **Slug catalog** — `requestFields()` is fetched once and cached; its slug→type
 *     map types every value (so `address` parses to an object, `photo` becomes a
 *     lazy binary handle, etc.).
 *   - **Binary** — a value's `BinaryHandle.bytes()` GETs the slot file endpoint,
 *     unwraps the API's `{"encrypted":true,"value":<wrapper>}` envelope, and runs
 *     the same service-key decrypt → the file bytes.
 *   - **Changes feed** — `processChanges` delegates to the {@link Pump}, injecting a
 *     `fetchChanges` closure (`GET /changes?limit=`, returning the raw ciphertext
 *     events) and a `decrypt` closure that builds a typed {@link Change}.
 */

import { readFileSync } from 'node:fs';
import type { KeyObject } from 'node:crypto';

import { Config } from './config.js';
import {
  decrypt as cryptoDecrypt,
  encryptForPublicKey,
  loadPrivateKey,
  loadPublicKey,
  type EncWrapper,
} from './crypto.js';
import { ApiError, ConfigError, DecryptError, RateLimitError } from './errors.js';
import { HttpClient, type HttpClientOptions } from './http.js';
import { Change, Connection, Document, LogEntry, RequestField } from './models.js';
import { Pump, type Handler, type Logger, type ProcessOptions } from './pump.js';
import type { DeadLetterRecord } from './buffer.js';
import { handleWebhook, loadAccountKey, parseWebhook, verifyWebhook, type Headers } from './webhooks.js';

// Endpoint paths (the API base comes from Config; HttpClient joins them).
const BASE = '/api/company-data';
const CONNECTIONS = `${BASE}/connections`;
const CHANGES = `${BASE}/changes`;
const REQUEST_FIELDS = `${BASE}/request-fields`;
const LOGS = `${BASE}/logs`;
const DOCUMENTS = `${BASE}/documents`;
const KEYS = '/api/keys';

// Default page size for the connections iterator. The endpoint is heavily
// rate-limited, so we keep pages reasonably large to minimize the
// number of requests for a full sync, while the iterator stays lazy.
const DEFAULT_CONN_PAGE = 100;

type Json = Record<string, unknown>;

// Bounded extra backoff for the connections iterator on a surfaced 429. The
// HttpClient already retries a 429 internally; if it still surfaces a
// RateLimitError we honor Retry-After once more here (the connections endpoints are
// expensive snapshots, not a poll target) before re-throwing.
const CONN_MAX_429_BACKOFFS = 5;
const CONN_DEFAULT_BACKOFF_S = 5.0;
const CONN_MAX_BACKOFF_S = 120.0;

export interface ClientOptions {
  /** An injected transport/auth layer (for tests). */
  http?: HttpClient;
  /** Options forwarded to the default {@link HttpClient} when `http` is not supplied. */
  httpOptions?: HttpClientOptions;
  /** A logger sink for the pump (every drain/deliver/ack/retry/dead-letter/replay). */
  logger?: Logger;
  /** A sleep callable (seconds → Promise) — injectable for tests. */
  sleep?: (seconds: number) => Promise<void>;
}

const defaultSleep = (seconds: number): Promise<void> =>
  new Promise((res) => setTimeout(res, Math.max(0, seconds) * 1000));

/** The company-data SDK client facade. */
export class Client {
  private readonly config: Config;
  private readonly log: Logger;
  private readonly sleep: (seconds: number) => Promise<void>;
  private readonly http: HttpClient;
  private readonly privateKey: KeyObject;
  private readonly accountKey: KeyObject | null;

  // The slug catalog, fetched once on first requestFields() and cached.
  private cachedRequestFields: RequestField[] | null = null;
  private typeBySlug: Map<string, string> = new Map();
  private requestFieldsInFlight: Promise<RequestField[]> | null = null;

  private _pump: Pump | null = null;

  // Recipient RSA public keys (by shareCode) — cached for per-person document
  // encryption. A public key is immutable + not a secret (fetched live, never configured).
  private pubKeyCache: Map<string, KeyObject> = new Map();

  constructor(config: Config, opts: ClientOptions = {}) {
    this.config = config;
    this.log = opts.logger ?? {};
    this.sleep = opts.sleep ?? defaultSleep;

    // Transport (auth + JSON/XML + error taxonomy). Injectable for tests.
    this.http = opts.http ?? new HttpClient(config, opts.httpOptions);

    // Load the service private key ONCE from the configured encrypted PEM +
    // passphrase (config-only key handling). This is the single place
    // the key material is read; a closure over it does every decrypt.
    this.privateKey = loadServiceKey(config);

    // Load the ACCOUNT private key ONCE too (null unless configured). Reused for
    // every encrypt_payload webhook so we don't re-read the PEM + re-run PBKDF2
    // (~100k iters) per request — same one-time-load discipline as the service key.
    this.accountKey = loadAccountKey(config);
  }

  // ── constructors (config-only keys) ────────────────────────────────────────

  /** Build from a JSON config file (env vars override secrets). */
  static fromConfig(path: string, opts: ClientOptions = {}): Client {
    return new Client(Config.fromFile(path), opts);
  }

  /** Build entirely from `ALLUS_*` env vars. */
  static fromEnv(opts: ClientOptions = {}): Client {
    return new Client(Config.fromEnv(), opts);
  }

  // ── decryption wiring (closures over the loaded key — never a method arg) ──

  private decryptValue = (wrapper: EncWrapper | string): string => cryptoDecrypt(wrapper, this.privateKey);

  /**
   * Fetch a slot file endpoint and unwrap its `{"encrypted":true,"value":...}` envelope.
   *
   * Returns the inner `{"_enc":1,...}` wrapper, which the {@link BinaryHandle} then
   * decrypts with the same service key.
   */
  private binaryFetch = async (valueUrl: string): Promise<EncWrapper | string> => {
    const body = await this.http.get(valueUrl);
    if (body !== null && typeof body === 'object' && !Array.isArray(body) && 'value' in body) {
      return (body as Record<string, unknown>)['value'] as EncWrapper | string;
    }
    // Defensive: some shapes might return the wrapper directly.
    return body as EncWrapper | string;
  };

  /** Resolve a request slug to its field type (loads the catalog once). */
  private typeForSlug = (slug: string): string | null => {
    return this.typeBySlug.get(slug) ?? null;
  };

  // ── definitions ────────────────────────────────────────────────────────────

  /**
   * The cached request-field DEFINITIONS.
   *
   * Fetched once from `GET /api/company-data/request-fields` and cached for the life
   * of the client (it's the company's static config, and it types every value).
   * Returns YOUR request config — never the person's fields. Concurrent callers
   * share a single in-flight fetch.
   */
  async requestFields(): Promise<RequestField[]> {
    if (this.cachedRequestFields !== null) {
      return this.cachedRequestFields;
    }
    if (this.requestFieldsInFlight === null) {
      this.requestFieldsInFlight = (async () => {
        const body = await this.http.get(REQUEST_FIELDS);
        const fields = RequestField.listFromApi(body);
        this.cachedRequestFields = fields;
        this.typeBySlug = new Map(fields.filter((f) => f.slug).map((f) => [f.slug, f.type]));
        return fields;
      })();
      try {
        return await this.requestFieldsInFlight;
      } finally {
        this.requestFieldsInFlight = null;
      }
    }
    return this.requestFieldsInFlight;
  }

  // ── connections (heavily rate-limited — initial sync / reconciliation) ─────

  /**
   * A lazy async generator paging the list endpoint, yielding one Connection at a time.
   *
   * `limit` is the page size; `offset` the starting offset. The generator auto-pages
   * `GET /api/company-data/connections?limit&offset` and yields typed
   * {@link Connection} objects (each `values[slug]` already decrypted / a lazy binary
   * handle) one at a time — bounded memory for a large book. It honors the response's
   * `total` (when present) so it never over-fetches a page past the end, and also
   * stops on a short page as a fallback.
   *
   * The connections endpoints are **heavily rate-limited**: use this
   * for the initial full sync + occasional reconciliation, never as a poll substitute
   * for the changes feed. On a surfaced {@link RateLimitError} the generator backs off
   * per `Retry-After` and retries the page a bounded number of times before
   * re-throwing — so it paces itself within the limit rather than hammering.
   */
  async *connections(limit: number = DEFAULT_CONN_PAGE, offset: number = 0): AsyncGenerator<Connection> {
    const page = Math.max(1, Math.trunc(limit));
    let cur = Math.max(0, Math.trunc(offset));
    // Ensure the slug catalog is loaded so values are typed correctly.
    await this.requestFields();

    let total: number | null = null;
    for (;;) {
      const body = await this.getConnectionsPage(page, cur);
      total = readTotal(body, total);
      const items = listItems(body);
      if (items.length === 0) {
        return;
      }
      for (const obj of items) {
        if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) continue;
        yield Connection.fromApi(obj as Record<string, unknown>, {
          typeForSlug: this.typeForSlug,
          decryptValue: this.decryptValue,
          binaryFetch: this.binaryFetch,
          // The list row carries identity (displayName/connectedAt) AND the values
          // map, so the same object is both detail + identity.
          identity: obj as Record<string, unknown>,
        });
      }
      cur += items.length;
      // Stop when we've consumed `total` rows (honor the API's total so we don't
      // over-fetch a final empty/short page), or on a short page as a fallback.
      if (total !== null && cur >= total) {
        return;
      }
      if (items.length < page) {
        return;
      }
    }
  }

  private async getConnectionsPage(page: number, offset: number): Promise<unknown> {
    let attempts = 0;
    for (;;) {
      try {
        return await this.http.get(CONNECTIONS, { limit: page, offset });
      } catch (exc) {
        if (!(exc instanceof RateLimitError)) throw exc;
        attempts += 1;
        if (attempts > CONN_MAX_429_BACKOFFS) throw exc;
        const delay = connBackoff(exc.retryAfter, attempts);
        this.log.warn?.(
          `connections rate-limited (offset=${offset}); backoff ${delay}s (attempt ${attempts})`,
        );
        if (delay) await this.sleep(delay);
      }
    }
  }

  /**
   * Fetch a single connection by id → one {@link Connection}.
   *
   * `GET /api/company-data/connections/{id}` returns `{connection_id, user_id,
   * values}` and no displayName/connectedAt; those identity fields simply stay
   * `null` (the list endpoint carries them).
   */
  async connection(id: string): Promise<Connection> {
    await this.requestFields();
    let body = await this.http.get(`${CONNECTIONS}/${id}`);
    if (
      body !== null &&
      typeof body === 'object' &&
      !Array.isArray(body) &&
      'items' in body &&
      !('values' in body)
    ) {
      // Defensive: a single-item list shape.
      const items = listItems(body);
      body = items.length > 0 ? items[0] : {};
    }
    return Connection.fromApi(body as Record<string, unknown>, {
      typeForSlug: this.typeForSlug,
      decryptValue: this.decryptValue,
      binaryFetch: this.binaryFetch,
    });
  }

  // ── logs (moderate rate-limit) ──────────────────────────────────────────────

  /**
   * The service's activity log → `LogEntry[]`.
   *
   * `GET /api/company-data/logs?limit&offset`. Ops events only (email / purge /
   * webhook) — never person field data.
   */
  async logs(limit: number = 50, offset: number = 0): Promise<LogEntry[]> {
    const body = await this.http.get(LOGS, {
      limit: Math.max(1, Math.trunc(limit)),
      offset: Math.max(0, Math.trunc(offset)),
    });
    return LogEntry.listFromApi(body);
  }

  // ── changes feed — the crash-safe pump ──────────────────────────────────────

  /** The crash-safe changes {@link Pump} (built lazily). */
  get pump(): Pump {
    if (this._pump === null) {
      this._pump = new Pump(this.config, {
        fetchChanges: (limit) => this.fetchChanges(limit),
        decrypt: (event) => this.decryptChange(event),
        logger: this.log,
        sleep: this.sleep,
      });
    }
    return this._pump;
  }

  private async fetchChanges(limit: number): Promise<Record<string, unknown>[]> {
    const body = await this.http.get(CHANGES, { limit: Math.trunc(limit) });
    let items: unknown;
    if (body !== null && typeof body === 'object' && !Array.isArray(body)) {
      items = (body as Record<string, unknown>)['changes'] ?? [];
    } else {
      items = body ?? [];
    }
    if (!Array.isArray(items)) return [];
    return items.filter((o): o is Record<string, unknown> => o !== null && typeof o === 'object' && !Array.isArray(o));
  }

  private decryptChange(event: Record<string, unknown>): Change {
    return Change.fromApi(event, {
      typeForSlug: this.typeForSlug,
      decryptValue: this.decryptValue,
      binaryFetch: this.binaryFetch,
    });
  }

  /**
   * Drain the changes feed through `handler` one at a time, crash-safely.
   *
   * Delegates to the {@link Pump}: replay the durable buffer, drain ≤500 at a time,
   * persist-before-deliver, per-item ack, retry→dead-letter→continue, until the feed
   * is empty then return (no daemon mode — schedule re-runs yourself). `handler` must
   * be idempotent (at-least-once; dedup on `Change.id`). Options:
   * `batchSize` (≤500), `maxRetries`, `onError` (`deadletter`|`halt`), `backoff`.
   */
  async processChanges(handler: Handler, options: ProcessOptions = {}): Promise<void> {
    await this.requestFields(); // ensure the catalog is loaded for value typing
    await this.pump.processChanges(handler, options);
  }

  /** Raw, UNBUFFERED drain → `Change[]` (advanced — you own durability). */
  async drainBatch(max: number = DEFAULT_CONN_PAGE): Promise<Change[]> {
    await this.requestFields();
    return this.pump.drainBatch(max);
  }

  /** The local dead-letter store. */
  deadLetters(): DeadLetterRecord[] {
    return this.pump.deadLetters();
  }

  /** Re-drive dead-lettered events through `handler`. */
  async retryDeadLetters(handler: Handler, options: ProcessOptions = {}): Promise<number> {
    await this.requestFields();
    return this.pump.retryDeadLetters(handler, options);
  }

  // ── webhook receiver helpers (config-driven, no key args) ───────────────────

  /** Verify a webhook's `X-Allus-Signature` HMAC. */
  verifyWebhook(rawBody: Buffer | Uint8Array | string, headers: Headers): boolean {
    return verifyWebhook(rawBody, headers, this.config);
  }

  /** Parse a webhook body → a typed {@link Change}. */
  parseWebhook(rawBody: Buffer | Uint8Array | string, headers: Headers): Change {
    return parseWebhook(rawBody, headers, this.config, {
      typeForSlug: this.typeForSlug,
      decryptValue: this.decryptValue,
      binaryFetch: this.binaryFetch,
      accountKey: this.accountKey, // cached once; no per-webhook PBKDF2
    });
  }

  /** Verify + parse a webhook in one call → {@link Change}. */
  handleWebhook(rawBody: Buffer | Uint8Array | string, headers: Headers): Change {
    return handleWebhook(rawBody, headers, this.config, {
      typeForSlug: this.typeForSlug,
      decryptValue: this.decryptValue,
      binaryFetch: this.binaryFetch,
      accountKey: this.accountKey, // cached once; no per-webhook PBKDF2
    });
  }

  // ── company documents (write) ───────────────────────────────────────────────

  /**
   * Fetch + cache the recipient RSA public key by shareCode
   * (`GET /api/keys/{shareCode}` → `{public_key:<b64 SPKI>}`).
   */
  private async recipientPublicKey(shareCode: string): Promise<KeyObject> {
    const cached = this.pubKeyCache.get(shareCode);
    if (cached !== undefined) return cached;
    const body = await this.http.get(`${KEYS}/${shareCode}`);
    const spki =
      body !== null && typeof body === 'object' && !Array.isArray(body)
        ? (body as Record<string, unknown>)['public_key']
        : null;
    if (typeof spki !== 'string' || spki === '') {
      throw new ApiError(0, 'keys.not_found', `no public_key for share_code ${shareCode}`);
    }
    const key = loadPublicKey(spki);
    this.pubKeyCache.set(shareCode, key);
    return key;
  }

  /**
   * Resolve a target's shareCode (the recipient public-key handle).
   *
   * Prefers a single-connection fetch (carries `share_code`); falls back to a
   * connections scan by `user_id`. Pass `shareCode` to skip this entirely.
   */
  private async resolveShareCode(
    connectionId: string | undefined,
    personUserId: string | undefined,
  ): Promise<string> {
    if (connectionId) {
      const body = await this.http.get(`${CONNECTIONS}/${connectionId}`);
      const sc =
        body !== null && typeof body === 'object' && !Array.isArray(body)
          ? (body as Record<string, unknown>)['share_code']
          : null;
      if (sc != null && String(sc) !== '') return String(sc);
    }
    if (personUserId) {
      for await (const conn of this.connections()) {
        const raw = conn.raw ?? {};
        if (raw['user_id'] === personUserId || conn.personId === personUserId) {
          const sc = raw['share_code'];
          if (sc != null && String(sc) !== '') return String(sc);
        }
      }
    }
    throw new ConfigError(
      'could not resolve a share_code for the target — pass shareCode explicitly',
    );
  }

  /**
   * Create a company document for a connection / person (PER-PERSON), or BROADCAST
   * (no target).
   *
   * `payloadKind:'json'` → `jsonValue` (object). `payloadKind:'file'` → `fileBytes`
   * (+ `fileMime`).
   *
   * Encryption is decided by the TARGET, not by is_private:
   *   PER-PERSON (connectionId/personUserId given) → the value is ALWAYS encrypted FOR
   *     THE RECIPIENT (shareCode resolved from connectionId/personUserId when not given)
   *     before it leaves the process — for EVERY per-person doc, private or not. The
   *     server stores ciphertext. NO key argument.
   *   BROADCAST (no target) → the value is sent PLAINTEXT (you cannot single-key-encrypt
   *     to all of a service's connections). A broadcast MUST be non-private (a plaintext
   *     value cannot be locked); is_private therefore requires a per-person target.
   *
   * is_private is a DISPLAY-ONLY flag passed through to the API — it governs the
   * recipient device's lock vs decrypt-on-load behaviour, NOT whether the value is
   * encrypted.
   */
  async createDocument(opts: {
    kind?: string;
    name: string;
    payloadKind: 'json' | 'file';
    isPrivate?: boolean;
    description?: string;
    connectionId?: string;
    personUserId?: string;
    /** Recipient handle for per-person encryption (skips share-code resolution). */
    shareCode?: string;
    jsonValue?: unknown;
    fileBytes?: Buffer | Uint8Array;
    fileMime?: string;
    /** Contract: the person must sign (step-up). Forces a per-person target. */
    requiresSignature?: boolean;
    /** Contract: the person must accept. Forces a per-person target. */
    requiresAcceptance?: boolean;
    metadata?: Json;
    status?: string;
  }): Promise<Document> {
    const payloadKind = opts.payloadKind;
    if (payloadKind !== 'json' && payloadKind !== 'file') {
      throw new ConfigError("payloadKind must be 'json' or 'file'");
    }
    const kind = opts.kind ?? 'document';
    if (kind !== 'document' && kind !== 'agreement' && kind !== 'subscription') {
      throw new ConfigError("kind must be 'document', 'agreement' or 'subscription'");
    }

    let target: Json | null = null;
    if (opts.connectionId) {
      target = { connection_id: opts.connectionId };
    } else if (opts.personUserId) {
      target = { person_user_id: opts.personUserId };
    } // else: broadcast — target stays null

    const perPerson = target !== null;
    const isPrivate = Boolean(opts.isPrivate);
    const requiresSignature = Boolean(opts.requiresSignature);
    const requiresAcceptance = Boolean(opts.requiresAcceptance);
    // A contract (agreement/subscription, or either flag) is ALWAYS per-person → it must target one person.
    const isContract = kind === 'agreement' || kind === 'subscription' || requiresSignature || requiresAcceptance;
    if (isContract && !perPerson) {
      throw new ConfigError('a contract must target one connected person');
    }
    if (isPrivate && !perPerson) {
      // A plaintext broadcast cannot be locked — is_private needs a per-person target.
      throw new ConfigError('isPrivate requires a per-person target (broadcast is plaintext)');
    }

    let pubKey: KeyObject | null = null;
    if (perPerson) {
      // EVERY per-person doc is encrypted, private or not — fetch the recipient key.
      const sc = opts.shareCode ?? (await this.resolveShareCode(opts.connectionId, opts.personUserId));
      pubKey = await this.recipientPublicKey(sc);
    }

    const body: Json = {
      kind,
      name: opts.name,
      payload_kind: payloadKind,
      is_private: isPrivate,
      requires_signature: requiresSignature,
      requires_acceptance: requiresAcceptance,
      target,
    };
    if (opts.description !== undefined) body['description'] = opts.description;
    if (opts.metadata !== undefined) body['metadata'] = opts.metadata;
    if (opts.status !== undefined) body['status'] = opts.status;

    if (payloadKind === 'json') {
      if (opts.jsonValue === undefined) {
        throw new ConfigError("jsonValue is required for payloadKind='json'");
      }
      body['value'] = perPerson
        ? encryptForPublicKey(JSON.stringify(opts.jsonValue), pubKey as KeyObject)
        : opts.jsonValue;
      const created = await this.http.post(DOCUMENTS, { json: body });
      return Document.fromApi(docObj(created), { decryptValue: this.decryptValue });
    }

    // file: create the metadata row first, then upload bytes to /{id}/file.
    if (opts.fileBytes === undefined) {
      throw new ConfigError("fileBytes is required for payloadKind='file'");
    }
    const created = await this.http.post(DOCUMENTS, { json: body });
    const doc = Document.fromApi(docObj(created), { decryptValue: this.decryptValue });
    const fileBytes = Buffer.from(opts.fileBytes);
    if (perPerson) {
      // Encrypt the file bytes (EVERY per-person doc): wrap the file envelope string,
      // then send the wrapper as bytes.
      const envelope = JSON.stringify({ file: dataUri(fileBytes, opts.fileMime) });
      const wrapper = encryptForPublicKey(envelope, pubKey as KeyObject);
      await this.http.post(`${DOCUMENTS}/${doc.id}/file`, {
        raw: Buffer.from(JSON.stringify(wrapper), 'utf8'),
        contentType: 'application/json',
      });
    } else {
      // Broadcast — raw plaintext bytes.
      await this.http.post(`${DOCUMENTS}/${doc.id}/file`, {
        raw: fileBytes,
        contentType: opts.fileMime ?? 'application/octet-stream',
      });
    }
    return doc;
  }

  /**
   * List this service's documents → `Document[]` (paged; optional person/status filter).
   */
  async listDocuments(
    opts: { personUserId?: string; status?: string; limit?: number; offset?: number } = {},
  ): Promise<Document[]> {
    const params: Record<string, string | number> = {
      limit: Math.max(1, Math.trunc(opts.limit ?? 100)),
      offset: Math.max(0, Math.trunc(opts.offset ?? 0)),
    };
    if (opts.personUserId) params['person_user_id'] = opts.personUserId;
    if (opts.status) params['status'] = opts.status;
    const body = await this.http.get(DOCUMENTS, params);
    return Document.listFromApi(body, { decryptValue: this.decryptValue });
  }

  /** Fetch one document by id → {@link Document}. */
  async document(documentId: string): Promise<Document> {
    const body = await this.http.get(`${DOCUMENTS}/${documentId}`);
    return Document.fromApi(docObj(body), { decryptValue: this.decryptValue });
  }

  /**
   * Set a document's lifecycle status
   * (offering|ready_to_sign|active|active_but_ending|ended).
   */
  async updateDocumentStatus(documentId: string, status: string): Promise<Document> {
    const body = await this.http.put(`${DOCUMENTS}/${documentId}`, { json: { status } });
    return Document.fromApi(docObj(body), { decryptValue: this.decryptValue });
  }

  /** Update a document's metadata / name / description. */
  async updateDocumentMetadata(
    documentId: string,
    opts: { metadata?: Json; name?: string; description?: string },
  ): Promise<Document> {
    const payload: Json = {};
    if (opts.metadata !== undefined) payload['metadata'] = opts.metadata;
    if (opts.name !== undefined) payload['name'] = opts.name;
    if (opts.description !== undefined) payload['description'] = opts.description;
    if (Object.keys(payload).length === 0) {
      throw new ConfigError('updateDocumentMetadata needs metadata, name, or description');
    }
    const body = await this.http.put(`${DOCUMENTS}/${documentId}`, { json: payload });
    return Document.fromApi(docObj(body), { decryptValue: this.decryptValue });
  }

  /** Delete a document (and its on-disk file). */
  async deleteDocument(documentId: string): Promise<void> {
    await this.http.delete(`${DOCUMENTS}/${documentId}`);
  }
}

// ── module-level helpers ──────────────────────────────────────────────────────

/** Read the configured encrypted PEM and decrypt it with the passphrase (once). */
function loadServiceKey(config: Config): KeyObject {
  let pemBytes: Buffer;
  try {
    pemBytes = readFileSync(config.servicePrivateKey);
  } catch (exc) {
    throw new ConfigError(
      `could not read servicePrivateKey PEM: ${config.servicePrivateKey}: ${(exc as Error).message}`,
    );
  }
  try {
    return loadPrivateKey(pemBytes, config.keyPassphrase);
  } catch (exc) {
    if (exc instanceof DecryptError) {
      // A bad passphrase / malformed PEM is a configuration problem (fail fast).
      throw new ConfigError(`could not load service private key: ${exc.message}`);
    }
    throw exc;
  }
}

/**
 * Pull the document object out of a create/get/update response.
 *
 * The API returns the bare document object; tolerate a `{"document": {...}}` wrapper too.
 */
function docObj(body: unknown): Json {
  if (body !== null && typeof body === 'object' && !Array.isArray(body)) {
    const inner = (body as Record<string, unknown>)['document'];
    if (inner !== null && typeof inner === 'object' && !Array.isArray(inner)) {
      return inner as Json;
    }
    return body as Json;
  }
  return {};
}

/** Build a `data:<mime>;base64,<…>` URI for the per-person file envelope. */
function dataUri(fileBytes: Buffer, mime: string | undefined): string {
  const b64 = fileBytes.toString('base64');
  return `data:${mime ?? 'application/octet-stream'};base64,${b64}`;
}

/** Pull the `items` array out of a `{total, items}` list response. */
function listItems(body: unknown): unknown[] {
  if (body !== null && typeof body === 'object' && !Array.isArray(body)) {
    const items = (body as Record<string, unknown>)['items'];
    if (items === undefined || items === null) return [];
    return Array.isArray(items) ? items : [];
  }
  if (Array.isArray(body)) return body;
  return [];
}

/** Read the `total` count out of a `{total, items}` list response (or keep the prior). */
function readTotal(body: unknown, prior: number | null): number | null {
  if (body !== null && typeof body === 'object' && !Array.isArray(body)) {
    const t = (body as Record<string, unknown>)['total'];
    if (t !== undefined && t !== null) {
      const n = Number(t);
      if (Number.isFinite(n)) return n;
    }
  }
  return prior;
}

/** Backoff before retrying a rate-limited connections page. */
function connBackoff(retryAfter: number | null, attempt: number): number {
  if (retryAfter !== null && retryAfter >= 0) {
    return Math.min(retryAfter, CONN_MAX_BACKOFF_S);
  }
  return Math.min(CONN_DEFAULT_BACKOFF_S * 2 ** (attempt - 1), CONN_MAX_BACKOFF_S);
}
