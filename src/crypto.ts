/**
 * Decryption core.
 *
 * Every person value arrives as a ciphertext wrapper, encrypted **for the service
 * public key**; the SDK decrypts with the service private key. The algorithm MUST
 * match the platform's Web Crypto encryption exactly:
 *
 *     wrapper = {"_enc":1,
 *                "k":  base64(rsa_oaep_sha256(aesKey, servicePublicKey)),
 *                "iv": base64(iv12),
 *                "d":  base64(aes256gcm_ciphertext_with_tag)}
 *
 *     decrypt(wrapper, servicePrivateKey):
 *       aesKey    = RSA-OAEP(SHA-256, MGF1-SHA256) decrypt wrapper.k   // 32 bytes
 *       plaintext = AES-256-GCM decrypt wrapper.d with aesKey, iv=wrapper.iv
 *                   // the 16-byte GCM tag is the LAST 16 bytes of d
 *       return utf8(plaintext)
 *
 * The service private key is the OpenSSL-encrypted PKCS#8 PEM downloaded from the
 * portal (PBES2 = PBKDF2-HMAC-SHA256 + AES-256-CBC, ~100k iters). Node's
 * `crypto.createPrivateKey({ key, passphrase })` reads it directly (PBES2 is
 * handled by OpenSSL under the hood).
 *
 * Node specifics (the cross-language gotchas to watch for):
 *   - `crypto.privateDecrypt({ key, padding: RSA_PKCS1_OAEP_PADDING,
 *     oaepHash: 'sha256' }, k)` — **`oaepHash: 'sha256'` MUST be set explicitly**;
 *     Node defaults `oaepHash` to SHA-1, which would mismatch the platform and
 *     fail to unwrap the AES key. Setting it to sha256 also pins MGF1 to SHA-256.
 *   - `crypto.createDecipheriv('aes-256-gcm', aesKey, iv)` + `setAuthTag(tag)` —
 *     the 16-byte tag is the LAST 16 bytes of `d`.
 */

import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  privateDecrypt,
  publicEncrypt,
  randomBytes,
  constants as cryptoConstants,
  type KeyObject,
  createHash,
  generateKeyPairSync,
} from 'node:crypto';
import { renameSync, unlinkSync, writeFileSync, openSync, fsyncSync, closeSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import { DecryptError } from './errors.js';

export const GCM_TAG_LEN = 16; // bytes — appended to the AES-GCM ciphertext
export const GCM_IV_LEN = 12; // bytes

// Re-export so `crypto.ts` consumers can pull the error alongside the core.
export { DecryptError } from './errors.js';

/** The platform hybrid wrapper `{"_enc":1,k,iv,d}`. */
export interface EncWrapper {
  _enc?: number;
  k: string;
  iv: string;
  d: string;
}

/**
 * Load a PKCS#8 PEM into an in-memory private key handle.
 *
 * The platform's key downloads are OpenSSL-encrypted PEMs (PBES2 = PBKDF2-HMAC-SHA256 +
 * AES-256-CBC, ~100k iters); Node's `createPrivateKey` decrypts one with the passphrase (OpenSSL
 * handles the SHA-256 PRF). An UNENCRYPTED PKCS#8 PEM loads too — a plugin server's own key, for
 * {@link pluginOpenRequest} — with the passphrase empty or null. The key is never written back to
 * disk in plaintext.
 *
 * Config-only key handling: the client roles use this only with the configured passphrase —
 * never one passed in by application code.
 */
export function loadPrivateKey(encryptedPem: Buffer | string, passphrase: string | null): KeyObject {
  try {
    return createPrivateKey({ key: encryptedPem, passphrase: passphrase ?? '' });
  } catch (exc) {
    // A wrong passphrase / malformed PEM / unsupported algorithm all land here.
    throw new DecryptError(`could not load private key PEM: ${(exc as Error).message}`);
  }
}

function b64decode(value: unknown, fieldName: string): Buffer {
  if (typeof value !== 'string') {
    throw new DecryptError(`wrapper field '${fieldName}' must be a base64 string`);
  }
  // Validate strictly: re-encoding must reproduce the (normalized) input so we
  // reject genuinely malformed base64 like the Python `validate=True` path does.
  const buf = Buffer.from(value, 'base64');
  const normalized = value.replace(/\s+/g, '');
  if (buf.toString('base64').replace(/=+$/, '') !== normalized.replace(/=+$/, '')) {
    throw new DecryptError(`wrapper field '${fieldName}' is not valid base64`);
  }
  return buf;
}

function parseWrapper(wrapper: EncWrapper | string): EncWrapper {
  let obj: unknown = wrapper;
  if (typeof wrapper === 'string') {
    try {
      obj = JSON.parse(wrapper);
    } catch {
      throw new DecryptError('wrapper string is not valid JSON');
    }
  }
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new DecryptError('wrapper must be an object or a JSON object string');
  }
  const rec = obj as Record<string, unknown>;
  for (const fieldName of ['k', 'iv', 'd'] as const) {
    if (!(fieldName in rec)) {
      throw new DecryptError(`wrapper missing required field '${fieldName}'`);
    }
  }
  return rec as unknown as EncWrapper;
}

/**
 * Decrypt a platform `{"_enc":1,k,iv,d}` wrapper → a utf-8 plaintext string.
 *
 * For a *text* value the plaintext is the value itself. For a *binary* value the
 * plaintext is a JSON envelope STRING (photo: `{"full":"data:...","thumb":...}`;
 * document: `{"file":"data:...","original_name":...}`) — NOT raw bytes. The full
 * binary-handle parse (envelope -> data-URI -> bytes) lives on {@link BinaryHandle};
 * here we only ever decrypt to that envelope string.
 *
 * Throws {@link DecryptError} on a malformed wrapper, the wrong key, or a GCM tag
 * mismatch.
 */
export function decrypt(wrapper: EncWrapper | string, privateKey: KeyObject): string {
  const w = parseWrapper(wrapper);

  const encKey = b64decode(w.k, 'k');
  const iv = b64decode(w.iv, 'iv');
  const ciphertextWithTag = b64decode(w.d, 'd');

  if (iv.length !== GCM_IV_LEN) {
    throw new DecryptError(`iv must be ${GCM_IV_LEN} bytes, got ${iv.length}`);
  }
  if (ciphertextWithTag.length < GCM_TAG_LEN) {
    throw new DecryptError('ciphertext too short to contain a GCM tag');
  }

  // 1) RSA-OAEP(SHA-256, MGF1-SHA256) unwrap the AES key. `oaepHash: 'sha256'`
  //    MUST be set explicitly — Node defaults to SHA-1 (and setting the OAEP hash
  //    also pins MGF1 to the same digest), matching Web Crypto RSA-OAEP/SHA-256.
  let aesKey: Buffer;
  try {
    aesKey = privateDecrypt(
      {
        key: privateKey,
        padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      encKey,
    );
  } catch (exc) {
    throw new DecryptError(`RSA-OAEP unwrap failed (wrong key?): ${(exc as Error).message}`);
  }

  if (aesKey.length !== 32) {
    throw new DecryptError(`unwrapped AES key must be 32 bytes (AES-256), got ${aesKey.length}`);
  }

  // 2) AES-256-GCM decrypt. The 16-byte tag is the LAST 16 bytes of `d`.
  const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - GCM_TAG_LEN);
  const ciphertext = ciphertextWithTag.subarray(0, ciphertextWithTag.length - GCM_TAG_LEN);

  let plaintext: Buffer;
  try {
    const decipher = createDecipheriv('aes-256-gcm', aesKey, iv);
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new DecryptError('AES-GCM tag mismatch (wrong key or corrupt data)');
  }

  // utf-8 with strict-ish handling: Node's 'utf8' decode replaces invalid bytes,
  // so re-encode and compare to catch a non-UTF-8 plaintext (parity with Python's
  // strict decode → DecryptError).
  const text = plaintext.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(plaintext)) {
    throw new DecryptError('decrypted plaintext is not valid UTF-8');
  }
  return text;
}

/**
 * Load a base64 SPKI/DER public key (the platform's `GET /api/keys` `public_key`) →
 * a Node public key handle.
 *
 * Config-only key handling does NOT apply to a RECIPIENT public key: it is not a
 * secret and is fetched live from the API per-recipient (never configured). The SDK
 * still never accepts a *private* key/passphrase as a method argument.
 */
export function loadPublicKey(spkiB64: string): KeyObject {
  let der: Buffer;
  try {
    der = b64decode(spkiB64, 'public_key');
  } catch {
    throw new DecryptError('recipient public_key is not valid base64');
  }
  try {
    return createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch (exc) {
    throw new DecryptError(`recipient public_key is not a valid SPKI key: ${(exc as Error).message}`);
  }
}

/**
 * Encrypt a UTF-8 string FOR a recipient public key → a `{"_enc":1,k,iv,d}` wrapper.
 *
 * The exact inverse of {@link decrypt}:
 *   aesKey  = 32 random bytes
 *   d       = AES-256-GCM(aesKey, iv=12 random bytes).encrypt(utf8(plaintext))  // tag appended
 *   k       = RSA-OAEP(SHA-256, MGF1-SHA256).encrypt(aesKey, publicKey)
 *
 * Used for EVERY per-person (targeted) document (json + file), independent of
 * is_private — broadcast docs stay plaintext.
 *
 * **`oaepHash: 'sha256'` MUST be set explicitly** — Node defaults `oaepHash` to
 * SHA-1 (and setting it pins MGF1 to the same digest), matching Web Crypto
 * RSA-OAEP/SHA-256 so the value round-trips through {@link decrypt}.
 */
export function encryptForPublicKey(plaintext: string, publicKey: KeyObject): EncWrapper {
  if (typeof plaintext !== 'string') {
    throw new DecryptError('plaintext to encrypt must be a string');
  }
  const aesKey = randomBytes(32);
  const iv = randomBytes(GCM_IV_LEN); // 12
  // AES-256-GCM: append the 16-byte tag to the ciphertext (the platform layout).
  const cipher = createCipheriv('aes-256-gcm', aesKey, iv);
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
  const d = Buffer.concat([ct, cipher.getAuthTag()]);
  // RSA-OAEP(SHA-256, MGF1-SHA256) — pin SHA-256 for digest AND MGF1 (never SHA-1).
  const k = publicEncrypt(
    { key: publicKey, padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    aesKey,
  );
  return {
    _enc: 1,
    k: k.toString('base64'),
    iv: iv.toString('base64'),
    d: d.toString('base64'),
  };
}

/**
 * One response from a company-facing binary file endpoint, in the shape a {@link BinaryHandle} needs.
 *
 * The route has THREE 200 shapes and the company cannot predict which it will get, because the
 * answer depends on the person's own privacy setting and on the TYPE of the field they answered
 * with, neither of which the company chooses:
 *
 * - **encrypted** — `application/json`, `{"encrypted":true,"value":<wrapper>}`. The wrapper decrypts
 *   to the binary ENVELOPE string.
 * - **envelope** — `application/json`, `{"encrypted":false,"value":"<envelope>"}`. The plaintext
 *   envelope string itself, for a non-private source whose type stores more than one file or
 *   declares metadata entries. Nothing to decrypt.
 * - **plaintext bytes** — the file's own `Content-Type` (e.g. `image/jpeg`, `application/pdf`) and
 *   the body IS the file bytes.
 *
 * The bytes shape is told apart from the two JSON ones on the response's `Content-Type`, never
 * guessed from the body: a plaintext answer's first byte is whatever the file starts with, and a PDF
 * or a JPEG that happened to begin with a brace would be indistinguishable from a wrapper by
 * sniffing. Inside a JSON body it is `encrypted` that decides; a JSON body that does not carry
 * `encrypted: false` with a string `value` is the wrapper arm, which is what the bare-wrapper
 * routes (a company's own contract copy, its run slot file) answer with.
 *
 * `contentSha256` is the platform's `X-Allus-Content-Sha256` — the sha256 of the SERVED ARTIFACT:
 * the raw bytes on the bytes shape, the served `value` string on either JSON shape — so a consumer
 * can record what it received and later prove its archived copy has not drifted.
 */
export interface BinaryFetchResult {
  /** `true` for the JSON-wrapper shape, `false` for the envelope shape and for raw bytes. */
  encrypted: boolean;
  /** The `{"_enc":1,…}` wrapper (encrypted shape). */
  wrapper?: EncWrapper | string | null;
  /** The file bytes themselves (plaintext-bytes shape). */
  bytes?: Buffer | null;
  /** The plaintext envelope string (envelope shape). */
  envelope?: string | null;
  contentType?: string | null;
  contentSha256?: string | null;
}

/**
 * One page of a multi-page binary answer (an ID document's front, back, …).
 *
 * `label` is the page's own label (`front` | `back` | `additional`), `name` the original filename
 * the person uploaded it under, `mime` the server-derived media type, and `bytes` the decoded page
 * bytes.
 */
export interface BinaryPage {
  label: string | null;
  name: string | null;
  mime: string | null;
  bytes: Buffer;
}

/** Fetch a slot file endpoint → the classified response (which shape arrived, plus its digest). */
export type BinaryFetch = (valueUrl: string) => Promise<BinaryFetchResult> | BinaryFetchResult;
/** Decrypt a ciphertext wrapper → the envelope string (closes over the service key). */
export type DecryptWrapper = (wrapper: EncWrapper | string) => string;

const DATA_URI_KEYS = ['full', 'file'] as const;

/**
 * Envelope members that describe the envelope itself rather than the type's own declared entries —
 * everything NOT in this set is metadata.
 */
const ENVELOPE_MEMBERS = new Set(['pages', 'file', 'full', 'thumb', 'original_name', 'mime_type', 'size']);

/**
 * Lazy handle for a binary (photo/document) value.
 *
 * A binary answer is stored server-side as a file, exposed in the hardened API as
 * a slot-keyed `value_url` (never the source field). `.bytes()` and `.save()` GET
 * that URL and return the FILE BYTES; `.pages()` and `.metadata()` expose the rest of the
 * envelope. The caller never has to know which of the three response shapes arrived.
 *
 * THERE ARE THREE SHAPES, AND WHICH ONE ARRIVES IS NOT THE COMPANY'S CHOICE. The person's own
 * privacy setting and the TYPE of the field they answered with decide it, either can change at
 * any time, and nothing in the API announces it in advance:
 *
 *   - **private source** → `application/json` `{"encrypted":true,"value":<wrapper>}`. The wrapper
 *     decrypts to a JSON envelope STRING (photo: `{"full":"data:...","thumb":...}`; single-file
 *     document: `{"file":"data:...",...}`; multi-page document:
 *     `{"pages":[{"file":"data:...",...}],...}`) — NOT raw bytes.
 *   - **non-private source whose type stores pages or declares entries** → `application/json`
 *     `{"encrypted":false,"value":"<envelope>"}`. The same envelope string, in the clear. There is
 *     nothing to decrypt.
 *   - **every other non-private source** → the file's own `Content-Type` and the body IS the file.
 *     A handle built this way needs no service key at all.
 *
 * Photos resolve to the `full` representation. There is no variant selection.
 *
 * The fetch + decrypt are supplied by the client as plain callables (config-only
 * key handling — no key is ever passed to this handle):
 *   - `valueUrl` + `fetch` — `fetch(valueUrl)` returns a {@link BinaryFetchResult} saying which
 *     shape arrived (the client classifies it on the response's `Content-Type`; the body is never
 *     sniffed).
 *   - `decrypt` — `decrypt(wrapper)` returns the decrypted envelope string (a
 *     closure over the loaded service private key). Only ever called for the encrypted shape.
 *
 * For the shared crypto test vector the decrypted envelope is already in hand, so
 * a handle can also be built directly from `envelopeJson` (no fetch).
 *
 * `bytes()`, `pages()` and `metadata()` share ONE lazy fetch: whichever is awaited first performs
 * it, and every later call answers from the parsed envelope.
 */
export class BinaryHandle {
  private envelopeJson: string | null;
  /** Plaintext file bytes, once a plaintext-shaped response has been fetched. */
  private plainBytes: Buffer | null = null;
  private _contentType: string | null = null;
  private _contentSha256: string | null = null;
  private readonly _valueUrl: string | null;
  private readonly fetch: BinaryFetch | null;
  private readonly decryptWrapper: DecryptWrapper | null;

  constructor(opts: {
    envelopeJson?: string | null;
    valueUrl?: string | null;
    fetch?: BinaryFetch | null;
    decrypt?: DecryptWrapper | null;
  } = {}) {
    this.envelopeJson = opts.envelopeJson ?? null;
    this._valueUrl = opts.valueUrl ?? null;
    this.fetch = opts.fetch ?? null;
    this.decryptWrapper = opts.decrypt ?? null;
  }

  /** The slot-keyed file URL this handle fetches from (opaque to callers). */
  get valueUrl(): string | null {
    return this._valueUrl;
  }

  /**
   * The platform's `X-Allus-Content-Sha256` — the digest of the SERVED ARTIFACT.
   *
   * Which artifact that is follows the response arm: the raw bytes when the answer arrived as
   * bytes, and the served `value` string on either JSON arm — the ciphertext wrapper for a private
   * source, the plaintext envelope for a non-private one. It is NOT "the sha256 of what
   * {@link bytes} returns": on an envelope carrying pages {@link bytes} rejects, and on an envelope
   * carrying one file it resolves to the decoded payload rather than the envelope string.
   *
   * A consumer can record it and later show that its archived copy has not drifted. `null` until
   * something has been fetched, and on a handle built from an envelope that was never fetched
   * through this class.
   *
   * It is the platform's word, not a signature: it proves agreement with the platform's record, not
   * anything to a third party who doubts that record.
   */
  get contentSha256(): string | null {
    return this._contentSha256;
  }

  /** The response `Content-Type` the bytes arrived with, once fetched. */
  get contentType(): string | null {
    return this._contentType;
  }

  /**
   * Fetch once and record which shape arrived. Idempotent: the result is cached on the handle so
   * repeated `.bytes()`/`.save()` calls do not re-fetch, and so a plaintext answer's digest survives
   * for {@link contentSha256}.
   */
  private async fetchOnce(): Promise<void> {
    if (this.plainBytes !== null || this.envelopeJson !== null) {
      return;
    }
    if (this.fetch === null || this._valueUrl === null) {
      throw new DecryptError(
        'BinaryHandle has no envelope and no fetch wiring ' +
          '(build it with envelopeJson, or valueUrl + fetch + decrypt)',
      );
    }
    const result = await this.fetch(this._valueUrl);
    this._contentType = result.contentType ?? null;
    this._contentSha256 = result.contentSha256 ?? null;

    if (!result.encrypted) {
      // A plaintext answer needs no service key. Requiring `decrypt` here would make a handle
      // built without one fail on exactly the answers that do not need it. The envelope arm is
      // plaintext too — the same envelope string the wrapper arm decrypts to — so both JSON arms
      // converge here.
      if (result.envelope != null) {
        this.envelopeJson = result.envelope;
        return;
      }
      this.plainBytes = result.bytes ?? Buffer.alloc(0);
      return;
    }
    if (this.decryptWrapper === null) {
      throw new DecryptError('binary answer is encrypted but this handle has no decrypt wiring');
    }
    this.envelopeJson = this.decryptWrapper(result.wrapper ?? '');
  }

  private async resolveEnvelope(): Promise<string> {
    if (this.envelopeJson !== null) {
      return this.envelopeJson;
    }
    await this.fetchOnce();
    if (this.envelopeJson === null) {
      throw new DecryptError('binary answer arrived as plaintext bytes; use bytes()/save()');
    }
    return this.envelopeJson;
  }

  /** The ONE envelope parser both JSON arms go through. */
  private static parseEnvelope(envelopeJson: string): Record<string, unknown> {
    let envelope: unknown;
    try {
      envelope = JSON.parse(envelopeJson);
    } catch {
      throw new DecryptError('binary envelope is not valid JSON');
    }
    if (envelope === null || typeof envelope !== 'object' || Array.isArray(envelope)) {
      throw new DecryptError('binary envelope must be a JSON object');
    }
    return envelope as Record<string, unknown>;
  }

  /** `data:<mime>;base64,<payload>` -> the decoded payload. */
  private static decodeDataUri(dataUri: string): Buffer {
    const marker = 'base64,';
    const idx = dataUri.indexOf(marker);
    if (idx === -1) {
      throw new DecryptError('binary data URI is not base64-encoded');
    }
    const payload = dataUri.slice(idx + marker.length);
    const buf = Buffer.from(payload, 'base64');
    if (buf.length === 0 && payload.length !== 0) {
      throw new DecryptError('binary data-URI payload is not valid base64');
    }
    return buf;
  }

  /**
   * Turn a decrypted binary envelope STRING into the primary file bytes.
   *
   * Photo envelope -> the `full` data-URI payload; single-file document envelope -> the `file`
   * data-URI payload. A MULTI-PAGE envelope has no single primary file, so it throws rather than
   * handing back the first page as though it were the whole document. Throws {@link DecryptError}
   * on a malformed envelope.
   */
  static parseEnvelopeBytes(envelopeJson: string): Buffer {
    const rec = BinaryHandle.parseEnvelope(envelopeJson);

    let dataUri: string | null = null;
    for (const key of DATA_URI_KEYS) {
      if (typeof rec[key] === 'string') {
        dataUri = rec[key] as string;
        break;
      }
    }
    if (dataUri === null) {
      if (Array.isArray(rec.pages) && rec.pages.length > 0) {
        throw new DecryptError('multi-page envelope: use pages');
      }
      throw new DecryptError("binary envelope has no 'full'/'file' data-URI payload");
    }

    return BinaryHandle.decodeDataUri(dataUri);
  }

  /**
   * The envelope's pages, in envelope order — an empty list for a single-file envelope.
   *
   * Lazy exactly as {@link bytes} is: the first call of `bytes`, `pages` or `metadata` performs the
   * one fetch and optional decrypt, and every later call answers from the parsed envelope. A handle
   * built from an envelope string needs no fetch. A plaintext-BYTES answer carries no envelope, so
   * it has no pages. Rejects with {@link DecryptError} on a failed fetch or decrypt, or a malformed
   * envelope.
   */
  async pages(): Promise<BinaryPage[]> {
    const rec = await this.envelopeOrNull();
    if (rec === null || !Array.isArray(rec.pages)) {
      return [];
    }
    return rec.pages.map((page): BinaryPage => {
      if (page === null || typeof page !== 'object' || Array.isArray(page)) {
        throw new DecryptError('binary envelope page has no data-URI payload');
      }
      const entry = page as Record<string, unknown>;
      if (typeof entry.file !== 'string') {
        throw new DecryptError('binary envelope page has no data-URI payload');
      }
      return {
        label: typeof entry.label === 'string' ? entry.label : null,
        name: typeof entry.original_name === 'string' ? entry.original_name : null,
        mime: typeof entry.mime_type === 'string' ? entry.mime_type : null,
        bytes: BinaryHandle.decodeDataUri(entry.file),
      };
    });
  }

  /**
   * Every declared entry the envelope carries, as a plain map.
   *
   * Keys are every string-keyed envelope member other than the envelope's own (`pages`, `file`,
   * `full`, `thumb`, `original_name`, `mime_type`, `size`); values are the stored string, or `null`
   * for an entry the person left unset. `name` — the holder name an ID provider extracted — is a
   * member like any other and appears here.
   *
   * **The map carries no ordering guarantee.** A consumer that needs the type's declared order
   * reads the envelope string itself.
   *
   * Empty for a photo, for a plain document that declares no entries, and for a plaintext-BYTES
   * answer. Lazy exactly as {@link pages} is.
   */
  async metadata(): Promise<Record<string, string | null>> {
    const rec = await this.envelopeOrNull();
    if (rec === null) {
      return {};
    }
    const out: Record<string, string | null> = {};
    for (const [key, value] of Object.entries(rec)) {
      if (ENVELOPE_MEMBERS.has(key)) {
        continue;
      }
      out[key] = typeof value === 'string' ? value : null;
    }
    return out;
  }

  /**
   * The parsed envelope, fetching+decrypting on first use. `null` when the answer is plaintext
   * BYTES, which carries no envelope at all.
   */
  private async envelopeOrNull(): Promise<Record<string, unknown> | null> {
    if (this.envelopeJson === null) {
      await this.fetchOnce();
      if (this.envelopeJson === null) {
        return null;
      }
    }
    return BinaryHandle.parseEnvelope(this.envelopeJson);
  }

  /**
   * Fetch (if needed), decrypt, and return the decoded primary file bytes.
   *
   * A MULTI-PAGE envelope has no single primary file and rejects: use {@link pages}.
   */
  async bytes(): Promise<Buffer> {
    if (this.plainBytes !== null) {
      return this.plainBytes;
    }
    if (this.envelopeJson === null) {
      await this.fetchOnce();
      if (this.plainBytes !== null) {
        return this.plainBytes;
      }
    }
    return BinaryHandle.parseEnvelopeBytes(await this.resolveEnvelope());
  }

  /**
   * Write the decoded file bytes to `path`; returns the number of bytes written.
   *
   * Crash-safe (matching the buffer's atomic-write discipline): the
   * bytes are written to a temp file in the same directory, fsync'd, and atomically
   * renamed into place — so a crash mid-write never leaves a truncated output file
   * (the destination is either the old file or the complete new one).
   */
  async save(path: string): Promise<number> {
    const data = await this.bytes();
    const directory = dirname(resolve(path));
    const tmp = join(directory, `.tmp_${process.pid}_${Date.now()}_${Math.random().toString(36).slice(2)}.part`);
    try {
      writeFileSync(tmp, data);
      const fd = openSync(tmp, 'r');
      try {
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      renameSync(tmp, path); // atomic rename over any existing file
    } catch (exc) {
      try {
        unlinkSync(tmp);
      } catch {
        // ignore — the temp file may not have been created
      }
      throw exc;
    }
    return data.length;
  }
}


/**
 * SHA-256 of raw PDF bytes, lowercase hex — the plainSha256 a signable file document's
 * create call and every sign/accept act must agree on. Exposed so a caller can precompute
 * or verify it; createDocument calls this itself when a plainSha256 override is not given.
 */
export function computePlainSha256(bytes: Buffer | Uint8Array): string {
  return createHash('sha256').update(Buffer.from(bytes)).digest('hex');
}

/**
 * Verified fields: true iff sha256(salt ‖ plaintext) === expectedHash (hex).
 * Consumers recompute this from the plaintext they just decrypted and trust the
 * verified flag ONLY on a match — a substituted/drifted value renders unverified.
 */
export function hashMatches(salt: string, expectedHash: string, plaintext: string): boolean {
  if (!salt || !expectedHash) return false;
  const computed = createHash('sha256').update(salt + plaintext, 'utf8').digest('hex');
  if (computed.length !== expectedHash.length) return false;
  let diff = 0;
  for (let i = 0; i < computed.length; i++) diff |= computed.charCodeAt(i) ^ expectedHash.charCodeAt(i);
  return diff === 0;
}

// ── plugin sealing ────────────────────────────────────────────────────────────

/** A reply key pair for one plugin call: the private half stays in memory, the public half travels. */
export interface ReplyKeyPair {
  privateKey: KeyObject;
  /** The public half as base64 SPKI (DER), the `reply_key` of a plugin request. */
  publicKeySpki: string;
}

/**
 * Generate a fresh RSA-2048 reply key pair. A plugin seals its reply to the public half; only the
 * caller holding the private half can open it.
 */
export function generateReplyKeyPair(): ReplyKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return { privateKey, publicKeySpki: exportPublicKeySpki(publicKey) };
}

/** A public key as base64 SPKI (DER) — the form every platform key travels in. */
export function exportPublicKeySpki(publicKey: KeyObject): string {
  return (publicKey.export({ type: 'spki', format: 'der' }) as Buffer).toString('base64');
}

/**
 * For a PLUGIN'S OWN SERVER: open the body of a `POST {base_url}/call` → the request object.
 *
 * `body` is the call's JSON body `{"request": "<wrapper string>"}` (raw or parsed);
 * `privateKeyPem` is the plugin's own PKCS#8 PEM, encrypted (with `passphrase`) or not (`null`).
 * The request carries `field_type`, `op`, `block`, `query`, `picks`, `values`, `inputs` and the
 * caller's `reply_key` — seal the answer to it with {@link pluginSealReply}. This is a function
 * for the plugin's server, never a call on the allme API.
 *
 * @throws DecryptError when the body, the wrapper or the key is not usable, or the plaintext is
 *   not a JSON object. A plugin answers a request sealed to a key it no longer holds with
 *   `409 {"error":"key_unknown"}`.
 */
export function pluginOpenRequest(
  body: string | Buffer | Record<string, unknown>,
  privateKeyPem: string | Buffer,
  passphrase: string | null,
): Record<string, unknown> {
  let parsed: unknown = body;
  if (typeof body === 'string' || Buffer.isBuffer(body)) {
    try {
      parsed = JSON.parse(body.toString());
    } catch {
      throw new DecryptError('plugin call body is not valid JSON');
    }
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new DecryptError('plugin call body must be a JSON object');
  }
  const request = (parsed as Record<string, unknown>)['request'];
  if (typeof request !== 'string' && (request === null || typeof request !== 'object')) {
    throw new DecryptError("plugin call body has no 'request' wrapper");
  }
  const plaintext = decrypt(request as EncWrapper | string, loadPrivateKey(privateKeyPem, passphrase));
  let opened: unknown;
  try {
    opened = JSON.parse(plaintext);
  } catch {
    throw new DecryptError('plugin request plaintext is not valid JSON');
  }
  if (opened === null || typeof opened !== 'object' || Array.isArray(opened)) {
    throw new DecryptError('plugin request plaintext must be a JSON object');
  }
  return opened as Record<string, unknown>;
}

/**
 * For a PLUGIN'S OWN SERVER: seal a reply to the request's `reply_key` → the response body
 * `{"reply": "<wrapper string>"}`.
 *
 * `reply` is the reply plaintext: `{"options":[{id,label}],"more":bool}`,
 * `{"outputs":{key: value|null}}` or `{"picks_invalid":true}`.
 */
export function pluginSealReply(reply: Record<string, unknown>, replyKeySpki: string): { reply: string } {
  return { reply: JSON.stringify(encryptForPublicKey(JSON.stringify(reply), loadPublicKey(replyKeySpki))) };
}
