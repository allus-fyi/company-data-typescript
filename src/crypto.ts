/**
 * Decryption core — byte-identical across all six SDKs.
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
 * Load an OpenSSL-encrypted PKCS#8 PEM into an in-memory private key handle.
 *
 * The PEM is PBES2 (PBKDF2-HMAC-SHA256 + AES-256-CBC, ~100k iters). Node's
 * `createPrivateKey` decrypts it with the passphrase (OpenSSL handles the SHA-256
 * PRF). The key is never written back to disk in plaintext.
 *
 * Config-only key handling: this is the single place a passphrase is used, driven
 * by `Config.keyPassphrase` — never passed in by application code.
 */
export function loadPrivateKey(encryptedPem: Buffer | string, passphrase: string): KeyObject {
  try {
    return createPrivateKey({ key: encryptedPem, passphrase });
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

/** Fetch a slot file endpoint → the inner `{"_enc":1,...}` wrapper. */
export type BinaryFetch = (valueUrl: string) => Promise<EncWrapper | string> | EncWrapper | string;
/** Decrypt a ciphertext wrapper → the envelope string (closes over the service key). */
export type DecryptWrapper = (wrapper: EncWrapper | string) => string;

const DATA_URI_KEYS = ['full', 'file'] as const;

/**
 * Lazy handle for a binary (photo/document) value.
 *
 * A binary answer is stored server-side as a file, exposed in the hardened API as
 * a slot-keyed `value_url` (never the source field). On `.bytes()` / `.save()` the
 * handle GETs that URL, receives the `{"_enc":1,...}` wrapper, runs the same
 * decrypt as text → a JSON envelope STRING (photo: `{"full":"data:...","thumb":...}`;
 * document: `{"file":"data:...",...}`) — NOT raw bytes — then parses the envelope
 * and base64-decodes the primary data-URI payload (`full` for photos, `file` for
 * documents) into the file bytes.
 *
 * The fetch + decrypt are supplied by the client as plain callables (config-only
 * key handling — no key is ever passed to this handle):
 *   - `valueUrl` + `fetch` — `fetch(valueUrl)` returns the encrypted wrapper (the
 *     client passes a callback that GETs the slot file endpoint and unwraps the
 *     `{"encrypted": true, "value": <wrapper>}` envelope to the inner wrapper).
 *   - `decrypt` — `decrypt(wrapper)` returns the decrypted envelope string (a
 *     closure over the loaded service private key).
 *
 * For the shared crypto test vector the decrypted envelope is already in hand, so
 * a handle can also be built directly from `envelopeJson` (no fetch).
 */
export class BinaryHandle {
  private envelopeJson: string | null;
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

  private async resolveEnvelope(): Promise<string> {
    if (this.envelopeJson !== null) {
      return this.envelopeJson;
    }
    if (this.fetch === null || this.decryptWrapper === null || this._valueUrl === null) {
      throw new DecryptError(
        'BinaryHandle has no envelope and no fetch/decrypt wiring ' +
          '(build it with envelopeJson, or valueUrl + fetch + decrypt)',
      );
    }
    const wrapper = await this.fetch(this._valueUrl);
    const envelopeJson = this.decryptWrapper(wrapper);
    // Cache so repeated .bytes()/.save() don't re-fetch.
    this.envelopeJson = envelopeJson;
    return envelopeJson;
  }

  /**
   * Turn a decrypted binary envelope STRING into the primary file bytes.
   *
   * Photo envelope -> the `full` data-URI payload; document envelope -> the `file`
   * data-URI payload. Throws {@link DecryptError} on a malformed envelope.
   */
  static parseEnvelopeBytes(envelopeJson: string): Buffer {
    let envelope: unknown;
    try {
      envelope = JSON.parse(envelopeJson);
    } catch {
      throw new DecryptError('binary envelope is not valid JSON');
    }
    if (envelope === null || typeof envelope !== 'object' || Array.isArray(envelope)) {
      throw new DecryptError('binary envelope must be a JSON object');
    }
    const rec = envelope as Record<string, unknown>;

    let dataUri: string | null = null;
    for (const key of DATA_URI_KEYS) {
      if (typeof rec[key] === 'string') {
        dataUri = rec[key] as string;
        break;
      }
    }
    if (dataUri === null) {
      throw new DecryptError("binary envelope has no 'full'/'file' data-URI payload");
    }

    // data:<mime>;base64,<payload>
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

  /** Fetch (if needed), decrypt, and return the decoded primary file bytes. */
  async bytes(): Promise<Buffer> {
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
