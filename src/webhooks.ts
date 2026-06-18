/**
 * Webhook receiver helpers.
 *
 * The lower-latency push alternative to polling the changes feed. The platform
 * delivers each change event to the company's configured webhook URL with:
 *
 *   - `X-Allus-Webhook-Id`  — which webhook this is (selects the HMAC secret).
 *   - `X-Allus-Signature`   — `HMAC-SHA256(rawBody, secret)` as lowercase hex.
 *   - the body — the same slug-keyed {@link Change} shape as the pull feed,
 *     JSON or XML. If the webhook has `encrypt_payload` on, the body is REPLACED
 *     by a `{"_enc":1,...}` envelope encrypted to the company **account** key (and
 *     the HMAC is then over that envelope — it is the final body that was sent).
 *
 * All secrets/keys come from {@link Config}. **These helpers take NO key or secret
 * arguments** — only the raw body, the headers, the config, and (for value typing)
 * the same decrypt/type closures the {@link Client} already holds.
 *
 * The account-key envelope is webhook-specific: the platform wraps it with
 * OpenSSL's DEFAULT OAEP padding (MGF1-**SHA1**), NOT the SHA-256 wrapper used for
 * person field values. So unwrapping the envelope uses an OAEP-SHA1 path here
 * (Node's default `oaepHash`, pinned explicitly to `'sha1'` for clarity), while the
 * inner field `value` (still a service-key wrapper) decrypts with the normal
 * SHA-256 {@link decrypt}. HMAC is always computed over the raw bytes, never the
 * parsed tree.
 */

import {
  createDecipheriv,
  createHmac,
  createPrivateKey,
  privateDecrypt,
  timingSafeEqual,
  constants as cryptoConstants,
  type KeyObject,
} from 'node:crypto';
import { readFileSync } from 'node:fs';

import { Config } from './config.js';
import { GCM_IV_LEN, GCM_TAG_LEN, type EncWrapper, type BinaryFetch, type DecryptWrapper } from './crypto.js';
import { WebhookError } from './errors.js';
import { Change, type TypeForSlug } from './models.js';
import { parseXml } from './xml.js';

const HDR_WEBHOOK_ID = 'x-allus-webhook-id';
const HDR_SIGNATURE = 'x-allus-signature';

const ENC_MARKER = '_enc';

/** Headers as a (possibly mixed-case) string map. */
export type Headers = Record<string, string | string[] | undefined>;

interface ParseDeps {
  typeForSlug: TypeForSlug;
  decryptValue: DecryptWrapper;
  binaryFetch?: BinaryFetch | null;
  /** A pre-loaded account private key the Client caches; loaded on demand otherwise. */
  accountKey?: KeyObject | null;
}

// ── header helpers ─────────────────────────────────────────────────────────────

/** Case-insensitive header lookup (frameworks normalize casing inconsistently). */
function header(headers: Headers, name: string): string | null {
  if (!headers) return null;
  const target = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === target) {
      if (Array.isArray(value)) return value.length > 0 ? String(value[0]) : null;
      return value != null ? String(value) : null;
    }
  }
  return null;
}

function asBytes(rawBody: Buffer | Uint8Array | string): Buffer {
  if (Buffer.isBuffer(rawBody)) return rawBody;
  if (rawBody instanceof Uint8Array) return Buffer.from(rawBody);
  if (typeof rawBody === 'string') return Buffer.from(rawBody, 'utf8');
  throw new WebhookError('webhook rawBody must be a Buffer, Uint8Array, or string');
}

// ── verify ─────────────────────────────────────────────────────────────────────

/**
 * Verify the `X-Allus-Signature` HMAC over the raw body.
 *
 * Reads `X-Allus-Webhook-Id`, looks up that webhook's HMAC secret in config
 * (falling back to the single-webhook shortcut), recomputes
 * `HMAC-SHA256(rawBody, secret)` as hex, and constant-time-compares it to the
 * `X-Allus-Signature` header. Returns `false` on a missing signature,
 * unknown/unconfigured webhook id, or mismatch — never throws for a bad signature
 * (that is {@link handleWebhook}'s job). The HMAC is over the exact raw bytes.
 */
export function verifyWebhook(rawBody: Buffer | Uint8Array | string, headers: Headers, config: Config): boolean {
  const body = asBytes(rawBody);
  const signature = header(headers, HDR_SIGNATURE);
  if (!signature) return false;

  const webhookId = header(headers, HDR_WEBHOOK_ID);
  const secret = config.webhookSecret(webhookId);
  if (!secret) return false;

  const expected = createHmac('sha256', secret).update(body).digest('hex');
  return constantTimeHexEqual(expected, signature.trim().toLowerCase());
}

/** Constant-time compare two hex strings (length-safe). */
function constantTimeHexEqual(a: string, b: string): boolean {
  // Compare fixed-length byte buffers; if lengths differ, compare against `a`
  // itself so we never short-circuit on a length mismatch (timing-safe).
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) {
    // Still do a constant-time compare against a same-length buffer to avoid a
    // length-based timing oracle, then return false.
    timingSafeEqual(ab, ab);
    return false;
  }
  return timingSafeEqual(ab, bb);
}

// ── parse ──────────────────────────────────────────────────────────────────────

/**
 * Parse a webhook body → a typed {@link Change}.
 *
 * Does NOT verify the signature (use {@link handleWebhook} for verify+parse).
 * Handles JSON and XML bodies, and an `encrypt_payload` account-key envelope: if
 * the (JSON) body is a `{"_enc":1,...}` wrapper, it is first unwrapped with the
 * account private key (OAEP-SHA1) into the inner serialized payload, which is then
 * parsed. The inner field `value` (a service-key wrapper) is decrypted by the same
 * model factory the feed uses, so a webhook `Change` is byte-identical to a feed
 * `Change`.
 *
 * `deps.accountKey` is an optional pre-loaded account private key (the
 * {@link Client} loads it ONCE and reuses it, so an `encrypt_payload` webhook
 * doesn't re-read the PEM + re-run PBKDF2 ~100k iters per request). When undefined,
 * the key is loaded from config on demand — config-only key handling either way.
 */
export function parseWebhook(
  rawBody: Buffer | Uint8Array | string,
  headers: Headers,
  config: Config,
  deps: ParseDeps,
): Change {
  // `headers` is part of the webhook contract (verify reads them; parse keeps the
  // symmetric signature) but the body/envelope decode is header-independent — the
  // encrypt_payload envelope is self-describing (`{"_enc":1,…}`).
  void headers;
  const body = asBytes(rawBody);
  const payload = decodePayload(body, config, deps.accountKey);

  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new WebhookError('webhook payload is not a JSON/XML object');
  }

  return Change.fromApi(payload as Record<string, unknown>, {
    typeForSlug: deps.typeForSlug,
    decryptValue: deps.decryptValue,
    binaryFetch: deps.binaryFetch,
  });
}

/**
 * Verify + parse a webhook in one call.
 *
 * Throws {@link WebhookError} on a bad/unknown signature; otherwise returns the
 * typed {@link Change}. The typical one-liner inside a webhook route. `deps.accountKey`
 * (optional) is a pre-loaded account private key reused for the `encrypt_payload`
 * envelope (see {@link parseWebhook}).
 */
export function handleWebhook(
  rawBody: Buffer | Uint8Array | string,
  headers: Headers,
  config: Config,
  deps: ParseDeps,
): Change {
  if (!verifyWebhook(rawBody, headers, config)) {
    throw new WebhookError('webhook signature verification failed');
  }
  return parseWebhook(rawBody, headers, config, deps);
}

// ── payload decoding (JSON / XML / encrypt_payload envelope) ────────────────────

function decodePayload(body: Buffer, config: Config, accountKey?: KeyObject | null): unknown {
  const text = body.toString('utf8').trim();

  // An encrypt_payload envelope is always JSON ({"_enc":1,...}). Detect + unwrap it
  // before anything else (the inner payload is then JSON or XML per format).
  if (text.startsWith('{')) {
    let obj: unknown;
    try {
      obj = JSON.parse(text);
    } catch (exc) {
      throw new WebhookError(`webhook body is not valid JSON: ${(exc as Error).message}`);
    }
    if (
      obj !== null &&
      typeof obj === 'object' &&
      !Array.isArray(obj) &&
      (obj as Record<string, unknown>)[ENC_MARKER] === 1 &&
      ['k', 'iv', 'd'].every((f) => f in (obj as Record<string, unknown>))
    ) {
      const inner = unwrapAccountEnvelope(obj as EncWrapper, config, accountKey);
      return decodeInner(inner);
    }
    return obj;
  }

  // Otherwise an XML body (the platform's <response> serialization).
  if (text.startsWith('<')) {
    try {
      return parseXml(text);
    } catch (exc) {
      throw new WebhookError(`webhook body is not valid XML: ${(exc as Error).message}`);
    }
  }

  throw new WebhookError('webhook body is neither JSON nor XML');
}

function decodeInner(innerText: string): unknown {
  const stripped = innerText.trim();
  if (stripped.startsWith('<')) {
    try {
      return parseXml(stripped);
    } catch (exc) {
      throw new WebhookError(`decrypted webhook payload is not valid XML: ${(exc as Error).message}`);
    }
  }
  try {
    return JSON.parse(stripped);
  } catch (exc) {
    throw new WebhookError(`decrypted webhook payload is not valid JSON: ${(exc as Error).message}`);
  }
}

// ── account-key envelope unwrap (OAEP-SHA1 — webhook-specific) ───────────────────

/**
 * Load the account private key from config ONCE (or `null` if not configured).
 *
 * Reused by the {@link Client} so an `encrypt_payload` webhook never re-reads the
 * PEM + re-runs PBKDF2 (~100k iters) per request — the account key is loaded a
 * single time at client construction, exactly like the service key. Returns `null`
 * when no `accountPrivateKey` is configured (the SDK only needs it for
 * `encrypt_payload` webhooks). Throws {@link WebhookError} on a read / passphrase /
 * PEM problem.
 */
export function loadAccountKey(config: Config): KeyObject | null {
  if (!config.accountPrivateKey) return null;
  let pem: Buffer;
  try {
    pem = readFileSync(config.accountPrivateKey);
  } catch (exc) {
    throw new WebhookError(
      `could not read accountPrivateKey PEM: ${config.accountPrivateKey}: ${(exc as Error).message}`,
    );
  }
  const passphrase = config.accountPassphrase ?? '';
  try {
    return createPrivateKey({ key: pem, passphrase });
  } catch (exc) {
    throw new WebhookError(`could not load account private key: ${(exc as Error).message}`);
  }
}

function unwrapAccountEnvelope(envelope: EncWrapper, config: Config, accountKey?: KeyObject | null): string {
  const key = accountKey ?? loadAccountKey(config);
  if (key === null || key === undefined) {
    throw new WebhookError('received an encrypt_payload webhook but no accountPrivateKey is configured');
  }
  return decryptOaepSha1(envelope, key);
}

function b64(value: unknown, name: string): Buffer {
  if (typeof value !== 'string') {
    throw new WebhookError(`envelope field '${name}' must be a base64 string`);
  }
  const buf = Buffer.from(value, 'base64');
  const normalized = value.replace(/\s+/g, '');
  if (buf.toString('base64').replace(/=+$/, '') !== normalized.replace(/=+$/, '')) {
    throw new WebhookError(`envelope field '${name}' is not valid base64`);
  }
  return buf;
}

/**
 * RSA-OAEP(**SHA-1**, MGF1-SHA1) unwrap + AES-256-GCM decrypt → utf-8 string.
 *
 * Mirrors {@link decrypt} but pins SHA-1 for the OAEP/MGF1 hash to match the
 * account-key envelope (the only place the platform uses SHA-1 OAEP). Node defaults
 * `oaepHash` to SHA-1 already; we set it explicitly for clarity + to be robust to a
 * future default change.
 */
function decryptOaepSha1(wrapper: EncWrapper, privateKey: KeyObject): string {
  const encKey = b64(wrapper.k, 'k');
  const iv = b64(wrapper.iv, 'iv');
  const ciphertextWithTag = b64(wrapper.d, 'd');

  if (iv.length !== GCM_IV_LEN) {
    throw new WebhookError(`envelope iv must be ${GCM_IV_LEN} bytes, got ${iv.length}`);
  }
  if (ciphertextWithTag.length < GCM_TAG_LEN) {
    throw new WebhookError('envelope ciphertext too short to contain a GCM tag');
  }

  let aesKey: Buffer;
  try {
    aesKey = privateDecrypt(
      {
        key: privateKey,
        padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha1',
      },
      encKey,
    );
  } catch (exc) {
    throw new WebhookError(
      `account-key envelope RSA-OAEP unwrap failed (wrong account key?): ${(exc as Error).message}`,
    );
  }

  if (aesKey.length !== 32) {
    throw new WebhookError(`unwrapped envelope AES key must be 32 bytes, got ${aesKey.length}`);
  }

  const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - GCM_TAG_LEN);
  const ciphertext = ciphertextWithTag.subarray(0, ciphertextWithTag.length - GCM_TAG_LEN);

  let plaintext: Buffer;
  try {
    const decipher = createDecipheriv('aes-256-gcm', aesKey, iv);
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new WebhookError('account-key envelope AES-GCM tag mismatch');
  }

  const out = plaintext.toString('utf8');
  if (!Buffer.from(out, 'utf8').equals(plaintext)) {
    throw new WebhookError('decrypted account-key envelope is not valid UTF-8');
  }
  return out;
}
