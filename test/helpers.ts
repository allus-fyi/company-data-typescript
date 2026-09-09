/**
 * Shared test helpers: load the cross-language decryption vector, and encrypt
 * arbitrary plaintext into a platform wrapper using the vector key's PUBLIC half
 * (so structured/date test values can be built that decrypt via the SAME crypto
 * core). Mirrors the Python tests' `encrypt_for_key`.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FieldTypeRegistry } from '../src/index.js';
import {
  createPublicKey,
  publicEncrypt,
  randomBytes,
  createCipheriv,
  createPrivateKey,
  constants as cryptoConstants,
  type KeyObject,
} from 'node:crypto';

const here = dirname(fileURLToPath(import.meta.url));

export const VECTOR_PATH = join(here, '..', 'testdata', 'decryption-vector.json');

export interface Vector {
  encrypted_private_key_pem: string;
  passphrase: string;
  text: { wrapper: { _enc: number; k: string; iv: string; d: string }; plaintext: string };
  binary: {
    wrapper: { _enc: number; k: string; iv: string; d: string };
    decrypted_json_sha256: string;
    inner_full_sha256: string;
  };
}

export function loadVector(): Vector {
  return JSON.parse(readFileSync(VECTOR_PATH, 'utf8')) as Vector;
}

export function loadVectorPrivateKey(vector: Vector): KeyObject {
  return createPrivateKey({ key: vector.encrypted_private_key_pem, passphrase: vector.passphrase });
}

/** Encrypt a plaintext into a platform wrapper with the vector key's PUBLIC half. */
export function encryptForKey(vector: Vector, plaintext: string): { _enc: number; k: string; iv: string; d: string } {
  const priv = loadVectorPrivateKey(vector);
  const pub = createPublicKey(priv);
  const aesKey = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', aesKey, iv);
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
  const tag = cipher.getAuthTag();
  const k = publicEncrypt(
    { key: pub, padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    aesKey,
  );
  return {
    _enc: 1,
    k: k.toString('base64'),
    iv: iv.toString('base64'),
    d: Buffer.concat([ct, tag]).toString('base64'),
  };
}

/** The field-type vector's own registry — the rows every model test types its values against. */
let cachedFieldTypes: FieldTypeRegistry | null = null;
let cachedFieldTypeRows: unknown[] | null = null;

export function testFieldTypes(): FieldTypeRegistry {
  if (cachedFieldTypes === null) {
    cachedFieldTypes = new FieldTypeRegistry(testFieldTypeRows() as never[]);
  }
  return cachedFieldTypes;
}

/** The same rows as a served GET /api/contact-field-types body. */
export function testFieldTypeRows(): unknown[] {
  if (cachedFieldTypeRows === null) {
    const path = join(here, '..', 'testdata', 'contract-field-validation-vector.json');
    cachedFieldTypeRows = (JSON.parse(readFileSync(path, 'utf8')) as { registry: unknown[] }).registry;
  }
  return cachedFieldTypeRows;
}
